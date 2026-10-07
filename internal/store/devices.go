package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/repository"
	"time"
)

var _ repository.DeviceWriter = (*PortalStore)(nil)

func (p *PortalStore) DeviceQuota(ctx context.Context, owner string) (domain.DeviceQuota, error) {
	var q domain.DeviceQuota
	e := p.db.QueryRowContext(ctx, `SELECT device_limit,(SELECT count(*) FROM devices WHERE user_id=u.id AND state!='revoked') FROM users u WHERE id=? AND role='user' AND state='active'`, owner).Scan(&q.Limit, &q.Used)
	if errors.Is(e, sql.ErrNoRows) {
		e = auth.ErrDenied
	}
	q.Remaining = max(0, q.Limit-q.Used)
	return q, e
}
func deviceFromTx(ctx context.Context, tx *sql.Tx, owner, id string) (domain.Device, error) {
	var d domain.Device
	e := tx.QueryRowContext(ctx, "SELECT id,user_id,name,os,state,revision FROM devices WHERE id=? AND user_id=?", id, owner).Scan(&d.ID, &d.OwnerID, &d.Name, &d.OS, &d.State, &d.Revision)
	if errors.Is(e, sql.ErrNoRows) {
		e = ErrNotFound
	}
	if e != nil {
		return d, e
	}
	d.Profiles = []domain.Profile{}
	rows, e := tx.QueryContext(ctx, "SELECT p.id,p.protocol,p.state,p.format FROM profiles p JOIN devices d ON d.id=p.device_id WHERE d.id=? AND d.user_id=? AND p.generation=d.generation ORDER BY p.protocol", id, owner)
	if e != nil {
		return d, e
	}
	defer rows.Close()
	for rows.Next() {
		var v domain.Profile
		if e = rows.Scan(&v.ID, &v.Protocol, &v.State, &v.Format); e != nil {
			return d, e
		}
		d.Profiles = append(d.Profiles, v)
	}
	return d, rows.Err()
}

// Lock the owner before checking quotas or mutating devices; concurrent requests serialize across DB handles.
func lockDeviceOwner(ctx context.Context, tx *sql.Tx, owner string) error {
	res, e := tx.ExecContext(ctx, "UPDATE users SET state=state WHERE id=? AND state='active' AND role='user'", owner)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return auth.ErrDenied
	}
	return nil
}
func (p *PortalStore) RequestDevice(ctx context.Context, owner string, in domain.DeviceRequest) (domain.Device, error) {
	empty := domain.Device{}
	in, hash, e := in.Validate()
	if e != nil {
		return empty, e
	}
	if e = p.AssertLocalAuth(ctx); e != nil {
		return empty, e
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return empty, e
	}
	defer tx.Rollback()
	if e = lockDeviceOwner(ctx, tx, owner); e != nil {
		return empty, e
	}
	var id string
	var previous []byte
	e = tx.QueryRowContext(ctx, "SELECT id,creation_hash FROM devices WHERE user_id=? AND creation_key=?", owner, in.RequestID).Scan(&id, &previous)
	if e == nil {
		if !bytes.Equal(hash, previous) {
			return empty, ErrConflict
		}
		d, e := deviceFromTx(ctx, tx, owner, id)
		if e != nil {
			return empty, e
		}
		return d, tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return empty, e
	}
	var limit, used, total int
	e = tx.QueryRowContext(ctx, `SELECT device_limit,(SELECT count(*) FROM devices WHERE user_id=u.id AND state!='revoked'),(SELECT count(*) FROM devices WHERE user_id=u.id) FROM users u WHERE id=?`, owner).Scan(&limit, &used, &total)
	if e != nil {
		return empty, e
	}
	// Bound cancelled history/idempotency storage until a retention policy is implemented.
	if used >= limit || total >= 200 {
		return empty, domain.ErrDeviceLimit
	}
	id = auth.RandomToken()
	now := time.Now()
	_, e = tx.ExecContext(ctx, `INSERT INTO devices(id,user_id,name,os,state,created_at,creation_key,creation_hash) VALUES(?,?,?,?,'pending',?,?,?)`, id, owner, in.Name, in.OS, stamp(now), in.RequestID, hash)
	if e != nil {
		return empty, e
	}
	for _, protocol := range []string{"awg", "reality"} {
		if _, e = tx.ExecContext(ctx, `INSERT INTO profiles(id,device_id,protocol,generation,state,format) VALUES(?,?,?,1,'pending','')`, auth.RandomToken(), id, protocol); e != nil {
			return empty, e
		}
	}
	if e = audit(ctx, tx, owner, "device.request", id, now); e != nil {
		return empty, e
	}
	d, e := deviceFromTx(ctx, tx, owner, id)
	if e != nil {
		return empty, e
	}
	return d, tx.Commit()
}
func (p *PortalStore) RenameDevice(ctx context.Context, owner, id, name string, revision int) (domain.Device, error) {
	var e error
	name, e = domain.DeviceName(name)
	if e != nil || revision < 1 {
		return domain.Device{}, domain.ErrDeviceInput
	}
	return p.mutateDevice(ctx, owner, id, revision, func(ctx context.Context, tx *sql.Tx, d domain.Device) error {
		if d.State == "revoked" || d.State == "revoking" {
			return domain.ErrDeviceState
		}
		_, e := tx.ExecContext(ctx, "UPDATE devices SET name=?,revision=revision+1 WHERE id=? AND user_id=?", name, id, owner)
		return e
	}, "device.rename")
}
func (p *PortalStore) CancelDeviceRequest(ctx context.Context, owner, id string, revision int) (domain.Device, error) {
	if revision < 1 {
		return domain.Device{}, domain.ErrDeviceInput
	}
	return p.mutateDevice(ctx, owner, id, revision, func(ctx context.Context, tx *sql.Tx, d domain.Device) error {
		if d.State != "pending" {
			return domain.ErrDeviceState
		}
		// Cancellation is deliberately unavailable after any installed/secret-bearing generation or subscription.
		var unsafe int
		e := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM profiles WHERE device_id=? AND (state!='pending' OR allocated_ip IS NOT NULL OR ciphertext IS NOT NULL OR nonce IS NOT NULL OR key_id IS NOT NULL OR installed_revision IS NOT NULL))+(SELECT count(*) FROM subscription_tokens WHERE device_id=?)`, id, id).Scan(&unsafe)
		if e != nil {
			return e
		}
		if unsafe != 0 {
			return domain.ErrDeviceState
		}
		var key sql.NullString
		if e = tx.QueryRowContext(ctx, "SELECT creation_key FROM devices WHERE id=?", id).Scan(&key); e != nil {
			return e
		}
		if !key.Valid {
			return domain.ErrDeviceState
		}
		if _, e = tx.ExecContext(ctx, "UPDATE profiles SET state='revoked' WHERE device_id=?", id); e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, "UPDATE devices SET state='revoked',revoked_at=?,revision=revision+1 WHERE id=? AND user_id=?", stamp(time.Now()), id, owner)
		return e
	}, "device.request.cancel")
}
func (p *PortalStore) mutateDevice(ctx context.Context, owner, id string, revision int, change func(context.Context, *sql.Tx, domain.Device) error, action string) (domain.Device, error) {
	empty := domain.Device{}
	if e := p.AssertLocalAuth(ctx); e != nil {
		return empty, e
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return empty, e
	}
	defer tx.Rollback()
	if e = lockDeviceOwner(ctx, tx, owner); e != nil {
		return empty, e
	}
	d, e := deviceFromTx(ctx, tx, owner, id)
	if e != nil {
		return empty, e
	}
	if d.Revision != revision {
		return empty, ErrConflict
	}
	if e = change(ctx, tx, d); e != nil {
		return empty, e
	}
	if e = audit(ctx, tx, owner, action, id, time.Now()); e != nil {
		return empty, e
	}
	d, e = deviceFromTx(ctx, tx, owner, id)
	if e != nil {
		return empty, e
	}
	return d, tx.Commit()
}
