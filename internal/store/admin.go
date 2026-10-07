package store

import (
	"context"
	"database/sql"
	"errors"
	"familyvpn.local/platform/internal/adminauth"
	"familyvpn.local/platform/internal/auth"
	"time"
)

type AdminStore struct{ *Database }

var _ adminauth.Repository = (*AdminStore)(nil)

func OpenAdmin(ctx context.Context, path string, initialize bool) (*AdminStore, error) {
	d, e := open(ctx, path, Admin, false, initialize)
	if e != nil {
		return nil, e
	}
	return &AdminStore{d}, nil
}

// OpenAdminReadOnly supports trusted stand diagnostics without migrations,
// session/rate-limit writes or changing journal settings.
func OpenAdminReadOnly(ctx context.Context, path string) (*AdminStore, error) {
	d, e := open(ctx, path, Admin, true, false)
	if e != nil {
		return nil, e
	}
	return &AdminStore{d}, nil
}
func (a *AdminStore) ReserveAttempts(ctx context.Context, ip, account []byte, now time.Time) error {
	return (&PortalStore{a.Database}).ReserveAttempts(ctx, ip, account, now)
}
func (a *AdminStore) CheckAdminKey(ctx context.Context, v *adminauth.Vault) error {
	rows, e := a.db.QueryContext(ctx, "SELECT id,key_id,encrypted_secret FROM admin_accounts WHERE state!='disabled'")
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var id, k string
		var b []byte
		if e = rows.Scan(&id, &k, &b); e != nil {
			return e
		}
		if _, e = v.Open(id, k, b); e != nil {
			return e
		}
	}
	return rows.Err()
}

// HasActiveAdmin checks enrollment state only, never creates a session or
// substitutes for password/TOTP authentication.
func (a *AdminStore) HasActiveAdmin(ctx context.Context) (bool, error) {
	var exists bool
	e := a.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM admin_accounts WHERE state='active')").Scan(&exists)
	return exists, e
}

const adminFields = "id,login,display_name,password_hash,key_id,encrypted_secret,last_step"

func scanAdmin(row interface{ Scan(...any) error }) (adminauth.Credential, error) {
	var c adminauth.Credential
	e := row.Scan(&c.ID, &c.Login, &c.DisplayName, &c.PasswordHash, &c.KeyID, &c.Ciphertext, &c.LastStep)
	if errors.Is(e, sql.ErrNoRows) {
		e = auth.ErrDenied
	}
	return c, e
}
func (a *AdminStore) AdminID(ctx context.Context, login string) (string, error) {
	var id string
	e := a.db.QueryRowContext(ctx, "SELECT id FROM admin_accounts WHERE login=?", login).Scan(&id)
	if errors.Is(e, sql.ErrNoRows) {
		e = auth.ErrDenied
	}
	return id, e
}
func (a *AdminStore) AdminCredential(ctx context.Context, login string) (adminauth.Credential, error) {
	return scanAdmin(a.db.QueryRowContext(ctx, "SELECT "+adminFields+" FROM admin_accounts WHERE login=? AND state='active'", login))
}
func (a *AdminStore) AdminEnroll(ctx context.Context, c adminauth.Credential, reset bool, now, expires time.Time) error {
	tx, e := a.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	// Lock before reading; replacing an account invalidates all pending proofs atomically.
	if _, e = tx.ExecContext(ctx, "UPDATE admin_accounts SET revision=revision WHERE login=?", c.Login); e != nil {
		return e
	}
	var old string
	e = tx.QueryRowContext(ctx, "SELECT id FROM admin_accounts WHERE login=?", c.Login).Scan(&old)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if reset && old == "" {
		return auth.ErrDenied
	}
	if !reset && old != "" {
		return auth.ErrConflict
	}
	action := "admin.enroll"
	if reset {
		action = "admin.reset"
		if _, e = tx.ExecContext(ctx, "DELETE FROM admin_challenges WHERE user_id=?", old); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE sessions SET revoked_at=COALESCE(revoked_at,?) WHERE user_id=?", stamp(now), old); e != nil {
			return e
		}
		if old != c.ID {
			return auth.ErrDenied
		}
		if _, e = tx.ExecContext(ctx, "UPDATE admin_accounts SET password_hash=?,encrypted_secret=?,key_id=?,last_step=-1,revision=revision+1,state='pending',enrollment_expires=?,display_name=? WHERE id=?", c.PasswordHash, c.Ciphertext, c.KeyID, stamp(expires), c.DisplayName, old); e != nil {
			return e
		}
	} else {
		if _, e = tx.ExecContext(ctx, `INSERT INTO admin_accounts(id,login,display_name,password_hash,encrypted_secret,key_id,last_step,state,enrollment_expires) VALUES(?,?,?,?,?,?,-1,'pending',?)`, c.ID, c.Login, c.DisplayName, c.PasswordHash, c.Ciphertext, c.KeyID, stamp(expires)); e != nil {
			return e
		}
	}
	if e = audit(ctx, tx, "local-cli", action, c.ID, now); e != nil {
		return e
	}
	return tx.Commit()
}
func (a *AdminStore) AdminConfirm(ctx context.Context, login, code string, now time.Time, verify func(adminauth.Credential, string) (int64, error)) error {
	tx, e := a.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "UPDATE admin_accounts SET revision=revision WHERE login=?", login); e != nil {
		return e
	}
	c, e := scanAdmin(tx.QueryRowContext(ctx, "SELECT "+adminFields+" FROM admin_accounts WHERE login=? AND state='pending' AND julianday(enrollment_expires)>julianday(?)", login, stamp(now)))
	if e != nil {
		return e
	}
	step, e := verify(c, code)
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE admin_accounts SET state='active',last_step=?,revision=revision+1 WHERE id=?", step, c.ID); e != nil {
		return e
	}
	if e = audit(ctx, tx, "local-cli", "admin.enrollment.confirm", c.ID, now); e != nil {
		return e
	}
	return tx.Commit()
}
func (a *AdminStore) AdminDisable(ctx context.Context, login string, now time.Time) error {
	tx, e := a.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	res, e := tx.ExecContext(ctx, "UPDATE admin_accounts SET state='disabled',revision=revision+1 WHERE login=?", login)
	if e != nil {
		return e
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return auth.ErrDenied
	}
	var id string
	if e = tx.QueryRowContext(ctx, "SELECT id FROM admin_accounts WHERE login=?", login).Scan(&id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM admin_challenges WHERE user_id=?", id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE sessions SET revoked_at=COALESCE(revoked_at,?) WHERE user_id=?", stamp(now), id); e != nil {
		return e
	}
	if e = audit(ctx, tx, "local-cli", "admin.disable", id, now); e != nil {
		return e
	}
	return tx.Commit()
}
func (a *AdminStore) AdminChallenge(ctx context.Context, c adminauth.Credential, hash, binding []byte, now, expires time.Time) error {
	tx, e := a.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "DELETE FROM admin_challenges WHERE julianday(expires_at)<=julianday(?) OR user_id=?", stamp(now), c.ID); e != nil {
		return e
	}
	res, e := tx.ExecContext(ctx, `INSERT INTO admin_challenges(token_hash,binding_hash,user_id,revision,expires_at) SELECT ?,?,id,revision,? FROM admin_accounts WHERE id=? AND password_hash=? AND state='active'`, hash, binding, stamp(expires), c.ID, c.PasswordHash)
	if e != nil {
		return e
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return auth.ErrDenied
	}
	return tx.Commit()
}
func (a *AdminStore) AdminFinish(ctx context.Context, hash, binding []byte, code string, sessionHash []byte, now, expires time.Time, verify func(adminauth.Credential, string) (int64, error)) (auth.Session, error) {
	empty := auth.Session{}
	tx, e := a.db.BeginTx(ctx, nil)
	if e != nil {
		return empty, e
	}
	defer tx.Rollback()
	res, e := tx.ExecContext(ctx, `UPDATE admin_challenges SET attempts=attempts+1 WHERE token_hash=? AND binding_hash=? AND attempts<5 AND julianday(expires_at)>julianday(?) AND EXISTS(SELECT 1 FROM admin_accounts WHERE id=admin_challenges.user_id AND revision=admin_challenges.revision AND state='active')`, hash, binding, stamp(now))
	if e != nil {
		return empty, e
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return empty, auth.ErrDenied
	}
	c, e := scanAdmin(tx.QueryRowContext(ctx, "SELECT "+adminFields+" FROM admin_accounts WHERE id=(SELECT user_id FROM admin_challenges WHERE token_hash=?)", hash))
	if e != nil {
		return empty, e
	}
	step, e := verify(c, code)
	if e != nil {
		if ce := tx.Commit(); ce != nil {
			return empty, ce
		}
		return empty, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE admin_accounts SET last_step=? WHERE id=? AND last_step<?", step, c.ID, step); e != nil {
		return empty, e
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM admin_challenges WHERE token_hash=?", hash); e != nil {
		return empty, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO sessions VALUES(?,?,?,?,?,?,NULL)", sessionHash, c.ID, stamp(now), stamp(now), stamp(expires), stamp(now)); e != nil {
		return empty, e
	}
	if e = audit(ctx, tx, c.ID, "admin.session.login", c.ID, now); e != nil {
		return empty, e
	}
	s := auth.Session{User: auth.User{ID: c.ID, Login: c.Login, DisplayName: c.DisplayName, Role: "admin"}, ExpiresAt: expires, AuthTime: now}
	return s, tx.Commit()
}
func (a *AdminStore) AdminSession(ctx context.Context, hash []byte, now time.Time, idle time.Duration) (auth.Session, error) {
	var s auth.Session
	var exp, at string
	e := a.db.QueryRowContext(ctx, `SELECT a.id,a.login,a.display_name,s.expires_at,s.auth_time FROM sessions s JOIN admin_accounts a ON a.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND julianday(s.expires_at)>julianday(?) AND julianday(s.last_seen_at)>julianday(?) AND a.state='active'`, hash, stamp(now), stamp(now.Add(-idle))).Scan(&s.ID, &s.Login, &s.DisplayName, &exp, &at)
	if errors.Is(e, sql.ErrNoRows) {
		e = auth.ErrDenied
	}
	if e != nil {
		return s, e
	}
	s.Role = "admin"
	s.ExpiresAt, e = time.Parse(time.RFC3339Nano, exp)
	if e != nil {
		return s, e
	}
	s.AuthTime, e = time.Parse(time.RFC3339Nano, at)
	return s, e
}
func (a *AdminStore) AdminTouch(ctx context.Context, hash []byte, now time.Time, idle time.Duration) error {
	res, e := a.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at=? WHERE token_hash=? AND revoked_at IS NULL AND julianday(expires_at)>julianday(?) AND julianday(last_seen_at)>julianday(?) AND EXISTS(SELECT 1 FROM admin_accounts WHERE id=sessions.user_id AND state='active')`, stamp(now), hash, stamp(now), stamp(now.Add(-idle)))
	if e != nil {
		return e
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return auth.ErrDenied
	}
	return nil
}
func (a *AdminStore) AdminLogout(ctx context.Context, hash []byte, now time.Time) error {
	return (&PortalStore{a.Database}).RevokeSession(ctx, hash, now)
}
