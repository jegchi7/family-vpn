package store

import (
	"context"
	"encoding/json"
	"familyvpn.local/platform/internal/adapters/fake"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/repository"
	"fmt"
	"time"
)

type PortalStore struct{ *Database }

var _ repository.Reader = (*PortalStore)(nil)

func OpenPortal(ctx context.Context, path string, readOnly bool) (*PortalStore, error) {
	d, e := Open(ctx, path, Portal, readOnly)
	if e != nil {
		return nil, e
	}
	return &PortalStore{d}, nil
}
func (p *PortalStore) Backend() string { return "sqlite" }
func (p *PortalStore) DevicesForOwner(ctx context.Context, owner string) ([]domain.Device, error) {
	rows, e := p.db.QueryContext(ctx, `SELECT d.id,d.user_id,d.name,d.os,d.state,d.revision,p.id,p.protocol,p.state,p.format FROM devices d LEFT JOIN profiles p ON p.device_id=d.id AND p.generation=d.generation WHERE d.user_id=? ORDER BY d.id,p.protocol`, owner)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []domain.Device{}
	indices := map[string]int{}
	for rows.Next() {
		var d domain.Device
		var id, protocol, state, format *string
		if e = rows.Scan(&d.ID, &d.OwnerID, &d.Name, &d.OS, &d.State, &d.Revision, &id, &protocol, &state, &format); e != nil {
			return nil, e
		}
		i, ok := indices[d.ID]
		if !ok {
			d.Profiles = []domain.Profile{}
			out = append(out, d)
			i = len(out) - 1
			indices[d.ID] = i
		}
		if id != nil {
			out[i].Profiles = append(out[i].Profiles, domain.Profile{ID: *id, Protocol: *protocol, State: *state, Format: *format})
		}
	}
	return out, rows.Err()
}
func (p *PortalStore) ProfileForOwner(ctx context.Context, owner, id string) (domain.Profile, bool, error) {
	devices, e := p.DevicesForOwner(ctx, owner)
	if e != nil {
		return domain.Profile{}, false, e
	}
	for _, d := range devices {
		for _, profile := range d.Profiles {
			if profile.ID == id {
				return profile, true, nil
			}
		}
	}
	return domain.Profile{}, false, nil
}
func (p *PortalStore) DeviceCount(ctx context.Context) (int, error) {
	var count int
	e := p.db.QueryRowContext(ctx, "SELECT count(*) FROM devices").Scan(&count)
	return count, e
}
func (p *PortalStore) HealthSamples(ctx context.Context) ([]domain.Health, error) {
	rows, e := p.db.QueryContext(ctx, "SELECT component,status,reason,measured_at,expires_at FROM health_samples ORDER BY id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []domain.Health{}
	for rows.Next() {
		var h domain.Health
		var m, x string
		if e = rows.Scan(&h.Component, &h.Status, &h.Reason, &m, &x); e != nil {
			return nil, e
		}
		if h.MeasuredAt, e = time.Parse(time.RFC3339Nano, m); e != nil {
			return nil, e
		}
		if h.ExpiresAt, e = time.Parse(time.RFC3339Nano, x); e != nil {
			return nil, e
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
func (p *PortalStore) Instructions(ctx context.Context) ([]domain.Instruction, error) {
	rows, e := p.db.QueryContext(ctx, "SELECT id,os,title,verified_at IS NOT NULL,steps_json FROM instructions ORDER BY id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []domain.Instruction{}
	for rows.Next() {
		var d domain.Instruction
		var steps string
		if e = rows.Scan(&d.ID, &d.OS, &d.Title, &d.Verified, &steps); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(steps), &d.Steps); e != nil {
			return nil, e
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SeedDemo is explicit, atomic and never overwrites edits or refreshes health timestamps.
func (p *PortalStore) SeedDemo(ctx context.Context, now time.Time) error {
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var count int
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM app_metadata WHERE key='dataset' AND value='demo-v1'").Scan(&count); e != nil {
		return e
	}
	if count == 1 {
		return nil
	}
	if e = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM users) + (SELECT count(*) FROM instructions) + (SELECT count(*) FROM health_samples) + (SELECT count(*) FROM public_operations) + (SELECT count(*) FROM audit_events) + (SELECT count(*) FROM app_metadata)`).Scan(&count); e != nil {
		return e
	}
	if count != 0 {
		return fmt.Errorf("refusing to seed a nonempty unmarked database")
	}
	for _, id := range []string{"demo-family", "other-user"} {
		if _, e = tx.ExecContext(ctx, "INSERT INTO users(id,login,display_name,role,state,created_at) VALUES(?,?,?,'user','active',?)", id, id, id, now.UTC().Format(time.RFC3339Nano)); e != nil {
			return e
		}
	}
	f := fake.New(now)
	for _, d := range f.Devices {
		if _, e = tx.ExecContext(ctx, "INSERT INTO devices(id,user_id,name,os,state,created_at) VALUES(?,?,?,?,?,?)", d.ID, d.OwnerID, d.Name, d.OS, d.State, now.UTC().Format(time.RFC3339Nano)); e != nil {
			return e
		}
		for _, profile := range d.Profiles {
			if _, e = tx.ExecContext(ctx, "INSERT INTO profiles(id,device_id,protocol,generation,state,format) VALUES(?,?,?,1,?,?)", profile.ID, d.ID, profile.Protocol, profile.State, profile.Format); e != nil {
				return e
			}
		}
	}
	for _, h := range f.Samples {
		if _, e = tx.ExecContext(ctx, "INSERT INTO health_samples(component,status,reason,measured_at,expires_at) VALUES(?,?,?,?,?)", h.Component, h.Status, h.Reason, h.MeasuredAt.UTC().Format(time.RFC3339Nano), h.ExpiresAt.UTC().Format(time.RFC3339Nano)); e != nil {
			return e
		}
	}
	for _, g := range fake.Instructions() {
		b, _ := json.Marshal(g.Steps)
		if _, e = tx.ExecContext(ctx, "INSERT INTO instructions(id,os,title,steps_json,content_version) VALUES(?,?,?,?,1)", g.ID, g.OS, g.Title, string(b)); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO app_metadata VALUES('dataset','demo-v1')"); e != nil {
		return e
	}
	return tx.Commit()
}

// RenameDemo is a local persistence demonstration, not a public mutation endpoint.
func (p *PortalStore) RenameDemo(ctx context.Context, id, name string, expected int) error {
	if e := p.AssertDemo(ctx); e != nil {
		return e
	}
	if !validName(name) || expected < 1 {
		return fmt.Errorf("invalid name or revision")
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	result, e := tx.ExecContext(ctx, "UPDATE devices SET name=?,revision=revision+1 WHERE id=? AND user_id='demo-family' AND revision=?", name, id, expected)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if n == 0 {
		var count int
		if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM devices WHERE id=? AND user_id='demo-family'", id).Scan(&count); e != nil {
			return e
		}
		if count == 0 {
			return ErrNotFound
		}
		return ErrConflict
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO audit_events(id,actor,action,object_ref,outcome,time) VALUES(lower(hex(randomblob(16))),'demo-cli','device.rename',?,'succeeded',?)", id, time.Now().UTC().Format(time.RFC3339Nano))
	if e != nil {
		return e
	}
	return tx.Commit()
}
