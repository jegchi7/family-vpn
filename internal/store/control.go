package store

import (
	"context"
	"fmt"
	"time"
)

type ControlStore struct{ *Database }

// Runtime requires an explicitly bootstrapped current schema; no implicit migration.
func OpenExistingControl(ctx context.Context, path string) (*ControlStore, error) {
	d, e := open(ctx, path, Control, false, false)
	if e != nil {
		return nil, e
	}
	return &ControlStore{d}, nil
}

func OpenControl(ctx context.Context, path string, readOnly bool) (*ControlStore, error) {
	d, e := Open(ctx, path, Control, readOnly)
	if e != nil {
		return nil, e
	}
	return &ControlStore{d}, nil
}
func (c *ControlStore) SeedDemo(ctx context.Context) error {
	tx, e := c.db.BeginTx(ctx, nil)
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
	if e = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM nodes) + (SELECT count(*) FROM revisions) + (SELECT count(*) FROM operations) + (SELECT count(*) FROM revocations) + (SELECT count(*) FROM audit_events) + (SELECT count(*) FROM app_metadata)`).Scan(&count); e != nil {
		return e
	}
	if count > 0 {
		return fmt.Errorf("refusing demo marker on a populated control store")
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO app_metadata(key,value) VALUES('dataset','demo-v1')"); e != nil {
		return e
	}
	return tx.Commit()
}

// RecordRevocation never removes or changes an existing tombstone.
// Runtime removal of VPN credentials is a later agent operation, NOT performed here.
func (c *ControlStore) RecordRevocation(ctx context.Context, id string, generation int, reason string) error {
	if id == "" || generation < 1 {
		return fmt.Errorf("invalid revocation")
	}
	_, e := c.db.ExecContext(ctx, "INSERT INTO revocations VALUES(?,?,?,?) ON CONFLICT(profile_id,generation) DO NOTHING", id, generation, time.Now().UTC().Format(time.RFC3339Nano), reason)
	return e
}
func (c *ControlStore) IsRevoked(ctx context.Context, id string, generation int) (bool, error) {
	var n int
	e := c.db.QueryRowContext(ctx, "SELECT count(*) FROM revocations WHERE profile_id=? AND generation=?", id, generation).Scan(&n)
	return n > 0, e
}
