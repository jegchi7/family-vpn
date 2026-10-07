package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/profileobserve"
	"familyvpn.local/platform/internal/profilevault"
	"time"
)

func pendingAWGTx(ctx context.Context, tx *sql.Tx, v *profilevault.Vault, c profilevault.Context, revision int) ([]byte, error) {
	if !c.Valid() || c.Protocol != "awg" || c.Format != clientconfig.AWG31Conf || revision < 1 {
		return nil, profilevault.ErrInput
	}
	return pendingClientTx(ctx, tx, v, c, revision)
}

func pendingClientTx(ctx context.Context, tx *sql.Tx, v *profilevault.Vault, c profilevault.Context, revision int) ([]byte, error) {
	if !c.Valid() || revision < 1 || !(c.Protocol == "awg" && c.Format == clientconfig.AWG31Conf || c.Protocol == "reality" && c.Format == clientconfig.VLESSRealityURI) {
		return nil, profilevault.ErrInput
	}
	var currentRevision, generation int
	var ds, ps string
	var installed *string
	e := tx.QueryRowContext(ctx, `SELECT d.revision,d.generation,d.state,p.state,p.installed_revision FROM profiles p JOIN devices d ON p.device_id=d.id JOIN users u ON u.id=d.user_id WHERE p.id=? AND d.id=? AND d.user_id=? AND p.generation=? AND p.protocol=? AND p.format=? AND u.state='active' AND u.role='user'`, c.ProfileID, c.DeviceID, c.OwnerID, c.Generation, c.Protocol, c.Format).Scan(&currentRevision, &generation, &ds, &ps, &installed)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if e != nil {
		return nil, e
	}
	if revision != currentRevision || generation != c.Generation {
		return nil, ErrConflict
	}
	if ds != "pending" || ps != "pending" || installed != nil {
		return nil, domain.ErrDeviceState
	}
	if e = profileKeyTx(ctx, tx, v); e != nil {
		return nil, e
	}
	actual, envelope, e := secretFromTx(ctx, tx, c.ProfileID)
	if e != nil || actual != c {
		return nil, profilevault.ErrEnvelope
	}
	return v.Open(actual, envelope)
}

// Trusted-only load for observation, never registered on HTTP or as a dump CLI.
func (p *PortalStore) LoadPendingAWGObservation(ctx context.Context, v *profilevault.Vault, c profilevault.Context, revision int) ([]byte, error) {
	if e := p.AssertLocalAuth(ctx); e != nil {
		return nil, e
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	plain, e := pendingAWGTx(ctx, tx, v, c, revision)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		clear(plain)
		return nil, e
	}
	return plain, nil
}

// The transaction rejects results for renamed/replaced/disabled targets, stale
// plaintext or expired observations. Recording never changes readiness/revision.
func (p *PortalStore) RecordProfileObservation(ctx context.Context, v *profilevault.Vault, c profilevault.Context, revision int, target profileobserve.Target, result profileobserve.Result) error {
	tx, e := p.profileWriteTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	plain, e := pendingAWGTx(ctx, tx, v, c, revision)
	if e != nil {
		return e
	}
	defer clear(plain)
	if e = result.Check(c, revision, plain, target, time.Now().UTC()); e != nil {
		return e
	}
	s := result.Summary()
	fields, e := json.Marshal(s.MismatchedFields)
	if e != nil {
		return profileobserve.ErrObservation
	}
	var existing string
	e = tx.QueryRowContext(ctx, "SELECT profile_id FROM profile_observations WHERE id=?", s.ID).Scan(&existing)
	if e == nil {
		if existing != c.ProfileID {
			return ErrConflict
		}
		return tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO profile_observations(id,profile_id,owner_id,generation,device_revision,source,peer_matches,mismatched_fields,measured_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, s.ID, c.ProfileID, c.OwnerID, c.Generation, revision, s.Source, s.PeerMatches, string(fields), stamp(s.MeasuredAt), stamp(s.ExpiresAt)); e != nil {
		return e
	}
	if e = profileAudit(ctx, tx, "profile.observe", c.ProfileID); e != nil {
		return e
	}
	return tx.Commit()
}
