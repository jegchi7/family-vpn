package store

import (
	"context"
	"database/sql"
	"errors"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/profilevault"
)

// PreflightClientProfile decrypts only the explicit current owner binding in a
// read transaction. Server configuration bytes are never inserted into the DB.
// A successful comparison deliberately leaves profiles pending.
func (p *PortalStore) PreflightClientProfile(ctx context.Context, v *profilevault.Vault, c profilevault.Context, revision int, snapshot []byte, tag, endpoint, pin string) ([]string, error) {
	if !c.Valid() || c.Format != clientconfig.VLESSRealityURI || c.Protocol != "reality" || revision < 1 {
		return nil, profilevault.ErrInput
	}
	if e := p.AssertLocalAuth(ctx); e != nil {
		return nil, e
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	var actualRevision, currentGeneration int
	var state, deviceState string
	e = tx.QueryRowContext(ctx, `SELECT d.revision,d.generation,d.state,p.state FROM profiles p JOIN devices d ON d.id=p.device_id JOIN users u ON u.id=d.user_id WHERE p.id=? AND d.id=? AND d.user_id=? AND p.protocol=? AND p.generation=? AND p.format=? AND u.state='active' AND u.role='user'`, c.ProfileID, c.DeviceID, c.OwnerID, c.Protocol, c.Generation, c.Format).Scan(&actualRevision, &currentGeneration, &deviceState, &state)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if e != nil {
		return nil, e
	}
	if revision != actualRevision || currentGeneration != c.Generation {
		return nil, ErrConflict
	}
	if state != "pending" || deviceState != "pending" {
		return nil, domain.ErrDeviceState
	}
	if e = profileKeyTx(ctx, tx, v); e != nil {
		return nil, e
	}
	actual, envelope, e := secretFromTx(ctx, tx, c.ProfileID)
	if e != nil {
		return nil, profilevault.ErrEnvelope
	}
	data, e := v.Open(actual, envelope)
	if e != nil {
		return nil, e
	}
	defer clear(data)
	result, e := clientconfig.CheckXraySnapshot(c.Format, data, snapshot, tag, endpoint, pin)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return result, nil
}
