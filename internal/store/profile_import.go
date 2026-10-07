package store

import (
	"context"
	"database/sql"
	"errors"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/profilevault"
)

var ErrClientCredentialConflict = errors.New("client credential is already assigned to another profile")

func checkClientCredentialTx(ctx context.Context, tx *sql.Tx, v *profilevault.Vault, target string, validated clientconfig.Validated) error {
	rows, e := tx.QueryContext(ctx, `SELECT p.id FROM profiles p JOIN devices d ON d.id=p.device_id WHERE p.id!=? AND p.format=? AND p.ciphertext IS NOT NULL AND p.state!='revoked' AND d.state!='revoked' ORDER BY p.id`, target, validated.Format)
	if e != nil {
		return e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, id := range ids {
		c, envelope, e := secretFromTx(ctx, tx, id)
		if e != nil {
			return e
		}
		data, e := v.Open(c, envelope)
		if e != nil {
			return e
		}
		other, e := clientconfig.Validate(c.Format, data)
		clear(data)
		if e != nil {
			return e
		}
		if clientconfig.SameCredential(validated, other) {
			return ErrClientCredentialConflict
		}
	}
	return nil
}

// ImportClientProfile validates before any write; dry-run uses a read transaction and can run on a read-only DB.
// Apply repeats all checks under the writer lock; a dry-run report is not an authorization or reservation.
func (p *PortalStore) ImportClientProfile(ctx context.Context, v *profilevault.Vault, c profilevault.Context, expectedRevision int, data []byte, apply bool) (StagedProfile, error) {
	empty := StagedProfile{}
	validated, e := clientconfig.Validate(c.Format, data)
	if e != nil {
		return empty, e
	}
	if !c.Valid() || c.Protocol != validated.Protocol || expectedRevision < 1 {
		return empty, profilevault.ErrInput
	}
	if e = p.AssertLocalAuth(ctx); e != nil {
		return empty, e
	}
	var tx *sql.Tx
	if apply {
		tx, e = p.profileWriteTx(ctx)
	} else {
		tx, e = p.db.BeginTx(ctx, nil)
	}
	if e != nil {
		return empty, e
	}
	defer tx.Rollback()
	result, e := stageProfileSecretTx(ctx, tx, v, c, expectedRevision, data, !apply, &validated)
	if e != nil {
		return empty, e
	}
	if e = tx.Commit(); e != nil {
		return empty, e
	}
	return result, nil
}

// ProfileImportTarget contains metadata only; it helps operators select explicit owner/device/profile bindings.
type ProfileImportTarget struct {
	OwnerID        string `json:"owner_id"`
	DeviceID       string `json:"device_id"`
	ProfileID      string `json:"profile_id"`
	Protocol       string `json:"protocol"`
	Generation     int    `json:"generation"`
	DeviceRevision int    `json:"device_revision"`
	DeviceState    string `json:"device_state"`
	ProfileState   string `json:"profile_state"`
	Format         string `json:"format"`
	Stored         bool   `json:"stored"`
}

func (p *PortalStore) ProfileImportTargets(ctx context.Context, login, device string) ([]ProfileImportTarget, error) {
	normalized, e := auth.NormalizeLogin(login)
	if e != nil {
		return nil, profilevault.ErrInput
	}
	if e = p.AssertLocalAuth(ctx); e != nil {
		return nil, e
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	var owner string
	if e = tx.QueryRowContext(ctx, "SELECT id FROM users WHERE login=? AND state='active' AND role='user'", normalized).Scan(&owner); e != nil {
		return nil, ErrNotFound
	}
	rows, e := tx.QueryContext(ctx, `SELECT d.user_id,d.id,p.id,p.protocol,p.generation,d.revision,d.state,p.state,p.format,p.ciphertext IS NOT NULL FROM devices d JOIN profiles p ON p.device_id=d.id AND p.generation=d.generation WHERE d.user_id=? AND (?='' OR d.id=?) ORDER BY d.id,p.protocol`, owner, device, device)
	if e != nil {
		return nil, e
	}
	out := []ProfileImportTarget{}
	for rows.Next() {
		var target ProfileImportTarget
		if e = rows.Scan(&target.OwnerID, &target.DeviceID, &target.ProfileID, &target.Protocol, &target.Generation, &target.DeviceRevision, &target.DeviceState, &target.ProfileState, &target.Format, &target.Stored); e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, target)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if device != "" && len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, tx.Commit()
}
