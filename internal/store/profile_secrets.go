package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/profilevault"
	"time"
)

// These trusted storage methods are deliberately not exposed through the HTTP repository interface.
// An importer must validate a client-only format before calling StageProfileSecret.
func (p *PortalStore) InitializeProfileVault(ctx context.Context, v *profilevault.Vault) error {
	if v == nil {
		return profilevault.ErrKey
	}
	if e := p.AssertLocalAuth(ctx); e != nil {
		return e
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "UPDATE app_metadata SET value=value WHERE key='dataset'"); e != nil {
		return e
	}
	var keyID string
	e = tx.QueryRowContext(ctx, "SELECT active_key_id FROM profile_vault_state WHERE singleton=1").Scan(&keyID)
	if e == nil {
		if keyID != v.ID() {
			return profilevault.ErrKey
		}
		if _, e = checkSecretsTx(ctx, tx, v); e != nil {
			return e
		}
		return tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	var count int
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM profiles WHERE ciphertext IS NOT NULL").Scan(&count); e != nil {
		return e
	}
	if count != 0 {
		return profilevault.ErrKey
	} // Never silently adopt pre-existing encrypted records.
	if _, e = tx.ExecContext(ctx, "INSERT INTO profile_vault_state(singleton,active_key_id) VALUES(1,?)", v.ID()); e != nil {
		return e
	}
	if e = profileAudit(ctx, tx, "profile-vault.initialize", "client-profiles"); e != nil {
		return e
	}
	return tx.Commit()
}
func profileAudit(ctx context.Context, tx *sql.Tx, action, object string) error {
	_, e := tx.ExecContext(ctx, "INSERT INTO audit_events(id,actor,action,object_ref,outcome,time) VALUES(?,'trusted-cli',?,?,'success',?)", auth.RandomToken(), action, object, stamp(time.Now()))
	return e
}
func profileKeyTx(ctx context.Context, tx *sql.Tx, v *profilevault.Vault) error {
	if v == nil {
		return profilevault.ErrKey
	}
	var id string
	if e := tx.QueryRowContext(ctx, "SELECT active_key_id FROM profile_vault_state WHERE singleton=1").Scan(&id); e != nil || id != v.ID() {
		return profilevault.ErrKey
	}
	return nil
}
func (p *PortalStore) profileWriteTx(ctx context.Context) (*sql.Tx, error) {
	if e := p.AssertLocalAuth(ctx); e != nil {
		return nil, e
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE profile_vault_state SET revision=revision WHERE singleton=1"); e != nil {
		tx.Rollback()
		return nil, e
	}
	return tx, nil
}

type StagedProfile struct {
	DeviceRevision int
	AlreadyStored  bool
}

func (p *PortalStore) StageProfileSecret(ctx context.Context, v *profilevault.Vault, c profilevault.Context, expectedRevision int, plaintext []byte) (StagedProfile, error) {
	empty := StagedProfile{}
	if !c.Valid() || expectedRevision < 1 || len(plaintext) == 0 || len(plaintext) > profilevault.MaxSize {
		return empty, profilevault.ErrInput
	}
	tx, e := p.profileWriteTx(ctx)
	if e != nil {
		return empty, e
	}
	defer tx.Rollback()
	result, e := stageProfileSecretTx(ctx, tx, v, c, expectedRevision, plaintext, false, nil)
	if e != nil {
		return empty, e
	}
	if e = tx.Commit(); e != nil {
		return empty, e
	}
	return result, nil
}
func stageProfileSecretTx(ctx context.Context, tx *sql.Tx, v *profilevault.Vault, c profilevault.Context, expectedRevision int, plaintext []byte, dryRun bool, validated *clientconfig.Validated) (StagedProfile, error) {
	empty := StagedProfile{}
	if e := profileKeyTx(ctx, tx, v); e != nil {
		return empty, e
	}
	if dryRun {
		var owner string
		if e := tx.QueryRowContext(ctx, "SELECT id FROM users WHERE id=? AND state='active' AND role='user'", c.OwnerID).Scan(&owner); e != nil {
			return empty, auth.ErrDenied
		}
	} else if e := lockDeviceOwner(ctx, tx, c.OwnerID); e != nil {
		return empty, e
	}
	var actual profilevault.Context
	var deviceState, profileState string
	var revision, currentGeneration int
	var installed *string
	var envelope profilevault.Envelope
	var storedKey *string
	e := tx.QueryRowContext(ctx, `SELECT p.id,d.id,d.user_id,p.protocol,p.generation,p.format,d.state,p.state,d.revision,d.generation,p.installed_revision,p.key_id,p.nonce,p.ciphertext FROM profiles p JOIN devices d ON d.id=p.device_id WHERE p.id=? AND d.id=? AND d.user_id=?`, c.ProfileID, c.DeviceID, c.OwnerID).Scan(&actual.ProfileID, &actual.DeviceID, &actual.OwnerID, &actual.Protocol, &actual.Generation, &actual.Format, &deviceState, &profileState, &revision, &currentGeneration, &installed, &storedKey, &envelope.Nonce, &envelope.Ciphertext)
	if errors.Is(e, sql.ErrNoRows) {
		return empty, ErrNotFound
	}
	if e != nil {
		return empty, e
	}
	if actual.Generation != c.Generation || actual.Protocol != c.Protocol || currentGeneration != c.Generation {
		return empty, ErrConflict
	}
	if deviceState != "pending" || profileState != "pending" || installed != nil {
		return empty, domain.ErrDeviceState
	}
	if validated != nil {
		if e := checkClientCredentialTx(ctx, tx, v, c.ProfileID, *validated); e != nil {
			return empty, e
		}
	}
	if storedKey != nil {
		envelope.KeyID = *storedKey
		existing, e := v.Open(actual, envelope)
		if e != nil {
			return empty, e
		}
		defer clear(existing)
		if actual.Format != c.Format || !bytes.Equal(existing, plaintext) {
			return empty, ErrConflict
		}
		// Replay succeeds even if another staged protocol or rename incremented the device revision.
		return StagedProfile{revision, true}, nil
	}
	if revision != expectedRevision || actual.Format != "" {
		return empty, ErrConflict
	}
	if dryRun {
		return StagedProfile{revision, false}, nil
	}
	envelope, e = v.Seal(c, plaintext)
	if e != nil {
		return empty, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE profiles SET format=?,ciphertext=?,nonce=?,key_id=? WHERE id=?", c.Format, envelope.Ciphertext, envelope.Nonce, envelope.KeyID, c.ProfileID); e != nil {
		return empty, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE devices SET revision=revision+1 WHERE id=?", c.DeviceID); e != nil {
		return empty, e
	}
	if e = profileAudit(ctx, tx, "profile.stage", c.ProfileID); e != nil {
		return empty, e
	}
	// Remains pending. No installed revision, IP allocation, agent call or publication.
	return StagedProfile{revision + 1, false}, nil
}
func secretFromTx(ctx context.Context, tx *sql.Tx, id string) (profilevault.Context, profilevault.Envelope, error) {
	var c profilevault.Context
	var e profilevault.Envelope
	err := tx.QueryRowContext(ctx, `SELECT p.id,d.id,d.user_id,p.protocol,p.generation,p.format,p.key_id,p.nonce,p.ciphertext FROM profiles p JOIN devices d ON d.id=p.device_id WHERE p.id=? AND p.ciphertext IS NOT NULL`, id).Scan(&c.ProfileID, &c.DeviceID, &c.OwnerID, &c.Protocol, &c.Generation, &c.Format, &e.KeyID, &e.Nonce, &e.Ciphertext)
	return c, e, err
}
func encryptedProfileIDs(ctx context.Context, tx *sql.Tx) ([]string, error) {
	rows, e := tx.QueryContext(ctx, "SELECT id FROM profiles WHERE ciphertext IS NOT NULL ORDER BY id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func checkSecretsTx(ctx context.Context, tx *sql.Tx, v *profilevault.Vault) (int, error) {
	if e := profileKeyTx(ctx, tx, v); e != nil {
		return 0, e
	}
	ids, e := encryptedProfileIDs(ctx, tx)
	if e != nil {
		return 0, e
	}
	for _, id := range ids {
		c, envelope, e := secretFromTx(ctx, tx, id)
		if e != nil {
			return 0, e
		}
		plain, e := v.Open(c, envelope)
		if e != nil {
			return 0, e
		}
		clear(plain)
	}
	return len(ids), nil
}
func (p *PortalStore) CheckProfileVault(ctx context.Context, v *profilevault.Vault) (int, error) {
	if e := p.AssertLocalAuth(ctx); e != nil {
		return 0, e
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	count, e := checkSecretsTx(ctx, tx, v)
	if e != nil {
		return 0, e
	}
	return count, tx.Commit()
}

// ReadReadyProfileSecret is an owner-scoped storage boundary for a future verified download adapter.
// It does not register an HTTP endpoint. The caller must clear the returned bytes.
func (p *PortalStore) ReadReadyProfileSecret(ctx context.Context, v *profilevault.Vault, owner, id string) ([]byte, error) {
	if e := p.AssertLocalAuth(ctx); e != nil {
		return nil, e
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	var state, deviceState string
	var installed *string
	e = tx.QueryRowContext(ctx, `SELECT p.state,d.state,p.installed_revision FROM profiles p JOIN devices d ON d.id=p.device_id JOIN users u ON u.id=d.user_id WHERE p.id=? AND d.user_id=? AND p.generation=d.generation AND u.state='active' AND u.role='user'`, id, owner).Scan(&state, &deviceState, &installed)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if e != nil {
		return nil, e
	}
	if state != "ready" || (deviceState != "active" && deviceState != "partial") || installed == nil || *installed == "" {
		return nil, domain.ErrDeviceState
	}
	if e = profileKeyTx(ctx, tx, v); e != nil {
		return nil, e
	}
	c, envelope, e := secretFromTx(ctx, tx, id)
	if e != nil {
		return nil, profilevault.ErrEnvelope
	}
	plaintext, e := v.Open(c, envelope)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		clear(plaintext)
		return nil, e
	}
	return plaintext, nil
}

// RotateProfileVault is atomic across all generations and states, including revoked profiles.
// The old key file is retained. A stale writer fails the active-key check after commit.
func (p *PortalStore) RotateProfileVault(ctx context.Context, old, new *profilevault.Vault) (int, error) {
	if old == nil || new == nil || old.ID() == new.ID() {
		return 0, profilevault.ErrKey
	}
	tx, e := p.profileWriteTx(ctx)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	var active string
	if e = tx.QueryRowContext(ctx, "SELECT active_key_id FROM profile_vault_state WHERE singleton=1").Scan(&active); e != nil {
		return 0, profilevault.ErrKey
	}
	if active == new.ID() { // Safe retry after uncertain commit: authenticate the entire result first.
		if _, e = checkSecretsTx(ctx, tx, new); e != nil {
			return 0, e
		}
		return 0, tx.Commit()
	}
	if active != old.ID() {
		return 0, profilevault.ErrKey
	}
	ids, e := encryptedProfileIDs(ctx, tx)
	if e != nil {
		return 0, e
	}
	for _, id := range ids {
		c, envelope, e := secretFromTx(ctx, tx, id)
		if e != nil {
			return 0, e
		}
		plain, e := old.Open(c, envelope)
		if e != nil {
			return 0, e
		}
		replacement, e := new.Seal(c, plain)
		clear(plain)
		if e != nil {
			return 0, e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE profiles SET key_id=?,nonce=?,ciphertext=? WHERE id=?", replacement.KeyID, replacement.Nonce, replacement.Ciphertext, id); e != nil {
			return 0, e
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE profile_vault_state SET active_key_id=?,revision=revision+1 WHERE singleton=1", new.ID()); e != nil {
		return 0, e
	}
	if e = profileAudit(ctx, tx, "profile-vault.rotate", "client-profiles"); e != nil {
		return 0, e
	}
	return len(ids), tx.Commit()
}
