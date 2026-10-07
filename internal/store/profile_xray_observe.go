package store

import (
	"context"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/profilevault"
	"familyvpn.local/platform/internal/xrayobserve"
	"time"
)

// Trusted-only read of exact current pending export. No HTTP or dump endpoint.
func (p *PortalStore) LoadPendingXrayUsersObservation(ctx context.Context, v *profilevault.Vault, c profilevault.Context, revision int) ([]byte, error) {
	if c.Protocol != "reality" || c.Format != clientconfig.VLESSRealityURI {
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
	plain, e := pendingClientTx(ctx, tx, v, c, revision)
	if e != nil {
		return nil, e
	}
	validated, e := clientconfig.Validate(c.Format, plain)
	if e == nil {
		e = checkClientCredentialTx(ctx, tx, v, c.ProfileID, validated)
	}
	if e != nil {
		clear(plain)
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		clear(plain)
		return nil, e
	}
	return plain, nil
}

// Repeat binding/key/AEAD/format/uniqueness/exact bytes/TTL after the API reads.
// No ledger/audit/state writes. The result is partial and never permits ready.
func (p *PortalStore) RecheckXrayUsersObservation(ctx context.Context, v *profilevault.Vault, c profilevault.Context, revision int, target xrayobserve.Target, result xrayobserve.Result) (xrayobserve.Summary, error) {
	empty := xrayobserve.Summary{}
	if c.Protocol != "reality" || c.Format != clientconfig.VLESSRealityURI {
		return empty, profilevault.ErrInput
	}
	if e := p.AssertLocalAuth(ctx); e != nil {
		return empty, e
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return empty, e
	}
	defer tx.Rollback()
	plain, e := pendingClientTx(ctx, tx, v, c, revision)
	if e != nil {
		return empty, e
	}
	defer clear(plain)
	validated, e := clientconfig.Validate(c.Format, plain)
	if e != nil {
		return empty, e
	}
	if e = checkClientCredentialTx(ctx, tx, v, c.ProfileID, validated); e != nil {
		return empty, e
	}
	if e = result.Check(c, revision, plain, target, time.Now().UTC()); e != nil {
		return empty, e
	}
	if e = tx.Commit(); e != nil {
		return empty, e
	}
	return result.Summary(), nil
}
