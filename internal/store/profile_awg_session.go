package store

import (
	"context"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/profileobserve"
	"familyvpn.local/platform/internal/profilevault"
	"time"
)

// CheckPendingAWGSession repeats current storage guards after the native reads.
// Session diagnostics never enter the configuration observation ledger or
// authorize a readiness transition. The returned summary is metadata only.
func (p *PortalStore) CheckPendingAWGSession(ctx context.Context, v *profilevault.Vault, c profilevault.Context, revision int, target profileobserve.Target, result profileobserve.SessionResult) (profileobserve.SessionSummary, error) {
	empty := profileobserve.SessionSummary{}
	if !c.Valid() || c.Protocol != "awg" || c.Format != clientconfig.AWG31Conf || revision < 1 {
		return empty, profilevault.ErrInput
	}
	if !target.Valid() {
		return empty, profileobserve.ErrTarget
	}
	if e := p.AssertLocalAuth(ctx); e != nil {
		return empty, e
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return empty, e
	}
	defer tx.Rollback()
	plain, e := pendingAWGTx(ctx, tx, v, c, revision)
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
