package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/profileobserve"
	"familyvpn.local/platform/internal/profilevault"
	"time"
)

// AWGReadinessCandidate retains an immutable in-memory observation, never
// plaintext or a permission. Its JSON is diagnostic and cannot restore it.
type AWGReadinessCandidate struct {
	binding     profilevault.Context
	revision    int
	observation profileobserve.Result
	target      profileobserve.Target
	report      AWGReadinessCheck
}

type AWGReadinessCheck struct {
	CheckedAt          time.Time `json:"checked_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	SecretVerified     bool      `json:"secret_verified"`
	RuntimeTargetBound bool      `json:"runtime_target_bound"`
	RuntimeMatches     bool      `json:"runtime_matches"`
	WriterFenced       bool      `json:"writer_fenced"`
	Blockers           []string  `json:"blockers"`
	Ready              bool      `json:"ready"`
	ClientsVerified    bool      `json:"clients_verified"`
	StateChanged       bool      `json:"state_changed"`
	NetworkChanged     bool      `json:"network_changed"`
}

func (c AWGReadinessCandidate) Summary() AWGReadinessCheck {
	r := c.report
	r.Blockers = append([]string{}, r.Blockers...)
	if c.revision == 0 {
		r.Blockers = []string{"candidate_unprepared"}
	}
	return r
}
func (c AWGReadinessCandidate) MarshalJSON() ([]byte, error) { return json.Marshal(c.Summary()) }
func (*AWGReadinessCandidate) UnmarshalJSON([]byte) error    { return profilevault.ErrInput }
func (c AWGReadinessCandidate) String() string               { return "blocked AWG readiness candidate" }
func (c AWGReadinessCandidate) GoString() string             { return c.String() }

// This helper must remain within the eventual transition's writer transaction;
// a returned report or candidate never reserves a revision or authorizes ready.
func awgReadinessCheckTx(ctx context.Context, tx *sql.Tx, v *profilevault.Vault, c profilevault.Context, revision int, observation profileobserve.Result, target profileobserve.Target, fenced bool) (AWGReadinessCheck, error) {
	empty := AWGReadinessCheck{}
	plain, e := pendingAWGTx(ctx, tx, v, c, revision)
	if e != nil {
		return empty, e
	}
	defer clear(plain)
	validated, e := clientconfig.Validate(c.Format, plain)
	if e != nil {
		return empty, e
	}
	if validated.Protocol != c.Protocol {
		return empty, profilevault.ErrInput
	}
	if e = checkClientCredentialTx(ctx, tx, v, c.ProfileID, validated); e != nil {
		return empty, e
	}
	// Check after potentially expensive decryption/credential validation. Ledger
	// metadata is deliberately not read as a substitute for the sealed result.
	now := time.Now().UTC()
	if e = observation.Check(c, revision, plain, target, now); e != nil {
		return empty, e
	}
	s := observation.Summary()
	r := AWGReadinessCheck{CheckedAt: now, ExpiresAt: s.ExpiresAt, SecretVerified: true, RuntimeTargetBound: s.RuntimeTargetBound, WriterFenced: fenced, Blockers: []string{}}
	if !s.RuntimeObserved {
		r.Blockers = append(r.Blockers, "snapshot_not_runtime")
	}
	if !s.PeerMatches {
		r.Blockers = append(r.Blockers, "observation_conflict")
	}
	r.RuntimeMatches = s.RuntimeObserved && s.RuntimeTargetBound && s.PeerMatches
	// No actual-client attestor or audited transition exists yet. These gates
	// cannot be bypassed by callers, CLI flags, a match, or a historical row.
	r.Blockers = append(r.Blockers, "client_acceptance_missing", "readiness_transition_unavailable")
	return r, nil
}

// PrepareAWGReadiness is a trusted-only read transaction over the explicit
// pending binding, active vault, validated exact bytes and scoped observation.
// HTTP repositories and the keyless profile-readiness CLI do not expose it.
func (p *PortalStore) PrepareAWGReadiness(ctx context.Context, v *profilevault.Vault, c profilevault.Context, revision int, target profileobserve.Target, observation profileobserve.Result) (AWGReadinessCandidate, error) {
	empty := AWGReadinessCandidate{}
	if e := p.AssertLocalAuth(ctx); e != nil {
		return empty, e
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return empty, e
	}
	defer tx.Rollback()
	r, e := awgReadinessCheckTx(ctx, tx, v, c, revision, observation, target, false)
	if e != nil {
		return empty, e
	}
	if e = tx.Commit(); e != nil {
		return empty, e
	}
	return AWGReadinessCandidate{c, revision, observation, target, r}, nil
}

// RecheckAWGReadiness repeats every guard after obtaining the SQLite writer
// fence, then rolls back. The fence ends on return; this is neither a lease nor
// a transition. A future transition must run checks and its audit in one tx.
func (p *PortalStore) RecheckAWGReadiness(ctx context.Context, v *profilevault.Vault, candidate AWGReadinessCandidate, target profileobserve.Target) (AWGReadinessCheck, error) {
	if !candidate.binding.Valid() || candidate.revision < 1 {
		return AWGReadinessCheck{}, profilevault.ErrInput
	}
	if target != candidate.target {
		return AWGReadinessCheck{}, profileobserve.ErrStale
	}
	tx, e := p.profileWriteTx(ctx)
	if e != nil {
		return AWGReadinessCheck{}, e
	}
	defer tx.Rollback()
	r, e := awgReadinessCheckTx(ctx, tx, v, candidate.binding, candidate.revision, candidate.observation, target, true)
	if e != nil {
		return AWGReadinessCheck{}, e
	}
	if e = tx.Rollback(); e != nil {
		return AWGReadinessCheck{}, e
	}
	return r, nil
}
