package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/profileobserve"
	"time"
)

// ReadinessTarget is an explicit current binding, never an owner lookup hint.
type ReadinessTarget struct {
	OwnerID, DeviceID, ProfileID string
	Generation, ExpectedRevision int
}

func (t ReadinessTarget) Valid() bool {
	return auth.ValidToken(t.OwnerID) && auth.ValidToken(t.DeviceID) && auth.ValidToken(t.ProfileID) && t.Generation > 0 && t.ExpectedRevision > 0
}

type ReadinessObservation struct {
	ID               string    `json:"observation_id"`
	Source           string    `json:"source"`
	Status           string    `json:"status"`
	MeasuredAt       time.Time `json:"measured_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	MismatchedFields []string  `json:"mismatched_fields"`
}
type ProfileReadinessReport struct {
	CheckedAt                  time.Time             `json:"checked_at"`
	Protocol                   string                `json:"protocol"`
	Format                     string                `json:"format"`
	DeviceState                string                `json:"device_state"`
	ProfileState               string                `json:"profile_state"`
	Generation                 int                   `json:"generation"`
	DeviceRevision             int                   `json:"device_revision"`
	StoredExport               bool                  `json:"stored_export"`
	Observation                *ReadinessObservation `json:"observation"`
	RuntimeTargetVerified      bool                  `json:"runtime_target_verified"`
	StoredRuntimeReadbackFresh bool                  `json:"stored_runtime_readback_fresh"`
	Blockers                   []string              `json:"blockers"`
	Ready                      bool                  `json:"ready"`
	ClientsVerified            bool                  `json:"clients_verified"`
	SecretVerified             bool                  `json:"secret_verified"`
	ReadOnly                   bool                  `json:"read_only"`
	NetworkChanged             bool                  `json:"network_changed"`
}

func observationFields(raw string, matched bool) ([]string, error) {
	if len(raw) > 1024 {
		return nil, profileobserve.ErrObservation
	}
	var fields []string
	if json.Unmarshal([]byte(raw), &fields) != nil || !clientconfig.ValidAWGMismatchFields(fields) || matched != (len(fields) == 0) {
		return nil, profileobserve.ErrObservation
	}
	return fields, nil
}

// Trusted CLI metadata only. This is not a repository/HTTP interface and does
// not decrypt secrets, invoke a core, or authorize a transition or download.
func (p *PortalStore) ProfileReadiness(ctx context.Context, t ReadinessTarget) (ProfileReadinessReport, error) {
	return p.profileReadinessAt(ctx, t, time.Now().UTC())
}
func (p *PortalStore) profileReadinessAt(ctx context.Context, t ReadinessTarget, now time.Time) (ProfileReadinessReport, error) {
	empty := ProfileReadinessReport{}
	if !t.Valid() || now.IsZero() {
		return empty, auth.ErrInput
	}
	if e := p.AssertLocalAuth(ctx); e != nil {
		return empty, e
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return empty, e
	}
	defer tx.Rollback()
	r := ProfileReadinessReport{CheckedAt: now.UTC(), ReadOnly: true, Blockers: []string{}}
	var currentGeneration int
	e = tx.QueryRowContext(ctx, `SELECT p.protocol,p.format,d.state,p.state,p.generation,d.generation,d.revision,p.ciphertext IS NOT NULL
 FROM profiles p JOIN devices d ON d.id=p.device_id JOIN users u ON u.id=d.user_id
 WHERE p.id=? AND d.id=? AND d.user_id=? AND u.state='active' AND u.role='user'`, t.ProfileID, t.DeviceID, t.OwnerID).Scan(&r.Protocol, &r.Format, &r.DeviceState, &r.ProfileState, &r.Generation, &currentGeneration, &r.DeviceRevision, &r.StoredExport)
	if errors.Is(e, sql.ErrNoRows) {
		return empty, ErrNotFound
	}
	if e != nil {
		return empty, e
	}
	if r.Generation != t.Generation || currentGeneration != t.Generation || r.DeviceRevision != t.ExpectedRevision {
		return empty, ErrConflict
	}
	if r.DeviceState != "pending" {
		r.Blockers = append(r.Blockers, "device_state_blocked")
	}
	if r.ProfileState != "pending" {
		r.Blockers = append(r.Blockers, "profile_state_blocked")
	}
	if !r.StoredExport {
		r.Blockers = append(r.Blockers, "client_import_missing")
	}
	if !(r.Protocol == "awg" && r.Format == clientconfig.AWG31Conf || r.Protocol == "reality" && r.Format == clientconfig.VLESSRealityURI) {
		// Do not echo arbitrary DB format labels.
		if r.Format != "" {
			r.Format = "unsupported"
		}
		r.Blockers = append(r.Blockers, "client_format_unverified")
	}
	if r.Protocol != "awg" {
		r.Blockers = append(r.Blockers, "runtime_observer_unavailable")
	}
	// Latest observation wins, including a newer conflict or stale/future row.
	// Normalize fractional seconds as in AdminAudit; RFC3339Nano lexical order
	// would select 00Z before the later 00.1Z. No scan of unbounded history.
	const sortTime = "(substr(o.measured_at,1,19)||'.'||substr(CASE WHEN substr(o.measured_at,20,1)='.' THEN substr(o.measured_at,21,length(o.measured_at)-21) ELSE '' END||'000000000',1,9)||'Z')"
	o := ReadinessObservation{}
	var generation, revision int
	var matched bool
	var fields, measured, expires string
	e = tx.QueryRowContext(ctx, `SELECT o.id,o.source,o.generation,o.device_revision,o.peer_matches,o.mismatched_fields,o.measured_at,o.expires_at
 FROM profile_observations o WHERE o.profile_id=? AND o.owner_id=? ORDER BY `+sortTime+` DESC,o.id DESC LIMIT 1`, t.ProfileID, t.OwnerID).Scan(&o.ID, &o.Source, &generation, &revision, &matched, &fields, &measured, &expires)
	if errors.Is(e, sql.ErrNoRows) {
		r.Blockers = append(r.Blockers, "observation_missing")
	} else if e != nil {
		return empty, e
	} else {
		id, err := hex.DecodeString(o.ID)
		if err != nil || len(id) != 16 || hex.EncodeToString(id) != o.ID || (o.Source != "awg-runtime" && o.Source != "awg-snapshot") {
			return empty, profileobserve.ErrObservation
		}
		o.MeasuredAt, err = time.Parse(time.RFC3339Nano, measured)
		if err != nil || stamp(o.MeasuredAt) != measured {
			return empty, profileobserve.ErrObservation
		}
		o.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires)
		if err != nil || stamp(o.ExpiresAt) != expires || !o.ExpiresAt.Equal(o.MeasuredAt.Add(profileobserve.TTL)) {
			return empty, profileobserve.ErrObservation
		}
		o.MismatchedFields, err = observationFields(fields, matched)
		if err != nil {
			return empty, err
		}
		switch {
		case r.Protocol != "awg" || r.Format != clientconfig.AWG31Conf:
			o.Status = "unsupported"
			r.Blockers = append(r.Blockers, "observation_scope_unsupported")
		case generation != t.Generation || revision != t.ExpectedRevision:
			o.Status = "stale_binding"
			r.Blockers = append(r.Blockers, "observation_binding_stale")
		case now.Before(o.MeasuredAt):
			o.Status = "future"
			r.Blockers = append(r.Blockers, "observation_time_invalid")
		case !now.Before(o.ExpiresAt):
			o.Status = "expired"
			r.Blockers = append(r.Blockers, "observation_expired")
		case !matched:
			o.Status = "conflict"
			r.Blockers = append(r.Blockers, "observation_conflict")
		case o.Source == "awg-snapshot":
			o.Status = "configuration_only"
			r.Blockers = append(r.Blockers, "snapshot_not_runtime")
		default:
			o.Status = "fresh_match"
			r.StoredRuntimeReadbackFresh = true
		}
		r.Observation = &o
	}
	// Historical metadata is not immutable native Result, authenticated secret
	// content, client proof or a fencing token. There is no positive permission
	// outcome in this version; these blockers cannot be removed with CLI flags.
	r.Blockers = append(r.Blockers, "runtime_target_verification_required", "secret_verification_required", "client_acceptance_missing", "readiness_transition_unavailable")
	if e = tx.Commit(); e != nil {
		return empty, e
	}
	return r, nil
}
