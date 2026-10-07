// Package profileobserve produces immutable, scoped readback results, never readiness.
package profileobserve

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/profilevault"
	"time"
)

var ErrObservation = errors.New("profile observation unavailable or invalid")
var ErrStale = errors.New("profile observation expired or binding changed")
var ErrRuntime = errors.New("AWG runtime readback unavailable")
var ErrTarget = errors.New("AWG runtime target unavailable or changed")
var ErrDrift = errors.New("AWG runtime changed during readback")

const TTL = 60 * time.Second

type Result struct {
	binding  profilevault.Context
	revision int
	digest   [32]byte
	target   Target
	summary  Summary
}
type Summary struct {
	ID                 string    `json:"observation_id"`
	Source             string    `json:"source"`
	MeasuredAt         time.Time `json:"measured_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	PeerMatches        bool      `json:"peer_matches"`
	MismatchedFields   []string  `json:"mismatched_fields"`
	RuntimeTargetBound bool      `json:"runtime_target_bound"`
	RuntimeObserved    bool      `json:"runtime_observed"`
	ClientsVerified    bool      `json:"clients_verified"`
	Ready              bool      `json:"ready"`
}

func (r Result) Summary() Summary {
	s := r.summary
	s.MismatchedFields = append([]string{}, s.MismatchedFields...)
	return s
}
func (r Result) MarshalJSON() ([]byte, error) { return json.Marshal(r.Summary()) }
func (*Result) UnmarshalJSON([]byte) error    { return ErrObservation }
func (r Result) String() string               { return "scoped profile observation" }
func (r Result) GoString() string             { return r.String() }
func (r Result) Check(c profilevault.Context, revision int, client []byte, target Target, now time.Time) error {
	if r.summary.ID == "" || r.target != target || (r.summary.RuntimeObserved && !target.Valid()) || (!r.summary.RuntimeObserved && !target.validSnapshot()) || r.binding != c || r.revision != revision || r.digest != sha256.Sum256(client) || now.Before(r.summary.MeasuredAt) || !now.Before(r.summary.ExpiresAt) {
		return ErrStale
	}
	return nil
}
func result(c profilevault.Context, revision int, client, snapshot []byte, target Target, source string, now time.Time) (Result, error) {
	if !c.Valid() || c.Protocol != "awg" || c.Format != clientconfig.AWG31Conf || revision < 1 {
		return Result{}, ErrObservation
	}
	if !(source == "awg-runtime" && target.Valid() || source == "awg-snapshot" && target.validSnapshot()) {
		return Result{}, ErrTarget
	}
	fields, e := clientconfig.CheckAWGSnapshot(client, snapshot, target.Endpoint)
	if e != nil {
		return Result{}, e
	}
	id := make([]byte, 16)
	if _, e = rand.Read(id); e != nil {
		return Result{}, ErrObservation
	}
	return Result{c, revision, sha256.Sum256(client), target, Summary{RuntimeTargetBound: source == "awg-runtime" && target.Valid(), ID: hex.EncodeToString(id), Source: source, MeasuredAt: now, ExpiresAt: now.Add(TTL), PeerMatches: len(fields) == 0, MismatchedFields: fields, RuntimeObserved: source == "awg-runtime"}}, nil
}

// Snapshot is intentionally labelled as configuration only. No constructor lets
// callers label supplied bytes as a live/native observation.
func Snapshot(c profilevault.Context, revision int, client, snapshot []byte, endpoint string) (Result, error) {
	return result(c, revision, client, snapshot, Target{Endpoint: endpoint}, "awg-snapshot", time.Now().UTC())
}
