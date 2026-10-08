package profileobserve

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/profilevault"
	"familyvpn.local/platform/internal/runtimeenv"
	"time"
)

const sessionSampleInterval = 2 * time.Second

// SessionResult is a sealed, short-lived observation of selected-peer activity.
// It is not the configuration observation used by readiness and cannot be
// restored from JSON or used as evidence of client import, DNS, or routing.
type SessionResult struct {
	binding  profilevault.Context
	revision int
	digest   [32]byte
	target   Target
	summary  SessionSummary
}

type SessionSummary struct {
	ObservationID        string     `json:"observation_id"`
	Source               string     `json:"source"`
	MeasuredAt           time.Time  `json:"measured_at"`
	ExpiresAt            time.Time  `json:"expires_at"`
	PeerObserved         bool       `json:"peer_observed"`
	LastHandshake        *time.Time `json:"last_handshake"`
	HandshakeRecent      bool       `json:"handshake_recent"`
	ReceivedAdvanced     bool       `json:"received_advanced"`
	SentAdvanced         bool       `json:"sent_advanced"`
	RuntimeTargetBound   bool       `json:"runtime_target_bound"`
	CoreIdentityVerified bool       `json:"core_identity_verified"`
	RevisionVerified     bool       `json:"revision_verified"`
	ClientsVerified      bool       `json:"clients_verified"`
	DNSRoutingVerified   bool       `json:"dns_routing_verified"`
	Ready                bool       `json:"ready"`
}

func (r SessionResult) Summary() SessionSummary {
	s := r.summary
	if s.LastHandshake != nil {
		last := *s.LastHandshake
		s.LastHandshake = &last
	}
	return s
}
func (r SessionResult) MarshalJSON() ([]byte, error) { return json.Marshal(r.Summary()) }
func (*SessionResult) UnmarshalJSON([]byte) error    { return ErrObservation }
func (r SessionResult) String() string               { return "scoped AWG session observation" }
func (r SessionResult) GoString() string             { return r.String() }

func (r SessionResult) Check(c profilevault.Context, revision int, client []byte, target Target, now time.Time) error {
	if r.summary.ObservationID == "" || !target.Valid() || r.target != target || r.binding != c || r.revision != revision || r.digest != sha256.Sum256(client) || now.Before(r.summary.MeasuredAt) || !now.Before(r.summary.ExpiresAt) {
		return ErrStale
	}
	return nil
}

func waitSession(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ErrRuntime
	case <-timer.C:
		return nil
	}
}

// The injectable boundaries are package-private and used only by contract tests.
// Native callers always use the fixed descriptor-pinned tool and proc reader.
func observeSession(ctx context.Context, c profilevault.Context, revision int, client []byte, target Target,
	read func(context.Context, string, string, string) ([]byte, error),
	environment func() (runtimeenv.Scope, error), wait func(context.Context, time.Duration) error) (SessionResult, error) {
	if !c.Valid() || c.Protocol != "awg" || c.Format != clientconfig.AWG31Conf || revision < 1 {
		return SessionResult{}, ErrObservation
	}
	if !target.Valid() {
		return SessionResult{}, ErrTarget
	}
	if len(client) == 0 || len(client) > profilevault.MaxSize {
		return SessionResult{}, ErrObservation
	}
	client = bytes.Clone(client)
	defer clear(client)
	if _, e := clientconfig.Validate(clientconfig.AWG31Conf, client); e != nil {
		return SessionResult{}, ErrObservation
	}
	start := time.Now().UTC()
	scope := func() error {
		if ctx.Err() != nil {
			return ErrRuntime
		}
		actual, e := environment()
		if e != nil || actual.BootID != target.BootID || actual.NetNSDevice != target.NetNSDevice || actual.NetNSInode != target.NetNSInode {
			return ErrTarget
		}
		if !time.Now().Before(start.Add(TTL)) {
			return ErrStale
		}
		return nil
	}
	var buffers [][]byte
	defer func() {
		for _, b := range buffers {
			clear(b)
		}
	}()
	if e := scope(); e != nil {
		return SessionResult{}, e
	}
	for _, view := range []string{"latest-handshakes", "transfer", "latest-handshakes", "transfer"} {
		if len(buffers) == 2 {
			if e := wait(ctx, sessionSampleInterval); e != nil {
				return SessionResult{}, ErrRuntime
			}
			if e := scope(); e != nil {
				return SessionResult{}, e
			}
		}
		data, e := read(ctx, target.Interface, target.ToolSHA256, view)
		buffers = append(buffers, data)
		if e != nil {
			return SessionResult{}, ErrRuntime
		}
		if e = scope(); e != nil {
			return SessionResult{}, e
		}
	}
	sampledAt := time.Now().UTC()
	sample, e := clientconfig.CheckAWGSession(client, buffers[0], buffers[1], buffers[2], buffers[3], sampledAt)
	if e != nil {
		return SessionResult{}, ErrRuntime
	}
	if e = scope(); e != nil {
		return SessionResult{}, e
	}
	id := make([]byte, 16)
	if _, e = rand.Read(id); e != nil {
		return SessionResult{}, ErrObservation
	}
	s := SessionSummary{ObservationID: hex.EncodeToString(id), Source: "awg-session-runtime", MeasuredAt: sampledAt, ExpiresAt: start.Add(TTL),
		PeerObserved: sample.PeerObserved, LastHandshake: sample.LastHandshake, HandshakeRecent: sample.HandshakeRecent,
		ReceivedAdvanced: sample.ReceivedAdvanced, SentAdvanced: sample.SentAdvanced, RuntimeTargetBound: true}
	return SessionResult{binding: c, revision: revision, digest: sha256.Sum256(client), target: target, summary: s}, nil
}
