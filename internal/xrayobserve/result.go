// Package xrayobserve reads named VLESS users only; no full core attestation.
package xrayobserve

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/profilevault"
	"familyvpn.local/platform/internal/runtimeenv"
	"familyvpn.local/platform/internal/xrayinventory"
	"time"
)

const TTL = 60 * time.Second

var ErrRuntime = errors.New("Xray users runtime unavailable")
var ErrTarget = errors.New("Xray execution environment unavailable or changed")
var ErrDrift = errors.New("Xray users changed during readback")
var ErrStale = errors.New("Xray users observation expired or binding changed")
var ErrInput = errors.New("invalid Xray users observation input")

type Result struct {
	binding  profilevault.Context
	revision int
	digest   [32]byte
	target   Target
	summary  Summary
}
type Summary struct {
	Source               string    `json:"source"`
	MeasuredAt           time.Time `json:"measured_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	UserObserved         bool      `json:"user_observed"`
	UserMatches          bool      `json:"user_matches"`
	MismatchedFields     []string  `json:"mismatched_fields"`
	InventoryBound       bool      `json:"inventory_bound"`
	ExecutionScopeBound  bool      `json:"execution_scope_bound"`
	RuntimeReadback      bool      `json:"runtime_readback"`
	EnumerationComplete  bool      `json:"enumeration_complete"`
	CoreIdentityVerified bool      `json:"core_identity_verified"`
	RevisionVerified     bool      `json:"revision_verified"`
	TransportVerified    bool      `json:"transport_verified"`
	ClientsVerified      bool      `json:"clients_verified"`
	Ready                bool      `json:"ready"`
}
type Target struct {
	Server, Tag, ToolSHA256, InventorySHA256 string
	Scope                                    runtimeenv.Scope
}

func (t Target) Valid() bool {
	return ValidTarget(t.Server, t.Tag, t.ToolSHA256) && t.Scope.Valid() && xrayinventory.ValidPin(t.InventorySHA256)
}

func (r Result) Summary() Summary {
	s := r.summary
	s.MismatchedFields = append([]string{}, s.MismatchedFields...)
	return s
}
func (r Result) MarshalJSON() ([]byte, error) { return json.Marshal(r.Summary()) }
func (*Result) UnmarshalJSON([]byte) error    { return ErrInput }
func (r Result) String() string               { return "partial scoped Xray users observation" }
func (r Result) GoString() string             { return r.String() }
func (r Result) Check(c profilevault.Context, revision int, client []byte, target Target, now time.Time) error {
	if r.summary.Source == "" || (r.summary.RuntimeReadback && !target.Valid()) || (!r.summary.RuntimeReadback && target != (Target{})) || r.binding != c || r.revision != revision || r.target != target || r.digest != sha256.Sum256(client) || now.Before(r.summary.MeasuredAt) || !now.Before(r.summary.ExpiresAt) {
		return ErrStale
	}
	return nil
}
func validBinding(c profilevault.Context, revision int) bool {
	return c.Valid() && c.Protocol == "reality" && c.Format == clientconfig.VLESSRealityURI && revision > 0
}
func ValidTarget(server, tag, pin string) bool { return xrayinventory.ValidTarget(server, tag, pin) }
func (t Target) inventoryExpected() xrayinventory.Expected {
	return xrayinventory.Expected{Server: t.Server, Tag: t.Tag, ToolSHA256: t.ToolSHA256, Scope: t.Scope}
}
func checkInventory(ctx context.Context, t Target) error {
	return xrayinventory.Require(ctx, t.InventorySHA256, t.inventoryExpected())
}

func result(c profilevault.Context, revision int, client []byte, comparison clientconfig.XrayUsers, target Target, source string, now time.Time) (Result, error) {
	if !validBinding(c, revision) || !(source == "xray-api-users" && target.Valid() || source == "xray-users-snapshot" && target == (Target{})) {
		return Result{}, ErrInput
	}
	s := comparison.Summary()
	return Result{c, revision, sha256.Sum256(client), target, Summary{InventoryBound: source == "xray-api-users" && target.Valid(), ExecutionScopeBound: source == "xray-api-users" && target.Valid(), Source: source, MeasuredAt: now, ExpiresAt: now.Add(TTL), UserObserved: s.UserObserved, UserMatches: s.UserMatches, MismatchedFields: s.MismatchedFields, RuntimeReadback: source == "xray-api-users"}}, nil
}

// Snapshot is configuration-only. No caller-supplied bytes can be labelled live.
func Snapshot(c profilevault.Context, revision int, client, response []byte) (Result, error) {
	r, e := clientconfig.CheckXrayUsers(client, response)
	if e != nil {
		return Result{}, e
	}
	return result(c, revision, client, r, Target{}, "xray-users-snapshot", time.Now().UTC())
}

type reader func(context.Context, string, string, string) ([]byte, error)

func observe(ctx context.Context, c profilevault.Context, revision int, client []byte, target Target, read reader, environment func() (runtimeenv.Scope, error), inventory func(context.Context, Target) error) (Result, error) {
	if !validBinding(c, revision) || !target.Valid() {
		return Result{}, ErrInput
	}
	if _, e := clientconfig.Validate(c.Format, client); e != nil {
		return Result{}, e
	}
	start := time.Now().UTC()
	scope := func() error {
		if ctx.Err() != nil {
			return ErrRuntime
		}
		actual, e := environment()
		if e != nil || actual != target.Scope {
			return ErrTarget
		}
		if e := inventory(ctx, target); e != nil {
			return xrayinventory.ErrInventory
		}
		if ctx.Err() != nil {
			return ErrRuntime
		}
		return nil
	}
	if e := scope(); e != nil {
		return Result{}, e
	}
	a, e := read(ctx, target.Server, target.Tag, target.ToolSHA256)
	if e != nil {
		clear(a)
		return Result{}, ErrRuntime
	}
	defer clear(a)
	if e = scope(); e != nil {
		return Result{}, e
	}
	before, e := clientconfig.CheckXrayUsers(client, a)
	if e != nil {
		return Result{}, e
	}
	b, e := read(ctx, target.Server, target.Tag, target.ToolSHA256)
	if e != nil {
		clear(b)
		return Result{}, ErrRuntime
	}
	defer clear(b)
	if e = scope(); e != nil {
		return Result{}, e
	}
	after, e := clientconfig.CheckXrayUsers(client, b)
	if e != nil {
		return Result{}, e
	}
	if !clientconfig.SameXrayUsers(before, after) {
		return Result{}, ErrDrift
	}
	if ctx.Err() != nil || !time.Now().Before(start.Add(TTL)) {
		return Result{}, ErrStale
	}
	return result(c, revision, client, after, target, "xray-api-users", start)
}
