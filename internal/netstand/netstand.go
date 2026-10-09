// Package netstand prepares and applies closed, operator-only network plans.
// Only fresh fixed-helper readback can report an observed kernel guard; stored
// plans and observations never grant permission to start a VPN or mark ready.
package netstand

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/netguard"
	"familyvpn.local/platform/internal/runtimeenv"
	"io"
	"os"
	"strings"
	"time"
)

const MaxArtifact = 128 * 1024

var (
	ErrInput      = errors.New("network stand inputs rejected")
	ErrPlatform   = errors.New("network preparation requires Linux root")
	ErrProtected  = errors.New("protected network stand unavailable or changed")
	ErrInventory  = errors.New("current network inventory rejected")
	ErrExecution  = errors.New("network command failed or changed")
	ErrGuardProof = errors.New("native kernel guard readback acceptance unavailable")
	ErrForwarding = errors.New("zero host forwarding requires preserved host configuration")
	ErrRecovery   = errors.New("owned network state needs independently checked recovery")
)

// Target is independently selected. Current inventory cannot fill missing
// expected hashes or execution scope on the caller's behalf.
type Target struct {
	Scope          runtimeenv.Scope `json:"scope"`
	IP_SHA256      string           `json:"ip_sha256"`
	NFT_SHA256     string           `json:"nft_sha256"`
	SysctlSHA256   string           `json:"sysctl_sha256"`
	TCSHA256       string           `json:"tc_sha256"`
	XTLegacySHA256 string           `json:"xtables_legacy_sha256,omitempty"`
}

func digestValid(s string) bool {
	if len(s) != 64 || s == strings.Repeat("0", 64) {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for n := range a {
		if a[n] != b[n] {
			return false
		}
	}
	return true
}
func (t Target) Valid() bool {
	return t.Scope.Valid() && digestValid(t.IP_SHA256) && digestValid(t.NFT_SHA256) && digestValid(t.SysctlSHA256) && digestValid(t.TCSHA256) && (t.XTLegacySHA256 == "" || digestValid(t.XTLegacySHA256))
}
func Validate(i netguard.Inputs, t Target) error {
	if netguard.ValidateInputs(i) != nil || !t.Valid() || i.Role != "foreign" && t.XTLegacySHA256 != "" {
		return ErrInput
	}
	return nil
}

type Summary struct {
	Role                   string `json:"role"`
	PlannedSteps           int    `json:"planned_steps"`
	ConfigurationValidated bool   `json:"configuration_validated"`
	InventoryChecked       bool   `json:"inventory_checked"`
	ExecutionScopeBound    bool   `json:"execution_scope_bound"`
	KernelGuardVerified    bool   `json:"kernel_guard_verified"`
	NetworkChanged         bool   `json:"network_changed"`
	ServicesStarted        bool   `json:"services_started"`
	NativeAcceptance       bool   `json:"native_acceptance"`
	ClientVerified         bool   `json:"client_verified"`
	Ready                  bool   `json:"ready"`
}

// Proof stays in trusted CLI memory. It binds independently expected host
// scope/tool pins/topology and one held namespace descriptor. It is not a
// profile proof or a lease, and cannot be recovered from JSON.
type Proof struct {
	inputs    netguard.Inputs
	target    Target
	namespace *os.File
	observed  time.Time
}

func (p Proof) MarshalJSON() ([]byte, error) { return nil, ErrGuardProof }
func (p Proof) String() string               { return "[private kernel guard observation]" }
func (p Proof) GoString() string             { return p.String() }
func (p *Proof) Close() {
	if p.namespace != nil {
		p.namespace.Close()
	}
	*p = Proof{}
}
func (p Proof) valid(i netguard.Inputs, t Target, now time.Time) bool {
	if p.namespace == nil || p.inputs != i || p.target != t || now.Sub(p.observed) < 0 || now.Sub(p.observed) >= 10*time.Second {
		return false
	}
	_, e := p.namespace.Stat()
	return e == nil
}

type manifest struct {
	Format                   int                `json:"format"`
	Inputs                   netguard.Inputs    `json:"inputs"`
	Target                   Target             `json:"target"`
	Inventory                netguard.Inventory `json:"inventory"`
	IPv4ForwardingBefore     bool               `json:"ipv4_forwarding_before"`
	HostSHA256               string             `json:"host_sha256"`
	NamespaceSHA256          string             `json:"namespace_sha256"`
	ForeignSHA256            string             `json:"foreign_sha256,omitempty"`
	Steps                    int                `json:"steps"`
	ForwardingBaselineSHA256 string             `json:"forwarding_baseline_sha256,omitempty"`
	ForwardingExpectedSHA256 string             `json:"forwarding_expected_sha256,omitempty"`
	Coexistence              coexistence        `json:"coexistence"`
}
type artifacts struct{ Manifest, Host, Namespace, ForeignXray []byte }

func hash(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func buildArtifacts(i netguard.Inputs, t Target, v netguard.Inventory, p netguard.Plan) (artifacts, error) {
	if Validate(i, t) != nil || len(p.HostFirewall) == 0 || len(p.NamespaceFirewall) == 0 || len(p.HostFirewall) > MaxArtifact || len(p.NamespaceFirewall) > MaxArtifact || len(p.Steps) == 0 || len(p.Steps) > 64 {
		return artifacts{}, ErrInput
	}
	m := manifest{Format: 2, Inputs: i, Target: t, Inventory: v, IPv4ForwardingBefore: v.IPv4Forwarding, HostSHA256: hash(p.HostFirewall), NamespaceSHA256: hash(p.NamespaceFirewall), Steps: len(p.Steps)}
	b, e := json.Marshal(m)
	if e != nil || len(b) > MaxArtifact {
		return artifacts{}, ErrInput
	}
	return artifacts{Manifest: b, Host: bytes.Clone(p.HostFirewall), Namespace: bytes.Clone(p.NamespaceFirewall)}, nil
}
func validateArtifacts(a artifacts) (manifest, error) {
	var m manifest
	if len(a.Manifest) == 0 || len(a.Manifest) > MaxArtifact || len(a.Host) == 0 || len(a.Host) > MaxArtifact || len(a.Namespace) == 0 || len(a.Namespace) > MaxArtifact {
		return m, ErrProtected
	}
	d := json.NewDecoder(bytes.NewReader(a.Manifest))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF || m.Format != 2 || Validate(m.Inputs, m.Target) != nil || m.HostSHA256 != hash(a.Host) || m.NamespaceSHA256 != hash(a.Namespace) || m.Steps <= 0 || m.Steps > 64 || validatePreservationMetadata(m) != nil || m.Coexistence.valid(m.Inputs, m.Target) != nil {
		return manifest{}, ErrProtected
	}
	canonical, e := json.Marshal(m)
	if e != nil || !bytes.Equal(a.Manifest, canonical) {
		return manifest{}, ErrProtected
	}
	if m.Inputs.Role == "foreign" {
		if len(a.ForeignXray) == 0 || len(a.ForeignXray) > MaxArtifact || m.ForeignSHA256 != hash(a.ForeignXray) {
			return manifest{}, ErrProtected
		}
	} else if len(a.ForeignXray) != 0 || m.ForeignSHA256 != "" {
		return manifest{}, ErrProtected
	}
	p, e := netguard.Build(m.Inputs, m.Inventory)
	if e == nil {
		p, e = coexistencePlan(p, m.Coexistence)
	}
	if e != nil || m.Inventory.IPv4Forwarding != m.IPv4ForwardingBefore || len(p.Steps) != m.Steps || !bytes.Equal(p.HostFirewall, a.Host) || !bytes.Equal(p.NamespaceFirewall, a.Namespace) {
		return manifest{}, ErrProtected
	}
	// Protected artifacts are storage only. An apply must regenerate from fresh,
	// pinned native inventory, rather than replay these bytes as attestation.
	return m, nil
}
func summary(m manifest) Summary {
	return Summary{Role: m.Inputs.Role, PlannedSteps: m.Steps, ConfigurationValidated: true}
}

// executionEngine is exercised with synthetic runners only. No exported API
// accepts arbitrary steps or caller-owned executable paths. A guard readback
// boundary is mandatory before any activation phase can execute.
type engineRunner interface {
	Run(context.Context, netguard.Step) error
	GuardReadback(context.Context, netguard.Plan) error
}

func execute(ctx context.Context, p netguard.Plan, r engineRunner, boundary int) (int, error) {
	if boundary <= 0 || boundary >= len(p.Steps) {
		return 0, ErrInput
	}
	for n, s := range p.Steps {
		if ctx.Err() != nil {
			return n, ErrExecution
		}
		if n == boundary || n > boundary && activationStep(s) {
			if r.GuardReadback(ctx, p) != nil {
				return n, ErrGuardProof
			}
			if ctx.Err() != nil {
				return n, ErrExecution
			}
		}
		if r.Run(ctx, s) != nil {
			return n, ErrExecution
		}
	}
	return len(p.Steps), nil
}

func activationStep(s netguard.Step) bool {
	if s.Executable == netguard.IPExecutable {
		for _, a := range s.Args {
			if a == "up" {
				return true
			}
		}
	}
	if s.Executable == netguard.SysctlExecutable {
		for _, a := range s.Args {
			if a == "net.ipv4.ip_forward=1" {
				return true
			}
		}
	}
	return false
}

// namespaceStart is the restoration boundary used by the fixed-FD executor.
// A failed restore never authorizes releasing the locked thread to the runtime.
func namespaceStart(enter, verifyNamespace, start, restore, verifyHost func() error) (started, restored bool, err error) {
	if enter() != nil {
		return false, true, ErrExecution
	}
	err = verifyNamespace()
	if err == nil {
		err = start()
		started = err == nil
	}
	if restore() != nil || verifyHost() != nil {
		return started, false, ErrExecution
	}
	return started, true, err
}
