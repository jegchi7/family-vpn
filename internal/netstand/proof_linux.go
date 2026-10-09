//go:build linux

package netstand

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"runtime"
	"time"

	"familyvpn.local/platform/internal/netguard"
	"golang.org/x/sys/unix"
)

func (r *nativeRunner) read(ctx context.Context, scope, tool string, args ...string) ([]byte, error) {
	return r.call(ctx, scope, tool, args, nil)
}

func (r *nativeRunner) verifyKernel(ctx context.Context, p netguard.Plan, activated bool) error {
	if ctx.Err() != nil || scopeCheck(r.target) != nil {
		return ErrGuardProof
	}
	hostNFT, e := r.read(ctx, "host", "nft", "-j", "list", "ruleset")
	if e != nil || netguard.VerifyNFTReadback(p, "host", hostNFT) != nil {
		return ErrGuardProof
	}
	nsNFT, e := r.read(ctx, netguard.Namespace, "nft", "-j", "list", "ruleset")
	if e != nil || netguard.VerifyNFTReadback(p, netguard.Namespace, nsNFT) != nil {
		return ErrGuardProof
	}
	var data [6][]byte
	requests := []struct {
		scope string
		args  []string
	}{
		{"host", []string{"-j", "-d", "link", "show"}}, {"host", []string{"-j", "address", "show"}}, {"host", []string{"-j", "-4", "-N", "route", "show", "table", "all"}},
		{netguard.Namespace, []string{"-j", "-d", "link", "show"}}, {netguard.Namespace, []string{"-j", "address", "show"}}, {netguard.Namespace, []string{"-j", "-4", "-N", "route", "show", "table", "all"}},
	}
	for n, q := range requests {
		data[n], e = r.read(ctx, q.scope, "ip", q.args...)
		if e != nil {
			return ErrGuardProof
		}
	}
	inventory, e := validateKernelTopology(data[0], data[1], data[2], data[3], data[4], data[5], p, activated)
	if e != nil {
		return ErrGuardProof
	}
	hostInterfaces := append(append([]string(nil), inventory.Interfaces...), netguard.HostVeth)
	if r.verifyTC(ctx, "host", hostInterfaces) != nil || r.verifyTC(ctx, netguard.Namespace, []string{"lo", netguard.NamespaceVeth}) != nil {
		return ErrGuardProof
	}
	for _, scope := range []string{"host", netguard.Namespace} {
		rules, e := r.read(ctx, scope, "ip", "-j", "-4", "-N", "rule", "show")
		if e != nil || parsePolicyRules(rules) != nil {
			return ErrGuardProof
		}
	}
	for _, scope := range []string{"host", netguard.Namespace} {
		sys, e := r.read(ctx, scope, "sysctl", append([]string{"-n"}, kernelSysctlKeys(scope)...)...)
		if e != nil || validateKernelSysctlsPhase(scope, sys, r.forwardingEnabled, r.forwardingTransition) != nil {
			return ErrGuardProof
		}
	}
	inventory.IPv4Forwarding = r.manifest.IPv4ForwardingBefore
	fresh, e := netguard.Build(r.inputs, inventory)
	if e != nil || !bytes.Equal(fresh.HostFirewall, p.HostFirewall) || !bytes.Equal(fresh.NamespaceFirewall, p.NamespaceFirewall) {
		return ErrGuardProof
	}
	if _, e := collectCoexistence(ctx, r.inputs, r.target, r.tools, inventory, &r.manifest.Coexistence); e != nil {
		return ErrGuardProof
	}
	if r.forwardingEnabled && !r.manifest.IPv4ForwardingBefore && !r.forwardingTransition {
		if verifyForwardingExpected(ctx, r.target, r.tools, hostInterfaces, r.manifest.ForwardingExpectedSHA256) != nil {
			return ErrGuardProof
		}
	}
	// Close the firewall observation after topology/sysctl reads. An intervening
	// unsupported NAT/offload declaration invalidates this observation.
	hostNFT, e = r.read(ctx, "host", "nft", "-j", "list", "ruleset")
	if e != nil || netguard.VerifyNFTReadback(p, "host", hostNFT) != nil {
		return ErrGuardProof
	}
	nsNFT, e = r.read(ctx, netguard.Namespace, "nft", "-j", "list", "ruleset")
	if e != nil || netguard.VerifyNFTReadback(p, netguard.Namespace, nsNFT) != nil || r.namespace.check() != nil || scopeCheck(r.target) != nil || ctx.Err() != nil {
		return ErrGuardProof
	}
	if _, e := collectCoexistence(ctx, r.inputs, r.target, r.tools, inventory, &r.manifest.Coexistence); e != nil {
		return ErrGuardProof
	}
	return nil
}
func (r *nativeRunner) GuardReadback(ctx context.Context, p netguard.Plan) error {
	return r.verifyKernel(ctx, p, false)
}

func Verify(ctx context.Context, i netguard.Inputs, t Target) (Proof, Summary, error) {
	if Validate(i, t) != nil {
		return Proof{}, Summary{}, ErrInput
	}
	if os.Geteuid() != 0 {
		return Proof{}, Summary{}, ErrPlatform
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	c, a, m, e := readStage(ctx)
	if e != nil {
		return Proof{}, Summary{}, e
	}
	defer c.close()
	defer clear(a.ForeignXray)
	s := summary(m)
	if m.Inputs != i || m.Target != t {
		return Proof{}, s, ErrGuardProof
	}
	if scopeCheck(t) != nil {
		return Proof{}, s, ErrGuardProof
	}
	bound, e := coreBinding(ctx, i, a.ForeignXray)
	defer clear(bound)
	if e != nil {
		return Proof{}, s, e
	}
	tools, e := openTools(t)
	if e != nil {
		return Proof{}, s, e
	}
	defer closeTools(tools)
	if readOperation(c[len(c)-1].fd, hash(a.Manifest), m.Steps) != nil {
		return Proof{}, s, ErrRecovery
	}
	r := &nativeRunner{target: t, tools: tools, inputs: i, artifacts: a, manifest: m, forwardingEnabled: true}
	defer func() { r.namespace.close() }()
	p, e := netguard.Build(i, m.Inventory)
	if e != nil {
		return Proof{}, s, ErrProtected
	}
	if r.verifyKernel(ctx, p, true) != nil || c.check() != nil {
		return Proof{}, s, ErrGuardProof
	}
	fd, e := unix.Dup(int(r.namespace.file.Fd()))
	if e != nil {
		return Proof{}, s, ErrGuardProof
	}
	unix.CloseOnExec(fd)
	file := os.NewFile(uintptr(fd), "private-guard-namespace")
	proof := Proof{inputs: i, target: t, namespace: file, observed: time.Now()}
	s.InventoryChecked = true
	s.ExecutionScopeBound = true
	s.KernelGuardVerified = true
	return proof, s, nil
}

// OpenNamespace duplicates a current, held kernel namespace descriptor. JSON,
// stale results, changed expected topology, closed files and namespace aliases
// never create an executable namespace handle.
func (p Proof) OpenNamespace(i netguard.Inputs, t Target) (*os.File, error) {
	if !p.valid(i, t, time.Now()) || Validate(i, t) != nil {
		return nil, ErrGuardProof
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if scopeCheck(t) != nil || noNamespaceOverrides() != nil {
		return nil, ErrGuardProof
	}
	h, e := openNamespace()
	if e != nil {
		return nil, ErrGuardProof
	}
	defer h.close()
	var held unix.Stat_t
	if unix.Fstat(int(p.namespace.Fd()), &held) != nil || !same(held, h.stat) || h.check() != nil || !p.valid(i, t, time.Now()) {
		return nil, ErrGuardProof
	}
	fd, e := unix.Dup(int(p.namespace.Fd()))
	if e != nil {
		return nil, ErrGuardProof
	}
	unix.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), "private-guard-namespace"), nil
}

// Used only by strict topology validation; addresses are never report fields.
func transitOwns(p netguard.Plan, a netip.Addr) bool {
	prefix, e := netip.ParsePrefix(p.Transit)
	return e == nil && prefix.Contains(a)
}
