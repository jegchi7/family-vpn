//go:build linux

package netstand

import (
	"bytes"
	"context"
	"os"
	"runtime"

	"familyvpn.local/platform/internal/netguard"
	"golang.org/x/sys/unix"
)

func refreshStage(c directoryChain) error {
	if len(c) == 0 {
		return ErrProtected
	}
	n := len(c) - 1
	old := c[n].stat
	var fresh unix.Stat_t
	if unix.Fstat(c[n].fd, &fresh) != nil || fresh.Dev != old.Dev || fresh.Ino != old.Ino || fresh.Uid != old.Uid || fresh.Gid != old.Gid || fresh.Mode != old.Mode || fresh.Nlink != old.Nlink || !protectedDir(fresh, true) {
		return ErrProtected
	}
	c[n].stat = fresh
	return c.check()
}

type recordedRunner struct {
	native    *nativeRunner
	operation *operation
	completed int
	attempted bool
}

func (r *recordedRunner) Run(ctx context.Context, s netguard.Step) error {
	r.attempted = true
	if e := r.native.Run(ctx, s); e != nil {
		return e
	}
	r.completed++
	return r.operation.record(r.completed, "progress")
}
func (r *recordedRunner) GuardReadback(ctx context.Context, p netguard.Plan) error {
	return r.native.GuardReadback(ctx, p)
}

func applyNative(ctx context.Context, i netguard.Inputs, t Target) (Summary, error) {
	if Validate(i, t) != nil {
		return Summary{}, ErrInput
	}
	if os.Geteuid() != 0 {
		return Summary{}, ErrPlatform
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	c, a, m, e := readStage(ctx)
	if e != nil {
		return Summary{}, e
	}
	defer c.close()
	defer clear(a.ForeignXray)
	s := summary(m)
	if m.Inputs != i || m.Target != t {
		return s, ErrProtected
	}
	if scopeCheck(t) != nil {
		return s, ErrInventory
	}
	bound, e := coreBinding(ctx, i, a.ForeignXray)
	defer clear(bound)
	if e != nil {
		return s, e
	}
	fd := c[len(c)-1].fd
	// Existing operations are never replayed. Only a complete journal together
	// with fresh full kernel readback can produce an idempotent observed result.
	var st unix.Stat_t
	if e := unix.Fstatat(fd, "apply.json", &st, unix.AT_SYMLINK_NOFOLLOW); e == nil {
		if readOperation(fd, hash(a.Manifest), m.Steps) != nil {
			return s, ErrRecovery
		}
		proof, observed, e := Verify(ctx, i, t)
		proof.Close()
		if e != nil {
			return s, ErrRecovery
		}
		return observed, nil
	} else if e != unix.ENOENT {
		return s, ErrProtected
	}
	tools, e := openTools(t)
	if e != nil {
		return s, e
	}
	defer closeTools(tools)
	v, e := collectInventory(ctx, t, tools)
	if e != nil {
		return s, e
	}
	s.InventoryChecked = true
	s.ExecutionScopeBound = true
	// Linux's global forwarding transition also resets host interface behavior
	// and LRO. No write is allowed until preservation of that baseline exists.
	if !v.IPv4Forwarding || !m.IPv4ForwardingBefore {
		return s, ErrForwarding
	}
	p, e := netguard.Build(i, v)
	if e != nil || len(p.Steps) != m.Steps || !bytes.Equal(p.HostFirewall, a.Host) || !bytes.Equal(p.NamespaceFirewall, a.Namespace) {
		return s, ErrInventory
	}
	if c.check() != nil || scopeCheck(t) != nil || ctx.Err() != nil {
		return s, ErrProtected
	}
	boundary := -1
	for n, step := range p.Steps {
		if activationStep(step) {
			boundary = n
			break
		}
	}
	if boundary <= 0 {
		return s, ErrGuardProof
	}
	op, e := beginOperation(fd, hash(a.Manifest))
	if e != nil {
		return s, e
	}
	defer op.close()
	if refreshStage(c) != nil {
		return s, ErrProtected
	}
	r := &nativeRunner{target: t, tools: tools, inputs: i, artifacts: a}
	defer func() { r.namespace.close() }()
	recorded := &recordedRunner{native: r, operation: op}
	// Once the first mutation is attempted, an error cannot prove the kernel
	// unchanged. Preserve guards and the exclusive journal for checked recovery.
	_, e = execute(ctx, p, recorded, boundary)
	s.NetworkChanged = recorded.attempted
	if e != nil {
		_ = op.record(recorded.completed, "failed")
		return s, e
	}
	if r.verifyKernel(ctx, p, true) != nil || c.check() != nil {
		_ = op.record(recorded.completed, "failed")
		return s, ErrGuardProof
	}
	if op.record(recorded.completed, "complete") != nil {
		return s, ErrRecovery
	}
	s.KernelGuardVerified = true
	return s, nil
}
