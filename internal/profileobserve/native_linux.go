//go:build linux

package profileobserve

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/observerexec"
	"familyvpn.local/platform/internal/profilevault"
	"familyvpn.local/platform/internal/runtimeenv"
	"io"
	"os"
	"runtime"
	"syscall"
	"time"
)

type boundedOutput struct {
	data     []byte
	overflow bool
}

func (w *boundedOutput) Write(b []byte) (int, error) {
	if len(w.data)+len(b) > profilevault.MaxSize {
		w.overflow = true
		return 0, ErrRuntime
	}
	w.data = append(w.data, b...)
	return len(b), nil
}
func readNative(ctx context.Context, interfaceName, pin string) ([]byte, error) {
	if !validInterface(interfaceName) || len(pin) != 64 {
		return nil, ErrRuntime
	}
	expected, e := hex.DecodeString(pin)
	if e != nil {
		return nil, ErrRuntime
	}
	path := "/usr/bin/awg"
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Mode().Perm()&0111 == 0 {
		return nil, ErrRuntime
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return nil, ErrRuntime
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrRuntime
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(st, actual) || actual.Size() > 16<<20 {
		return nil, ErrRuntime
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, (16<<20)+1)); e != nil || !bytes.Equal(h.Sum(nil), expected) {
		return nil, ErrRuntime
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return nil, ErrRuntime
	}
	// Execute the already pinned descriptor with bounded pipe cleanup.
	output := &boundedOutput{}
	if e = observerexec.Run(ctx, f, []string{"showconf", interfaceName}, output); e != nil || output.overflow || len(output.data) == 0 {
		clear(output.data)
		return nil, ErrRuntime
	}
	return output.data, nil
}

// Observe only reads the named existing interface. It never invokes setconf,
// awg-quick, ip, a shell or a caller-provided executable. Both readbacks must be
// byte-identical; an intervening update is uncertain, not a successful match.
type runtimeEnvironment = runtimeenv.Scope

func currentEnvironment() (runtimeEnvironment, error) {
	scope, e := runtimeenv.Current()
	if e != nil {
		return runtimeEnvironment{}, ErrTarget
	}
	return scope, nil
}

func Observe(ctx context.Context, c profilevault.Context, revision int, client []byte, target Target) (Result, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return observe(ctx, c, revision, client, target, readNative, currentEnvironment)
}

func observe(ctx context.Context, c profilevault.Context, revision int, client []byte, target Target, read func(context.Context, string, string) ([]byte, error), environment func() (runtimeEnvironment, error)) (Result, error) {
	if !c.Valid() || c.Protocol != "awg" || c.Format != clientconfig.AWG31Conf || revision < 1 {
		return Result{}, ErrObservation
	}
	if !target.Valid() {
		return Result{}, ErrTarget
	}
	if _, e := clientconfig.Validate(clientconfig.AWG31Conf, client); e != nil {
		return Result{}, e
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
		return nil
	}
	if e := scope(); e != nil {
		return Result{}, e
	}
	before, e := read(ctx, target.Interface, target.ToolSHA256)
	if e != nil {
		clear(before)
		return Result{}, ErrRuntime
	}
	defer clear(before)
	if e = scope(); e != nil {
		return Result{}, e
	}
	after, e := read(ctx, target.Interface, target.ToolSHA256)
	if e != nil {
		clear(after)
		return Result{}, ErrRuntime
	}
	defer clear(after)
	if e = scope(); e != nil {
		return Result{}, e
	}
	if !bytes.Equal(before, after) {
		return Result{}, ErrDrift
	}
	if !time.Now().Before(start.Add(TTL)) {
		return Result{}, ErrStale
	}
	return result(c, revision, client, after, target, "awg-runtime", start)
}
