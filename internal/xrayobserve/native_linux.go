//go:build linux

package xrayobserve

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"familyvpn.local/platform/internal/observerexec"
	"familyvpn.local/platform/internal/profilevault"
	"familyvpn.local/platform/internal/runtimeenv"
	"io"
	"os"
	"runtime"
	"syscall"
)

type boundedOutput struct {
	data     []byte
	overflow bool
}

func (w *boundedOutput) Write(b []byte) (int, error) {
	if len(w.data)+len(b) > 64<<10 {
		w.overflow = true
		return 0, ErrRuntime
	}
	w.data = append(w.data, b...)
	return len(b), nil
}
func readNative(ctx context.Context, server, tag, pin string) ([]byte, error) {
	if !ValidTarget(server, tag, pin) {
		return nil, ErrInput
	}
	expected, _ := hex.DecodeString(pin)
	st, e := os.Lstat("/usr/bin/xray")
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Mode().Perm()&0111 == 0 {
		return nil, ErrRuntime
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return nil, ErrRuntime
	}
	f, e := os.Open("/usr/bin/xray")
	if e != nil {
		return nil, ErrRuntime
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(st, actual) || actual.Size() > 128<<20 {
		return nil, ErrRuntime
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, (128<<20)+1)); e != nil || !bytes.Equal(h.Sum(nil), expected) {
		return nil, ErrRuntime
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return nil, ErrRuntime
	}
	out := &boundedOutput{}
	if e = observerexec.Run(ctx, f, []string{"api", "inbounduser", "--server=" + server, "--timeout=3", "-tag=" + tag}, out); e != nil || out.overflow || len(out.data) == 0 {
		clear(out.data)
		return nil, ErrRuntime
	}
	return out.data, nil
}

// Observe executes only the pinned read-only API command; no config/apply path.
func Observe(ctx context.Context, c profilevault.Context, revision int, client []byte, target Target) (Result, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return observe(ctx, c, revision, client, target, readNative, runtimeenv.Current, checkInventory)
}
