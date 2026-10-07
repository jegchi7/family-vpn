//go:build linux

package xrayobserve

import (
	"bytes"
	"context"
	"errors"
	"familyvpn.local/platform/internal/runtimeenv"
	"runtime"
	"strings"
	"testing"
)

func TestBoundedNativeOutputAndInvalidInputs(t *testing.T) {
	w := &boundedOutput{}
	if n, e := w.Write(bytes.Repeat([]byte(" "), 64<<10)); e != nil || n != 64<<10 {
		t.Fatal("output boundary", e)
	}
	if _, e := w.Write([]byte("x")); !errors.Is(e, ErrRuntime) || !w.overflow || len(w.data) != 64<<10 {
		t.Fatal("unbounded output", e)
	}
	clear(w.data)
	if _, e := readNative(context.Background(), "192.0.2.1:10085", "clients", strings.Repeat("a", 64)); !errors.Is(e, ErrInput) {
		t.Fatal("nonloopback reader", e)
	}
}

func TestNativeEntryRejectsDifferentNamespaceBeforeToolOrAPI(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	s, e := runtimeenv.Current()
	if e != nil {
		t.Fatal("local proc unavailable", e)
	}
	c, client, _ := sample(t)
	target := testTarget()
	target.Scope = s
	target.Scope.NetNSInode++
	if _, e = Observe(context.Background(), c, 2, client, target); !errors.Is(e, ErrTarget) {
		t.Fatal("native entry reached tool/API in wrong namespace", e)
	}
}
