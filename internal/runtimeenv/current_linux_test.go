//go:build linux

package runtimeenv

import (
	"os"
	"runtime"
	"syscall"
	"testing"
)

func TestCurrentReadsCallingThreadAndStableBoot(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	a, e := Current()
	if e != nil || !a.Valid() {
		t.Fatal("local proc scope", e)
	}
	b, e := Current()
	if e != nil || a != b {
		t.Fatal("unstable scope", e)
	}
	st, e := os.Stat("/proc/thread-self/ns/net")
	if e != nil {
		t.Fatal(e)
	}
	ns := st.Sys().(*syscall.Stat_t)
	if a.NetNSDevice != uint64(ns.Dev) || a.NetNSInode != ns.Ino {
		t.Fatal("not calling thread namespace")
	}
}
