//go:build linux

package runtimeenv

import (
	"io"
	"os"
	"strings"
	"syscall"
)

// Current must be called on the same locked OS thread that starts the tool.
// It only reads fixed proc paths, never enters or creates a namespace.
func Current() (Scope, error) {
	st, e := os.Stat("/proc/thread-self/ns/net")
	if e != nil {
		return Scope{}, ErrScope
	}
	ns, ok := st.Sys().(*syscall.Stat_t)
	if !ok || ns.Dev == 0 || ns.Ino == 0 {
		return Scope{}, ErrScope
	}
	f, e := os.Open("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return Scope{}, ErrScope
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 38))
	if e != nil || len(b) != 37 || b[36] != '\n' || !ValidBootID(string(b[:36])) {
		return Scope{}, ErrScope
	}
	return Scope{strings.TrimSuffix(string(b), "\n"), uint64(ns.Dev), ns.Ino}, nil
}
