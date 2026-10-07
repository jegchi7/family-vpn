//go:build linux

// Package observerexec bounds execution of already pinned observer tools.
// Callers must validate the fixed tool, descriptor and allowlisted arguments.
package observerexec

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const pipeWait = 200 * time.Millisecond

// Run accepts only an already verified descriptor. The caller supplies a
// bounded, nonblocking stdout writer; stderr is discarded. No PATH lookup.
func Run(ctx context.Context, tool *os.File, args []string, stdout io.Writer) error {
	child, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(child, "/proc/self/fd/3", args...)
	cmd.ExtraFiles = []*os.File{tool}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.Stderr = io.Discard
	cmd.Stdout = stdout
	return run(cmd)
}

func run(cmd *exec.Cmd) error {
	// The default CommandContext cancellation kills only the immediate process.
	// A descendant can retain a pipe and keep Wait blocked beyond the deadline.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	killGroup := func() error {
		e := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(e, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return e
	}
	cmd.Cancel = killGroup
	cmd.WaitDelay = pipeWait
	e := cmd.Run()
	// Early successful parent exit can trigger WaitDelay before context expiry.
	// Clean up descendants remaining in that group as well as closing the pipes.
	if errors.Is(e, exec.ErrWaitDelay) {
		_ = killGroup()
	}
	return e
}
