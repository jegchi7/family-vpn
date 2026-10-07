//go:build linux

package observerexec

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Real local helper processes exercise pipe/process semantics, not AWG/Xray.
func TestInheritedPipeDoesNotHangAfterParentExit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", `sleep 30 & echo $! > "$1"; printf partial`, "helper", pidFile)
	var out bytes.Buffer
	cmd.Stdout = &out
	start := time.Now()
	e := run(cmd)
	if !errors.Is(e, exec.ErrWaitDelay) || time.Since(start) > 2*time.Second {
		t.Fatal("inherited pipe was accepted or wait was unbounded", e)
	}
	if out.String() != "partial" {
		t.Fatal("helper did not exercise retained stdout")
	}
	assertChildStopped(t, pidFile)
}

func TestCancellationStopsProcessGroup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", `sleep 30 & echo $! > "$1"; wait`, "helper", pidFile)
	var out bytes.Buffer
	cmd.Stdout = &out
	start := time.Now()
	if e := run(cmd); e == nil || time.Since(start) > 2*time.Second {
		t.Fatal("cancellation was accepted or wait was unbounded", e)
	}
	assertChildStopped(t, pidFile)
}

func assertChildStopped(t *testing.T, file string) {
	t.Helper()
	b, e := os.ReadFile(file)
	if e != nil {
		t.Fatal("helper failed to start", e)
	}
	pid, e := strconv.Atoi(strings.TrimSpace(string(b)))
	if e != nil || pid < 1 {
		t.Fatal("invalid helper pid")
	}
	// Orphans can remain zombies until the environment's init reaps them.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		b, e = os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if os.IsNotExist(e) || e == nil && strings.Contains(string(b), ") Z ") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatal("descendant survived cancellation/pipe cleanup")
}

func TestPinnedDescriptorSuccessFailureAndCancelledStart(t *testing.T) {
	// A test helper descriptor only; production callers pin fixed AWG/Xray tools.
	tool, e := os.Open("/bin/sh")
	if e != nil {
		t.Fatal(e)
	}
	defer tool.Close()
	var out bytes.Buffer
	if e = Run(context.Background(), tool, []string{"-c", "printf ok"}, &out); e != nil || out.String() != "ok" {
		t.Fatal("descriptor execution failed", e)
	}
	out.Reset()
	if e = Run(context.Background(), tool, []string{"-c", "exit 7"}, &out); e == nil {
		t.Fatal("nonzero exit accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = Run(ctx, tool, []string{"-c", "printf forbidden"}, &out); e == nil || out.Len() != 0 {
		t.Fatal("cancelled start ran command", e)
	}
}
