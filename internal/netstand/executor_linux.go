//go:build linux

package netstand

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"

	"familyvpn.local/platform/internal/netguard"
	"familyvpn.local/platform/internal/runtimeenv"
	"golang.org/x/sys/unix"
)

func openTools(t Target) (map[string]*pinnedTool, error) {
	tools := map[string]*pinnedTool{}
	for _, s := range []struct{ name, pin string }{{"ip", t.IP_SHA256}, {"nft", t.NFT_SHA256}, {"sysctl", t.SysctlSHA256}, {"tc", t.TCSHA256}} {
		tool, e := openTool(s.name, s.pin)
		if e != nil {
			closeTools(tools)
			return nil, e
		}
		tools[s.name] = tool
	}
	return tools, nil
}
func closeTools(tools map[string]*pinnedTool) {
	for _, t := range tools {
		t.close()
	}
}

// ip netns exec mounts /etc/netns/<name> files. The closed stand forbids this
// implicit configuration channel rather than accepting resolver/preload files.
func noNamespaceOverrides() error {
	c, e := directories([]string{"etc"}, false)
	if e != nil {
		return e
	}
	defer c.close()
	var st unix.Stat_t
	e = unix.Fstatat(c[len(c)-1].fd, "netns", &st, unix.AT_SYMLINK_NOFOLLOW)
	if e == unix.ENOENT {
		return c.check()
	}
	if e != nil {
		return ErrProtected
	}
	item, e := directoryAt(c[len(c)-1].fd, "netns", false)
	if e != nil {
		return e
	}
	defer unix.Close(item.fd)
	if unix.Fstatat(item.fd, netguard.Namespace, &st, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT || c.check() != nil {
		return ErrProtected
	}
	return nil
}

type namespaceHandle struct {
	file *os.File
	dirs directoryChain
	stat unix.Stat_t
}

func (h *namespaceHandle) close() {
	if h == nil {
		return
	}
	if h.file != nil {
		h.file.Close()
	}
	h.dirs.close()
}
func (h *namespaceHandle) check() error {
	if h == nil || h.file == nil || h.dirs.check() != nil {
		return ErrGuardProof
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(int(h.file.Fd()), &st) != nil || !same(st, h.stat) || unix.Fstatat(h.dirs[len(h.dirs)-1].fd, netguard.Namespace, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(st, h.stat) || unix.Fstatfs(int(h.file.Fd()), &fs) != nil || uint64(fs.Type) != uint64(unix.NSFS_MAGIC) {
		return ErrGuardProof
	}
	return nil
}
func openNamespace() (*namespaceHandle, error) {
	c, e := directories([]string{"run", "netns"}, false)
	if e != nil {
		return nil, e
	}
	var before, after unix.Stat_t
	parent := c[len(c)-1].fd
	if unix.Fstatat(parent, netguard.Namespace, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || before.Uid != 0 || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0022 != 0 {
		c.close()
		return nil, ErrGuardProof
	}
	fd, e := unix.Openat(parent, netguard.Namespace, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		c.close()
		return nil, ErrGuardProof
	}
	f := os.NewFile(uintptr(fd), "private-data-namespace")
	if unix.Fstat(fd, &after) != nil || !same(before, after) {
		f.Close()
		c.close()
		return nil, ErrGuardProof
	}
	h := &namespaceHandle{f, c, before}
	if h.check() != nil {
		h.close()
		return nil, ErrGuardProof
	}
	return h, nil
}

type nativeRunner struct {
	target    Target
	tools     map[string]*pinnedTool
	namespace *namespaceHandle
	inputs    netguard.Inputs
	artifacts artifacts
}

func (r *nativeRunner) call(ctx context.Context, scope, name string, args []string, stdin []byte) ([]byte, error) {
	if name != "ip" && name != "nft" && name != "sysctl" && name != "tc" || scope != "host" && scope != netguard.Namespace || len(args) > 64 || len(stdin) > MaxArtifact || ctx.Err() != nil {
		return nil, ErrExecution
	}
	for _, a := range args {
		if len(a) > 4096 {
			return nil, ErrExecution
		}
	}
	if scopeCheck(r.target) != nil || r.tools[name].check() != nil {
		return nil, ErrProtected
	}
	tool := r.tools[name]
	extra := []*os.File{tool.file}
	arguments := append([]string(nil), args...)
	if scope == netguard.Namespace {
		if noNamespaceOverrides() != nil {
			return nil, ErrProtected
		}
		if r.namespace == nil {
			h, e := openNamespace()
			if e != nil {
				return nil, e
			}
			r.namespace = h
		}
		if r.namespace.check() != nil || r.tools["ip"].check() != nil {
			return nil, ErrProtected
		}
	}
	// The one namespace move command uses the already held descriptor, never a
	// second name lookup. No caller path is accepted by this closed rewrite.
	move := scope == "host" && name == "ip" && equalStrings(args, []string{"link", "set", netguard.NamespaceVeth, "netns", netguard.Namespace})
	if move {
		if r.namespace == nil || r.namespace.check() != nil {
			return nil, ErrProtected
		}
		extra = append(extra, r.namespace.file)
		arguments[len(arguments)-1] = "/proc/self/fd/4"
	}
	child, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(child, "/proc/self/fd/3", arguments...)
	cmd.ExtraFiles = extra
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stderr = io.Discard
	out := &boundedOutput{limit: 1024 * 1024}
	cmd.Stdout = out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	kill := func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		e := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if e == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return e
	}
	cmd.Cancel = kill
	cmd.WaitDelay = 200 * time.Millisecond
	started, e := r.startScoped(scope, cmd)
	if started {
		waitErr := cmd.Wait()
		if e == nil {
			e = waitErr
		}
	}
	if cmd.Process != nil {
		_ = kill()
	}
	if e != nil || ctx.Err() != nil || scopeCheck(r.target) != nil || tool.check() != nil || (scope == netguard.Namespace || move) && (r.namespace.check() != nil || noNamespaceOverrides() != nil) {
		return nil, ErrExecution
	}
	return bytes.Clone(out.Bytes()), nil
}
func (r *nativeRunner) Run(ctx context.Context, s netguard.Step) error {
	name := ""
	switch s.Executable {
	case netguard.IPExecutable:
		name = "ip"
	case netguard.NFTExecutable:
		name = "nft"
	case netguard.SysctlExecutable:
		name = "sysctl"
	default:
		return ErrInput
	}
	_, e := r.call(ctx, s.Scope, name, s.Args, s.Stdin)
	if e == nil && s.Scope == "host" && name == "ip" && equalStrings(s.Args, []string{"netns", "add", netguard.Namespace}) {
		r.namespace, e = openNamespace()
	}
	return e
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

type startResult struct {
	started bool
	err     error
}

func (r *nativeRunner) startScoped(scope string, cmd *exec.Cmd) (bool, error) {
	if scope == "host" {
		e := cmd.Start()
		return e == nil, e
	}
	result := make(chan startResult, 1)
	go func() {
		runtime.LockOSThread()
		clean := true
		defer func() {
			if clean {
				runtime.UnlockOSThread()
			}
		}()
		fail := func(started bool) {
			if started && cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
			result <- startResult{started, ErrExecution}
		}
		if scopeCheck(r.target) != nil || r.namespace.check() != nil {
			fail(false)
			return
		}
		fd, e := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if e != nil {
			fail(false)
			return
		}
		defer unix.Close(fd)
		var host unix.Stat_t
		var fs unix.Statfs_t
		if unix.Fstat(fd, &host) != nil || uint64(host.Dev) != r.target.Scope.NetNSDevice || host.Ino != r.target.Scope.NetNSInode || unix.Fstatfs(fd, &fs) != nil || uint64(fs.Type) != uint64(unix.NSFS_MAGIC) {
			fail(false)
			return
		}
		started, restored, startErr := namespaceStart(
			func() error {
				e := unix.Setns(int(r.namespace.file.Fd()), unix.CLONE_NEWNET)
				if e == nil {
					clean = false
				}
				return e
			},
			func() error {
				observed, e := runtimeenv.Current()
				if e != nil || observed.BootID != r.target.Scope.BootID || observed.NetNSDevice != uint64(r.namespace.stat.Dev) || observed.NetNSInode != r.namespace.stat.Ino || r.namespace.check() != nil {
					return ErrExecution
				}
				return nil
			},
			cmd.Start,
			func() error { return unix.Setns(fd, unix.CLONE_NEWNET) },
			func() error { return scopeCheck(r.target) },
		)
		// Never return a contaminated thread to the runtime. Exiting this still
		// locked goroutine makes Go terminate that thread if restoration fails.
		if !restored {
			fail(started)
			return
		}
		clean = true
		result <- startResult{started, startErr}
	}()
	startedResult := <-result
	return startedResult.started, startedResult.err
}
