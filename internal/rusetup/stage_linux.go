//go:build linux

package rusetup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"familyvpn.local/platform/internal/coreinstall"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func directory(s unix.Stat_t, private bool) bool {
	return s.Uid == 0 && s.Mode&unix.S_IFMT == unix.S_IFDIR && s.Mode&(0022|07000) == 0 && (!private || s.Mode&0777 == 0700)
}
func file(s unix.Stat_t) bool {
	return s.Uid == 0 && s.Mode&unix.S_IFMT == unix.S_IFREG && s.Mode&07777 == 0600 && s.Nlink == 1 && s.Size > 0 && s.Size <= MaxSize
}
func same(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

type component struct {
	fd   int
	name string
	stat unix.Stat_t
}
type chain []component

func (c chain) close() {
	for _, v := range c {
		unix.Close(v.fd)
	}
}
func (c chain) check() error {
	for n, v := range c {
		var s unix.Stat_t
		if unix.Fstat(v.fd, &s) != nil || !same(s, v.stat) {
			return ErrStage
		}
		if n > 0 && (unix.Fstatat(c[n-1].fd, v.name, &s, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(s, v.stat)) {
			return ErrStage
		}
	}
	return nil
}
func dirAt(parent int, name string, private bool) (component, error) {
	var before unix.Stat_t
	if unix.Fstatat(parent, name, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !directory(before, private) {
		return component{}, ErrStage
	}
	fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_DIRECTORY, 0)
	if e != nil {
		return component{}, ErrStage
	}
	var actual unix.Stat_t
	if unix.Fstat(fd, &actual) != nil || !directory(actual, private) || !same(before, actual) {
		unix.Close(fd)
		return component{}, ErrStage
	}
	return component{fd, name, actual}, nil
}
func base(create bool) (chain, error) {
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if e != nil {
		return nil, ErrStage
	}
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil || !directory(s, false) {
		unix.Close(fd)
		return nil, ErrStage
	}
	c := chain{{fd: fd, stat: s}}
	for _, name := range []string{"etc", "family-vpn"} {
		parent := c[len(c)-1].fd
		if name == "family-vpn" && create {
			var st unix.Stat_t
			if e := unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW); e == unix.ENOENT {
				if unix.Mkdirat(parent, name, 0700) != nil || unix.Fsync(parent) != nil {
					c.close()
					return nil, ErrStage
				}
				// Child creation changes the parent metadata legitimately.
				if unix.Fstat(parent, &c[len(c)-1].stat) != nil {
					c.close()
					return nil, ErrStage
				}
			}
		}
		child, e := dirAt(parent, name, false)
		if e != nil {
			c.close()
			return nil, ErrStage
		}
		c = append(c, child)
	}
	return c, nil
}

func writeAt(parent int, name string, data []byte) error {
	fd, e := unix.Openat(parent, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return ErrStage
	}
	f := os.NewFile(uintptr(fd), "RU private staged file")
	defer f.Close()
	if _, e := f.Write(data); e != nil || f.Sync() != nil {
		return ErrStage
	}
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil || !file(s) || s.Size != int64(len(data)) {
		return ErrStage
	}
	return nil
}

// stageAt exists only for package tests using an already checked directory
// descriptor. Public Stage has fixed paths and requires Linux root.
func stageAt(ctx context.Context, parent int, i Inputs, hop []byte) (Summary, error) {
	fail := func() (Summary, error) { return summary(false), ErrStage }
	var parentStat, existing unix.Stat_t
	if ctx.Err() != nil || unix.Fstat(parent, &parentStat) != nil || !directory(parentStat, false) {
		return fail()
	}
	if e := unix.Fstatat(parent, "ru-staging", &existing, unix.AT_SYMLINK_NOFOLLOW); e != unix.ENOENT {
		return fail()
	}
	// All validation and entropy generation finish before any staged file exists.
	b, e := Generate(i, hop)
	if e != nil {
		return summary(false), e
	}
	defer b.Clear()
	result, _, e := ValidateBundle(b)
	if e != nil {
		return fail()
	}
	var random [16]byte
	if _, e := rand.Read(random[:]); e != nil || ctx.Err() != nil {
		return fail()
	}
	name := ".ru-staging-" + hex.EncodeToString(random[:])
	if unix.Mkdirat(parent, name, 0700) != nil {
		return fail()
	}
	fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if e != nil {
		unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
		return fail()
	}
	defer unix.Close(fd)
	committed := false
	defer func() {
		if !committed {
			unix.Unlinkat(fd, "xray.json", 0)
			unix.Unlinkat(fd, "ru-hop.json", 0)
			unix.Unlinkat(fd, "sing-box.json", 0)
			unix.Unlinkat(fd, "plan.json", 0)
			unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
		}
	}()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !directory(st, true) || writeAt(fd, "xray.json", b.Xray) != nil || writeAt(fd, "ru-hop.json", b.Hop) != nil || writeAt(fd, "sing-box.json", b.SingBox) != nil || writeAt(fd, "plan.json", b.Plan) != nil || unix.Fsync(fd) != nil || ctx.Err() != nil {
		return fail()
	}
	// Atomic publication, never replacing an existing stage, including a symlink.
	if unix.Renameat2(parent, name, parent, "ru-staging", unix.RENAME_NOREPLACE) != nil {
		return fail()
	}
	committed = true
	if unix.Fsync(parent) != nil {
		// Preserve the published stage if directory persistence could not be confirmed.
		return fail()
	}
	return result, nil
}

// Stage creates a new private bundle only. It never installs a service, opens
// a listener or changes routes/firewall/SSH. Existing stages are preserved.
func Stage(ctx context.Context, i Inputs) (Summary, error) {
	if ValidateInputs(i) != nil {
		return summary(false), ErrInput
	}
	if ctx.Err() != nil {
		return summary(false), ErrStage
	}
	if os.Geteuid() != 0 {
		return summary(false), ErrPlatform
	}
	c, e := base(true)
	if e != nil {
		return summary(false), e
	}
	defer c.close()
	if c.check() != nil {
		return summary(false), ErrStage
	}
	parent := c[len(c)-1].fd
	d, e := dirAt(parent, "ru-import", true)
	if e != nil {
		return summary(false), ErrStage
	}
	defer unix.Close(d.fd)
	h, e := readAt(d.fd, "ru-hop.json")
	if e != nil {
		return summary(false), ErrStage
	}
	defer h.close()
	if closedDirectory(d.fd, []string{"ru-hop.json"}) != nil || h.check(d.fd) != nil {
		return summary(false), ErrStage
	}
	s, e := stageAt(ctx, parent, i, h.data)
	if e != nil {
		return s, e
	}
	if ctx.Err() != nil || checkAfterStage(c, d, h) != nil {
		return summary(false), ErrStage
	}
	return s, nil
}

func checkAfterStage(c chain, input component, hop privateFile) error {
	if len(c) == 0 {
		return ErrStage
	}
	parent := &c[len(c)-1]
	var current unix.Stat_t
	if unix.Fstat(parent.fd, &current) != nil || !directory(current, false) || current.Dev != parent.stat.Dev || current.Ino != parent.stat.Ino || current.Uid != parent.stat.Uid || current.Gid != parent.stat.Gid || current.Mode != parent.stat.Mode {
		return ErrStage
	}
	// Publishing the owned child legitimately changes only directory metadata.
	// Refresh this component while still binding its fixed path to the held inode.
	parent.stat = current
	if c.check() != nil || hop.check(input.fd) != nil || unix.Fstat(input.fd, &current) != nil || !same(input.stat, current) || unix.Fstatat(parent.fd, "ru-import", &current, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(input.stat, current) {
		return ErrStage
	}
	return nil
}

type privateFile struct {
	f    *os.File
	name string
	stat unix.Stat_t
	data []byte
}

func (f *privateFile) close() {
	clear(f.data)
	f.f.Close()
}
func readAt(parent int, name string) (privateFile, error) {
	var before unix.Stat_t
	if unix.Fstatat(parent, name, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !file(before) {
		return privateFile{}, ErrStage
	}
	fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if e != nil {
		return privateFile{}, ErrStage
	}
	f := os.NewFile(uintptr(fd), "RU protected configuration")
	var actual unix.Stat_t
	if unix.Fstat(fd, &actual) != nil || !file(actual) || !same(before, actual) {
		f.Close()
		return privateFile{}, ErrStage
	}
	b, e := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if e != nil || int64(len(b)) != before.Size || len(b) > MaxSize {
		clear(b)
		f.Close()
		return privateFile{}, ErrStage
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || !same(after, before) || unix.Fstatat(parent, name, &after, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(after, before) {
		clear(b)
		f.Close()
		return privateFile{}, ErrStage
	}
	if _, e := f.Seek(0, io.SeekStart); e != nil {
		clear(b)
		f.Close()
		return privateFile{}, ErrStage
	}
	return privateFile{f, name, before, b}, nil
}
func (f privateFile) check(parent int) error {
	var s unix.Stat_t
	if unix.Fstat(int(f.f.Fd()), &s) != nil || !same(s, f.stat) || unix.Fstatat(parent, f.name, &s, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(s, f.stat) {
		return ErrStage
	}
	return nil
}

// syntax uses only the installed core and protected config descriptors. Its
// environment has no caller XRAY_LOCATION_CONFIG/ASSET/plugin settings. All
// subprocess output is discarded, including potential core validation secrets.
func syntax(ctx context.Context, core string, config *os.File) error {
	a, e := coreinstall.VerifyInstalled(core)
	if e != nil || (core != "xray" && core != "sing-box") || a.Destination != "/usr/bin/"+core {
		return ErrNative
	}
	fd, e := unix.Open(a.Destination, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return ErrNative
	}
	tool := os.NewFile(uintptr(fd), "Pinned Xray syntax checker")
	defer tool.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Uid != 0 || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0755 || before.Nlink != 1 || before.Size != a.BinarySize {
		return ErrNative
	}
	h := sha256.New()
	if _, e := io.Copy(h, io.LimitReader(tool, a.BinarySize+1)); e != nil || hex.EncodeToString(h.Sum(nil)) != a.BinarySHA256 || unix.Fstat(fd, &after) != nil || !same(before, after) {
		return ErrNative
	}
	child, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	args := []string{"run", "-test", "-format", "json", "-config", "/proc/self/fd/4"}
	if core == "sing-box" {
		args = []string{"check", "-c", "/proc/self/fd/4"}
	}
	cmd := exec.CommandContext(child, "/proc/self/fd/3", args...)
	cmd.ExtraFiles = []*os.File{tool, config}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	kill := func() error {
		e := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if e == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return e
	}
	cmd.Cancel = kill
	cmd.WaitDelay = 200 * time.Millisecond
	if e := cmd.Run(); e != nil || child.Err() != nil {
		if cmd.Process != nil {
			_ = kill()
		}
		return ErrNative
	}
	// Do not leave subprocesses in the checker group after successful parent exit.
	_ = kill()
	if unix.Fstat(fd, &after) != nil || !same(before, after) {
		return ErrNative
	}
	return nil
}

func closedDirectory(fd int, names []string) error {
	dup, e := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if e != nil {
		return ErrStage
	}
	d := os.NewFile(uintptr(dup), "RU closed private directory")
	entries, e := d.Readdirnames(len(names) + 1)
	more, end := d.Readdirnames(1)
	d.Close()
	if e != nil && e != io.EOF || end != io.EOF || len(more) != 0 || len(entries) != len(names) {
		return ErrStage
	}
	seen := map[string]bool{}
	for _, n := range entries {
		seen[n] = true
	}
	for _, n := range names {
		if !seen[n] {
			return ErrStage
		}
	}
	return nil
}

func checkAt(ctx context.Context, parent int, native bool) (Summary, Binding, error) {
	fail := func(e error) (Summary, Binding, error) { return summary(false), Binding{}, e }
	c, e := dirAt(parent, "ru-staging", true)
	if e != nil || ctx.Err() != nil {
		return fail(ErrStage)
	}
	defer unix.Close(c.fd)
	var files []privateFile
	defer func() {
		for n := range files {
			files[n].close()
		}
	}()
	names := []string{"xray.json", "sing-box.json", "ru-hop.json", "plan.json"}
	for _, name := range names {
		f, e := readAt(c.fd, name)
		if e != nil {
			return fail(ErrStage)
		}
		files = append(files, f)
	}
	if closedDirectory(c.fd, names) != nil {
		return fail(ErrStage)
	}
	s, binding, e := ValidateBundle(Bundle{Xray: files[0].data, SingBox: files[1].data, Hop: files[2].data, Plan: files[3].data})
	if e != nil {
		return fail(e)
	}
	if native {
		if syntax(ctx, "xray", files[0].f) != nil || syntax(ctx, "sing-box", files[1].f) != nil {
			return s, Binding{}, ErrNative
		}
		s.NativeSyntaxValidated = true
	}
	for _, f := range files {
		if f.check(c.fd) != nil {
			return fail(ErrStage)
		}
	}
	var st unix.Stat_t
	if ctx.Err() != nil || unix.Fstat(c.fd, &st) != nil || !same(c.stat, st) || unix.Fstatat(parent, "ru-staging", &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(c.stat, st) {
		return fail(ErrStage)
	}
	return s, binding, nil
}

// Check reads the fixed protected stage. Optional core invocations only test
// syntax; this API cannot create a persistent process or change the network.
func Check(ctx context.Context, native bool) (Summary, Binding, error) {
	if os.Geteuid() != 0 {
		return summary(false), Binding{}, ErrPlatform
	}
	c, e := base(false)
	if e != nil {
		return summary(false), Binding{}, ErrStage
	}
	defer c.close()
	s, binding, e := checkAt(ctx, c[len(c)-1].fd, native)
	if e != nil {
		return s, Binding{}, e
	}
	if c.check() != nil {
		return summary(false), Binding{}, ErrStage
	}
	return s, binding, nil
}
