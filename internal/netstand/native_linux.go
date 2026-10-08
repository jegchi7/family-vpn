//go:build linux

package netstand

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"familyvpn.local/platform/internal/foreignsetup"
	"familyvpn.local/platform/internal/netguard"
	"familyvpn.local/platform/internal/runtimeenv"
	"familyvpn.local/platform/internal/rusetup"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func same(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func protectedDir(s unix.Stat_t, private bool) bool {
	return s.Uid == 0 && s.Mode&unix.S_IFMT == unix.S_IFDIR && s.Mode&(0022|07000) == 0 && (!private || s.Mode&0777 == 0700)
}
func protectedFile(s unix.Stat_t, mode uint32, limit int64) bool {
	return s.Uid == 0 && s.Mode&unix.S_IFMT == unix.S_IFREG && s.Mode&07777 == mode && s.Nlink == 1 && s.Size > 0 && s.Size <= limit
}

type item struct {
	fd   int
	name string
	stat unix.Stat_t
}
type directoryChain []item

func (c directoryChain) close() {
	for _, i := range c {
		unix.Close(i.fd)
	}
}
func (c directoryChain) check() error {
	for n, i := range c {
		var st unix.Stat_t
		if unix.Fstat(i.fd, &st) != nil || !same(i.stat, st) {
			return ErrProtected
		}
		if n > 0 && (unix.Fstatat(c[n-1].fd, i.name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(st, i.stat)) {
			return ErrProtected
		}
	}
	return nil
}
func directoryAt(parent int, name string, private bool) (item, error) {
	var before, after unix.Stat_t
	if unix.Fstatat(parent, name, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !protectedDir(before, private) {
		return item{}, ErrProtected
	}
	fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
	if e != nil {
		return item{}, ErrProtected
	}
	if unix.Fstat(fd, &after) != nil || !same(before, after) || !protectedDir(after, private) {
		unix.Close(fd)
		return item{}, ErrProtected
	}
	return item{fd, name, after}, nil
}
func directories(parts []string, createFamily bool) (directoryChain, error) {
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if e != nil {
		return nil, ErrProtected
	}
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil || !protectedDir(s, false) {
		unix.Close(fd)
		return nil, ErrProtected
	}
	c := directoryChain{{fd: fd, stat: s}}
	for _, name := range parts {
		parent := c[len(c)-1].fd
		if createFamily && name == "family-vpn" {
			var current unix.Stat_t
			if e := unix.Fstatat(parent, name, &current, unix.AT_SYMLINK_NOFOLLOW); e == unix.ENOENT {
				if unix.Mkdirat(parent, name, 0700) != nil || unix.Fsync(parent) != nil || unix.Fstat(parent, &c[len(c)-1].stat) != nil {
					c.close()
					return nil, ErrProtected
				}
			}
		}
		i, e := directoryAt(parent, name, name == "network-staging")
		if e != nil {
			c.close()
			return nil, e
		}
		c = append(c, i)
	}
	return c, nil
}
func readProtected(parent int, name string) ([]byte, error) {
	var before, after unix.Stat_t
	if unix.Fstatat(parent, name, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !protectedFile(before, 0600, MaxArtifact) {
		return nil, ErrProtected
	}
	fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if e != nil {
		return nil, ErrProtected
	}
	f := os.NewFile(uintptr(fd), "protected-network-artifact")
	defer f.Close()
	if unix.Fstat(fd, &after) != nil || !same(before, after) {
		return nil, ErrProtected
	}
	data, e := io.ReadAll(io.LimitReader(f, MaxArtifact+1))
	if e != nil || int64(len(data)) != before.Size || unix.Fstat(fd, &after) != nil || !same(before, after) || unix.Fstatat(parent, name, &after, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(before, after) {
		return nil, ErrProtected
	}
	return data, nil
}
func writeProtected(parent int, name string, b []byte) error {
	fd, e := unix.Openat(parent, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return ErrProtected
	}
	f := os.NewFile(uintptr(fd), "new-network-artifact")
	defer f.Close()
	var s unix.Stat_t
	if _, e = f.Write(b); e != nil || f.Sync() != nil || unix.Fstat(fd, &s) != nil || !protectedFile(s, 0600, MaxArtifact) || s.Size != int64(len(b)) {
		return ErrProtected
	}
	return nil
}
func stageAt(ctx context.Context, parent int, a artifacts) error {
	if _, e := validateArtifacts(a); e != nil {
		return e
	}
	var parentStat, existing unix.Stat_t
	if ctx.Err() != nil || unix.Fstat(parent, &parentStat) != nil || !protectedDir(parentStat, false) {
		return ErrProtected
	}
	if unix.Fstatat(parent, "network-staging", &existing, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
		return ErrProtected
	}
	var entropy [16]byte
	if _, e := rand.Read(entropy[:]); e != nil || ctx.Err() != nil {
		return ErrProtected
	}
	name := ".network-staging-" + hex.EncodeToString(entropy[:])
	if unix.Mkdirat(parent, name, 0700) != nil {
		return ErrProtected
	}
	fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if e != nil {
		unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
		return ErrProtected
	}
	defer unix.Close(fd)
	committed := false
	defer func() {
		if !committed {
			for _, file := range []string{"manifest.json", "host.nft", "namespace.nft", "foreign-xray.json"} {
				unix.Unlinkat(fd, file, 0)
			}
			unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
		}
	}()
	if writeProtected(fd, "manifest.json", a.Manifest) != nil || writeProtected(fd, "host.nft", a.Host) != nil || writeProtected(fd, "namespace.nft", a.Namespace) != nil || unix.Fsync(fd) != nil || ctx.Err() != nil {
		return ErrProtected
	}
	if len(a.ForeignXray) > 0 && writeProtected(fd, "foreign-xray.json", a.ForeignXray) != nil {
		return ErrProtected
	}
	if unix.Fsync(fd) != nil || ctx.Err() != nil {
		return ErrProtected
	}
	if unix.Renameat2(parent, name, parent, "network-staging", unix.RENAME_NOREPLACE) != nil {
		return ErrProtected
	}
	committed = true
	if unix.Fsync(parent) != nil {
		return ErrProtected
	}
	return nil
}
func readStage(ctx context.Context) (directoryChain, artifacts, manifest, error) {
	var a artifacts
	fail := func(c directoryChain) (directoryChain, artifacts, manifest, error) {
		clear(a.ForeignXray)
		c.close()
		return nil, artifacts{}, manifest{}, ErrProtected
	}
	if ctx.Err() != nil {
		return fail(nil)
	}
	if os.Geteuid() != 0 {
		return nil, artifacts{}, manifest{}, ErrPlatform
	}
	c, e := directories([]string{"etc", "family-vpn", "network-staging"}, false)
	if e != nil {
		return nil, artifacts{}, manifest{}, e
	}
	if c.check() != nil {
		return fail(c)
	}
	fd := c[len(c)-1].fd
	duplicate, e := unix.Dup(fd)
	if e != nil {
		return fail(c)
	}
	dir := os.NewFile(uintptr(duplicate), "stage-directory")
	if dir == nil {
		return fail(c)
	}
	defer dir.Close()
	names, e := dir.Readdirnames(6)
	if e != nil && e != io.EOF {
		return fail(c)
	}
	if a.Manifest, e = readProtected(fd, "manifest.json"); e != nil {
		return fail(c)
	}
	if a.Host, e = readProtected(fd, "host.nft"); e != nil {
		return fail(c)
	}
	if a.Namespace, e = readProtected(fd, "namespace.nft"); e != nil {
		return fail(c)
	}
	var raw manifest
	if json.Unmarshal(a.Manifest, &raw) != nil {
		return fail(c)
	}
	expected := []string{"host.nft", "manifest.json", "namespace.nft"}
	if raw.Inputs.Role == "foreign" {
		expected = append(expected, "foreign-xray.json")
		if a.ForeignXray, e = readProtected(fd, "foreign-xray.json"); e != nil {
			return fail(c)
		}
	}
	for _, name := range names {
		if name == "apply.json" {
			expected = append(expected, name)
			if e := validateJournal(fd); e != nil {
				clear(a.ForeignXray)
				return fail(c)
			}
		}
	}
	if strings.Join(sorted(names), ",") != strings.Join(sorted(expected), ",") {
		clear(a.ForeignXray)
		return fail(c)
	}
	m, e := validateArtifacts(a)
	if e != nil || ctx.Err() != nil || c.check() != nil {
		clear(a.ForeignXray)
		return fail(c)
	}
	return c, a, m, nil
}
func Check(ctx context.Context) (Summary, error) {
	c, a, m, e := readStage(ctx)
	if e != nil {
		return Summary{}, e
	}
	defer c.close()
	defer clear(a.ForeignXray)
	bound, e := coreBinding(ctx, m.Inputs, a.ForeignXray)
	defer clear(bound)
	if e != nil {
		return Summary{}, e
	}
	return summary(m), nil
}
func coreBinding(ctx context.Context, i netguard.Inputs, expected []byte) ([]byte, error) {
	if i.Role == "ru" {
		_, binding, e := rusetup.Check(ctx, false)
		if e != nil || binding.RUIPv4 != i.RUIPv4.String() || binding.ForeignIPv4 != i.ForeignIPv4.String() {
			return nil, ErrProtected
		}
		return nil, nil
	}
	b, binding, e := foreignsetup.ReadNamespaceIPv4Config(ctx)
	if e != nil || binding.RUIPv4 != i.RUIPv4.String() || binding.ForeignIPv4 != i.ForeignIPv4.String() || expected != nil && !bytes.Equal(expected, b) {
		clear(b)
		return nil, ErrProtected
	}
	return b, nil
}
func sorted(s []string) []string {
	v := append([]string(nil), s...)
	for a := 0; a < len(v); a++ {
		for b := a + 1; b < len(v); b++ {
			if v[b] < v[a] {
				v[a], v[b] = v[b], v[a]
			}
		}
	}
	return v
}

type pinnedTool struct {
	file       *os.File
	path, name string
	stat       unix.Stat_t
	dirs       directoryChain
	hash       string
	aliases    []toolAlias
}

func (t *pinnedTool) close() {
	t.file.Close()
	t.dirs.close()
	for _, a := range t.aliases {
		a.dirs.close()
	}
}
func (t *pinnedTool) check() error {
	for _, a := range t.aliases {
		if a.check() != nil {
			return ErrProtected
		}
	}
	var st unix.Stat_t
	if t.dirs.check() != nil || unix.Fstat(int(t.file.Fd()), &st) != nil || !same(st, t.stat) || unix.Fstatat(t.dirs[len(t.dirs)-1].fd, t.name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(st, t.stat) {
		return ErrProtected
	}
	if _, e := t.file.Seek(0, io.SeekStart); e != nil {
		return ErrProtected
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(t.file, t.stat.Size+1))
	if e != nil || n != t.stat.Size || hex.EncodeToString(h.Sum(nil)) != t.hash || unix.Fstat(int(t.file.Fd()), &st) != nil || !same(st, t.stat) {
		return ErrProtected
	}
	return nil
}
func openTool(name, pin string) (*pinnedTool, error) {
	if !digestValid(pin) || (name != "ip" && name != "nft" && name != "sysctl" && name != "tc") {
		return nil, ErrInput
	}
	c, e := directories([]string{"usr", "sbin"}, false)
	if e != nil {
		return nil, e
	}
	var before, after unix.Stat_t
	parent := c[len(c)-1].fd
	if unix.Fstatat(parent, name, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !protectedFile(before, 0755, 64*1024*1024) {
		if name == "ip" && before.Mode&unix.S_IFMT == unix.S_IFLNK && before.Uid == 0 && before.Nlink == 1 {
			return openIPAlias(c, before, pin)
		}
		c.close()
		return nil, ErrProtected
	}
	fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if e != nil {
		c.close()
		return nil, ErrProtected
	}
	f := os.NewFile(uintptr(fd), "pinned-network-helper")
	if unix.Fstat(fd, &after) != nil || !same(before, after) {
		f.Close()
		c.close()
		return nil, ErrProtected
	}
	t := &pinnedTool{file: f, path: "/usr/sbin/" + name, name: name, stat: before, dirs: c, hash: pin}
	if helperELF(f) != nil {
		t.close()
		return nil, ErrProtected
	}
	if t.check() != nil {
		t.close()
		return nil, ErrProtected
	}
	return t, nil
}

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (w *boundedOutput) Write(b []byte) (int, error) {
	if len(b) > w.limit-w.Len() {
		return 0, ErrInventory
	}
	return w.Buffer.Write(b)
}
func scopeCheck(t Target) error {
	got, e := runtimeenv.Current()
	if e != nil || got != t.Scope {
		return ErrInventory
	}
	// Both independently expected current scope and fixed init namespace must
	// agree. This command cannot apply inside a manually entered data namespace.
	info, e := os.Stat("/proc/1/ns/net")
	if e != nil {
		return ErrInventory
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(st.Dev) != got.NetNSDevice || st.Ino != got.NetNSInode {
		return ErrInventory
	}
	return nil
}
func runTool(ctx context.Context, target Target, t *pinnedTool, args []string) ([]byte, error) {
	if ctx.Err() != nil || scopeCheck(target) != nil || t.check() != nil {
		return nil, ErrInventory
	}
	child, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(child, "/proc/self/fd/3", args...)
	cmd.ExtraFiles = []*os.File{t.file}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.Stdin = nil
	cmd.Stderr = io.Discard
	out := &boundedOutput{limit: 1024 * 1024}
	cmd.Stdout = out
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
	e := cmd.Run()
	if cmd.Process != nil {
		_ = kill()
	}
	if e != nil || t.check() != nil || scopeCheck(target) != nil {
		return nil, ErrExecution
	}
	return out.Bytes(), nil
}
func Prepare(ctx context.Context, i netguard.Inputs, target Target) (Summary, error) {
	if Validate(i, target) != nil {
		return Summary{}, ErrInput
	}
	if os.Geteuid() != 0 {
		return Summary{}, ErrPlatform
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if scopeCheck(target) != nil {
		return Summary{}, ErrInventory
	}
	foreignConfig, e := coreBinding(ctx, i, nil)
	if e != nil {
		return Summary{}, e
	}
	defer clear(foreignConfig)
	tools := map[string]*pinnedTool{}
	for _, spec := range []struct{ name, pin string }{{"ip", target.IP_SHA256}, {"nft", target.NFT_SHA256}, {"sysctl", target.SysctlSHA256}, {"tc", target.TCSHA256}} {
		t, e := openTool(spec.name, spec.pin)
		if e != nil {
			for _, t := range tools {
				t.close()
			}
			return Summary{}, e
		}
		tools[spec.name] = t
	}
	defer func() {
		for _, t := range tools {
			t.close()
		}
	}()
	inventory, e := collectInventory(ctx, target, tools)
	if e != nil {
		return Summary{}, e
	}
	p, e := netguard.Build(i, inventory)
	if e != nil {
		return Summary{}, ErrInventory
	}
	a, e := buildArtifacts(i, target, inventory, p)
	if e != nil {
		return Summary{}, e
	}
	if i.Role == "foreign" {
		var m manifest
		if json.Unmarshal(a.Manifest, &m) != nil {
			return Summary{}, ErrProtected
		}
		m.ForeignSHA256 = hash(foreignConfig)
		a.ForeignXray = foreignConfig
		a.Manifest, e = json.Marshal(m)
		if e != nil {
			return Summary{}, ErrProtected
		}
	}
	if scopeCheck(target) != nil || ctx.Err() != nil {
		return Summary{}, ErrInventory
	}
	c, e := directories([]string{"etc", "family-vpn"}, true)
	if e != nil {
		return Summary{}, e
	}
	defer c.close()
	if c.check() != nil {
		return Summary{}, ErrProtected
	}
	if stageAt(ctx, c[len(c)-1].fd, a) != nil {
		return Summary{}, ErrProtected
	}
	// Publication legitimately changes only the held family directory. Preserve
	// every ancestor identity and recheck its canonical path before reporting it.
	last := len(c) - 1
	old := c[last].stat
	var published unix.Stat_t
	if unix.Fstat(c[last].fd, &published) != nil || published.Dev != old.Dev || published.Ino != old.Ino || published.Uid != old.Uid || published.Gid != old.Gid || published.Mode != old.Mode || !protectedDir(published, false) || published.Nlink != old.Nlink+1 {
		return Summary{}, ErrProtected
	}
	c[last].stat = published
	if c.check() != nil {
		return Summary{}, ErrProtected
	}
	m, _ := validateArtifacts(a)
	s := summary(m)
	s.InventoryChecked = true
	s.ExecutionScopeBound = true
	return s, nil
}

func Apply(ctx context.Context, i netguard.Inputs, target Target) (Summary, error) {
	return applyNative(ctx, i, target)
}
