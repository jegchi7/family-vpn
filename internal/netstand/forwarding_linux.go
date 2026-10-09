//go:build linux

package netstand

import (
	"bytes"
	"context"
	"io"
	"os"
	"runtime"
	"sort"
	"unsafe"

	"familyvpn.local/platform/internal/netguard"
	"golang.org/x/sys/unix"
)

// Only these read-only Linux UAPI commands are used. No ethtool executable,
// driver-specific command, offload write or caller-selected pointer is accepted.
const (
	forwardingGSSetInfo   = 0x37
	forwardingGStrings    = 0x1b
	forwardingGFeatures   = 0x3a
	forwardingFeatureSet  = 4
	forwardingMaxFeatures = 256
)

type forwardingIfreq struct {
	name    [16]byte
	data    unsafe.Pointer
	padding [16]byte
}
type forwardingSSetInfo struct {
	command, reserved uint32
	mask              uint64
	count             uint32
}
type forwardingStrings struct {
	command, set, count uint32
	data                [forwardingMaxFeatures * 32]byte
}
type forwardingFeatureWords struct {
	command, count uint32
	words          [forwardingMaxFeatures / 32][4]uint32
}

func forwardingIoctl(ctx context.Context, t Target, fd int, name string, command uint32, data unsafe.Pointer) error {
	if (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") || unsafe.Sizeof(forwardingIfreq{}) != 40 || !forwardingName(name) || data == nil || (command != forwardingGSSetInfo && command != forwardingGStrings && command != forwardingGFeatures) || *(*uint32)(data) != command || ctx.Err() != nil || scopeCheck(t) != nil {
		return ErrForwarding
	}
	request := forwardingIfreq{data: data}
	copy(request.name[:], name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&request)))
	runtime.KeepAlive(data)
	runtime.KeepAlive(&request)
	if errno != 0 || ctx.Err() != nil || scopeCheck(t) != nil {
		return ErrForwarding
	}
	return nil
}

func forwardingFeatureState(ctx context.Context, t Target, socket int, name string) (forwardingFeatures, error) {
	info := forwardingSSetInfo{command: forwardingGSSetInfo, mask: 1 << forwardingFeatureSet}
	if forwardingIoctl(ctx, t, socket, name, info.command, unsafe.Pointer(&info)) != nil || info.command != forwardingGSSetInfo || info.reserved != 0 || info.mask != 1<<forwardingFeatureSet || info.count == 0 || info.count > forwardingMaxFeatures {
		return forwardingFeatures{}, ErrForwarding
	}
	strings := forwardingStrings{command: forwardingGStrings, set: forwardingFeatureSet, count: info.count}
	if forwardingIoctl(ctx, t, socket, name, strings.command, unsafe.Pointer(&strings)) != nil || strings.command != forwardingGStrings || strings.set != forwardingFeatureSet || strings.count != info.count {
		return forwardingFeatures{}, ErrForwarding
	}
	words := forwardingFeatureWords{command: forwardingGFeatures, count: (info.count + 31) / 32}
	if forwardingIoctl(ctx, t, socket, name, words.command, unsafe.Pointer(&words)) != nil || words.command != forwardingGFeatures || words.count != (info.count+31)/32 {
		return forwardingFeatures{}, ErrForwarding
	}
	out := forwardingFeatures{words: append([][4]uint32(nil), words.words[:words.count]...)}
	for n := uint32(0); n < info.count; n++ {
		data := strings.data[n*32 : (n+1)*32]
		end := bytes.IndexByte(data, 0)
		if end < 0 || !bytes.Equal(data[end:], make([]byte, 32-end)) {
			return forwardingFeatures{}, ErrForwarding
		}
		out.names = append(out.names, string(data[:end]))
	}
	if validateForwardingFeatures(out) != nil {
		return forwardingFeatures{}, ErrForwarding
	}
	return out, nil
}

func forwardingProcIdentity(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Nlink == b.Nlink
}

func forwardingProcDirIdentity(a, b unix.Stat_t) bool {
	// /proc reports dynamic process counts in st_nlink. conf directories also
	// gain the deliberately created owned veth. Neither link counts, directory
	// sizes nor timestamps are stable identity for a fixed procfs directory.
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode
}

type forwardingProcChain []item

func (c forwardingProcChain) close() {
	for _, entry := range c {
		unix.Close(entry.fd)
	}
}

func (c forwardingProcChain) check() error {
	if len(c) < 2 {
		return ErrForwarding
	}
	for n, entry := range c {
		var st unix.Stat_t
		if unix.Fstat(entry.fd, &st) != nil || !protectedDir(st, false) {
			return ErrForwarding
		}
		if n == 0 {
			if !same(entry.stat, st) {
				return ErrForwarding
			}
			continue
		}
		var fs unix.Statfs_t
		if !forwardingProcDirIdentity(entry.stat, st) || unix.Fstatfs(entry.fd, &fs) != nil || uint64(fs.Type) != uint64(unix.PROC_SUPER_MAGIC) || unix.Fstatat(c[n-1].fd, entry.name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !forwardingProcDirIdentity(entry.stat, st) {
			return ErrForwarding
		}
	}
	return nil
}

func forwardingDirectoryAt(parent int, name string) (item, error) {
	var before, after unix.Stat_t
	if unix.Fstatat(parent, name, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !protectedDir(before, false) {
		return item{}, ErrForwarding
	}
	fd, e := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
	if e != nil {
		return item{}, ErrForwarding
	}
	var fs unix.Statfs_t
	if unix.Fstat(fd, &after) != nil || !forwardingProcDirIdentity(before, after) || !protectedDir(after, false) || unix.Fstatfs(fd, &fs) != nil || uint64(fs.Type) != uint64(unix.PROC_SUPER_MAGIC) {
		unix.Close(fd)
		return item{}, ErrForwarding
	}
	return item{fd, name, after}, nil
}

func forwardingDirectories(parts []string) (forwardingProcChain, error) {
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if e != nil {
		return nil, ErrForwarding
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !protectedDir(st, false) || !equalStrings(parts, []string{"proc", "sys", "net", "ipv4"}) {
		unix.Close(fd)
		return nil, ErrForwarding
	}
	c := forwardingProcChain{{fd: fd, stat: st}}
	for _, name := range parts {
		entry, e := forwardingDirectoryAt(c[len(c)-1].fd, name)
		if e != nil {
			c.close()
			return nil, e
		}
		c = append(c, entry)
	}
	if c.check() != nil {
		c.close()
		return nil, ErrForwarding
	}
	return c, nil
}

func forwardingProcFile(fd int, st unix.Stat_t) bool {
	var fs unix.Statfs_t
	return unix.Fstatfs(fd, &fs) == nil && uint64(fs.Type) == uint64(unix.PROC_SUPER_MAGIC) && st.Uid == 0 && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&(0022|07000) == 0 && st.Nlink == 1 && st.Size == 0
}

func forwardingProcValue(parent int, key string) (int32, error) {
	allowed := key == "ip_forward"
	for _, k := range forwardingConfKeys {
		allowed = allowed || key == k
	}
	if !allowed {
		return 0, ErrForwarding
	}
	var before, after unix.Stat_t
	if unix.Fstatat(parent, key, &before, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return 0, ErrForwarding
	}
	fd, e := unix.Openat(parent, key, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if e != nil {
		return 0, ErrForwarding
	}
	f := os.NewFile(uintptr(fd), "fixed-kernel-forwarding-value")
	defer f.Close()
	if unix.Fstat(fd, &after) != nil || !forwardingProcIdentity(before, after) || !forwardingProcFile(fd, after) {
		return 0, ErrForwarding
	}
	data, e := io.ReadAll(io.LimitReader(f, 13))
	if e != nil {
		return 0, ErrForwarding
	}
	value, e := forwardingNumber(data)
	if e != nil {
		return 0, ErrForwarding
	}
	if unix.Fstat(fd, &after) != nil || !forwardingProcIdentity(before, after) || !forwardingProcFile(fd, after) || unix.Fstatat(parent, key, &after, unix.AT_SYMLINK_NOFOLLOW) != nil || !forwardingProcIdentity(before, after) {
		return 0, ErrForwarding
	}
	return value, nil
}

func forwardingNamesAt(parent int, maximum int) ([]string, error) {
	fd, e := unix.Openat(parent, ".", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrForwarding
	}
	f := os.NewFile(uintptr(fd), "fixed-kernel-forwarding-directory")
	defer f.Close()
	var fs unix.Statfs_t
	var st unix.Stat_t
	if unix.Fstatfs(fd, &fs) != nil || uint64(fs.Type) != uint64(unix.PROC_SUPER_MAGIC) || unix.Fstat(fd, &st) != nil || !protectedDir(st, false) {
		return nil, ErrForwarding
	}
	names, e := f.Readdirnames(maximum + 1)
	if e != nil && e != io.EOF || len(names) > maximum {
		return nil, ErrForwarding
	}
	sort.Strings(names)
	return names, nil
}

func sameForwardingInterfaces(names []string, expected []string) bool {
	a, b := append([]string(nil), names...), append([]string(nil), expected...)
	sort.Strings(a)
	sort.Strings(b)
	return equalStrings(a, b)
}

func collectForwardingObservation(ctx context.Context, t Target, tools map[string]*pinnedTool, interfaces []string, owned bool) (forwardingObservation, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fail := func() (forwardingObservation, error) { return forwardingObservation{}, ErrForwarding }
	if !t.Valid() || ctx.Err() != nil || scopeCheck(t) != nil || len(interfaces) == 0 || len(interfaces) > 256 || tools["ip"] == nil || tools["sysctl"] == nil || tools["ip"].check() != nil || tools["sysctl"].check() != nil {
		return fail()
	}
	linksBytes, e := runTool(ctx, t, tools["ip"], []string{"-j", "-d", "link", "show"})
	if e != nil {
		return fail()
	}
	links, names, e := kernelLinks(linksBytes)
	if e != nil || !sameForwardingInterfaces(names, interfaces) {
		return fail()
	}
	o := forwardingObservation{scope: t.Scope, links: map[string]int{}, conf: map[string]map[string]int32{}, features: map[string]forwardingFeatures{}}
	for name, link := range links {
		o.links[name] = link.index
	}
	c, e := forwardingDirectories([]string{"proc", "sys", "net", "ipv4"})
	if e != nil {
		return fail()
	}
	defer c.close()
	var fs unix.Statfs_t
	parent := c[len(c)-1].fd
	if unix.Fstatfs(parent, &fs) != nil || uint64(fs.Type) != uint64(unix.PROC_SUPER_MAGIC) {
		return fail()
	}
	if o.global, e = forwardingProcValue(parent, "ip_forward"); e != nil {
		return fail()
	}
	conf, e := forwardingDirectoryAt(parent, "conf")
	if e != nil {
		return fail()
	}
	defer unix.Close(conf.fd)
	want := append(append([]string(nil), interfaces...), "all", "default")
	confNames, e := forwardingNamesAt(conf.fd, 258)
	if e != nil || !sameForwardingInterfaces(confNames, want) {
		return fail()
	}
	for _, name := range confNames {
		if name != "all" && name != "default" && !forwardingName(name) || ctx.Err() != nil || scopeCheck(t) != nil {
			return fail()
		}
		dir, e := forwardingDirectoryAt(conf.fd, name)
		if e != nil {
			return fail()
		}
		values, readErr := readForwardingConf(dir.fd)
		var after unix.Stat_t
		stable := unix.Fstat(dir.fd, &after) == nil && forwardingProcDirIdentity(dir.stat, after) && unix.Fstatat(conf.fd, name, &after, unix.AT_SYMLINK_NOFOLLOW) == nil && forwardingProcDirIdentity(dir.stat, after)
		unix.Close(dir.fd)
		if readErr != nil || !stable {
			return fail()
		}
		o.conf[name] = values
	}
	socket, e := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if e != nil {
		return fail()
	}
	defer unix.Close(socket)
	for _, name := range names {
		f, e := forwardingFeatureState(ctx, t, socket, name)
		if e != nil {
			return fail()
		}
		o.features[name] = f
	}
	end, e := runTool(ctx, t, tools["ip"], []string{"-j", "-d", "link", "show"})
	if e != nil {
		return fail()
	}
	after, afterNames, e := kernelLinks(end)
	if e != nil || !sameForwardingInterfaces(afterNames, names) {
		return fail()
	}
	for name, link := range links {
		if after[name].index != link.index {
			return fail()
		}
	}
	if c.check() != nil || ctx.Err() != nil || scopeCheck(t) != nil || tools["ip"].check() != nil || tools["sysctl"].check() != nil || validateForwardingObservation(o, owned) != nil {
		return fail()
	}
	return o, nil
}

func readForwardingConf(parent int) (map[string]int32, error) {
	keys, e := forwardingNamesAt(parent, len(forwardingConfKeys))
	if e != nil || !equalStrings(keys, forwardingConfKeys) {
		return nil, ErrForwarding
	}
	values := map[string]int32{}
	for _, key := range keys {
		v, e := forwardingProcValue(parent, key)
		if e != nil {
			return nil, e
		}
		values[key] = v
	}
	return values, validateForwardingConf(values)
}

func captureForwarding(ctx context.Context, t Target, tools map[string]*pinnedTool, interfaces []string, uplink string) (*forwardingPreservation, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	a, e := collectForwardingObservation(ctx, t, tools, interfaces, false)
	if e != nil {
		return nil, e
	}
	b, e := collectForwardingObservation(ctx, t, tools, interfaces, false)
	if e != nil || !exactForwarding(a, b) {
		return nil, ErrForwarding
	}
	p, e := newForwardingPreservation(b, uplink)
	if e != nil {
		return nil, e
	}
	source, e := openForwardingSource(p)
	if e != nil {
		p.close()
		return nil, e
	}
	p.source = source
	check, e := collectForwardingObservation(ctx, t, tools, interfaces, false)
	if e != nil || !exactForwarding(b, check) || source.check() != nil {
		p.close()
		return nil, ErrForwarding
	}
	return p, nil
}

type forwardingNative struct {
	runner *nativeRunner
	p      *forwardingPreservation
	guard  func(context.Context) error
}

func (b forwardingNative) Observe(ctx context.Context) (forwardingObservation, error) {
	if b.p.source == nil || b.p.source.check() != nil {
		return forwardingObservation{}, ErrForwarding
	}
	names := []string{netguard.HostVeth}
	for name := range b.p.before.links {
		names = append(names, name)
	}
	o, e := collectForwardingObservation(ctx, b.runner.target, b.runner.tools, names, true)
	if e != nil || b.p.source.check() != nil {
		return forwardingObservation{}, ErrForwarding
	}
	return o, nil
}
func (b forwardingNative) Guard(ctx context.Context) error { return b.guard(ctx) }
func (b forwardingNative) Write(ctx context.Context, w forwardingWrite) error {
	r := b.runner
	if ctx.Err() != nil || scopeCheck(r.target) != nil || r.tools["sysctl"].check() != nil {
		return ErrForwarding
	}
	// No value outside the closed memory-derived write sequence is accepted.
	valid := w.interfaceName == "" && w.key == "ip_forward" && w.value == 1 || w.interfaceName == "all" && w.key == "accept_redirects" && w.value == b.p.before.conf["all"]["accept_redirects"] || w.interfaceName == "default" && w.key == "forwarding" && w.value == b.p.before.conf["default"]["forwarding"]
	if b.p.before.links[w.interfaceName] != 0 && w.interfaceName != b.p.uplink && w.key == "forwarding" && w.value == b.p.before.conf[w.interfaceName]["forwarding"] {
		valid = true
	}
	if !valid {
		return ErrForwarding
	}
	if b.p.source == nil || b.p.source.write(ctx, r.target, w) != nil || ctx.Err() != nil || scopeCheck(r.target) != nil || r.tools["sysctl"].check() != nil {
		return ErrForwarding
	}
	return nil
}

func (p *forwardingPreservation) enable(ctx context.Context, r *nativeRunner, guard func(context.Context) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if guard == nil || r == nil || p == nil || p.source == nil || r.target.Scope != p.before.scope || r.inputs.Uplink != p.uplink {
		return ErrForwarding
	}
	return p.preserve(ctx, forwardingNative{r, p, guard})
}

// Read-only restart comparison. The expected digest cannot supply restoration
// values, bypass the kernel guard or grant core/profile readiness.
func verifyForwardingExpected(ctx context.Context, t Target, tools map[string]*pinnedTool, interfaces []string, expectedSHA256 string) error {
	if !digestValid(expectedSHA256) {
		return ErrForwarding
	}
	a, e := collectForwardingObservation(ctx, t, tools, interfaces, true)
	if e != nil || a.global != 1 || forwardingFingerprint(a) != expectedSHA256 || a.links[netguard.HostVeth] == 0 {
		return ErrForwarding
	}
	owned := a.conf[netguard.HostVeth]
	if owned["forwarding"] != 1 || owned["rp_filter"] != 1 || owned["accept_redirects"] != 0 || owned["send_redirects"] != 0 || owned["route_localnet"] != 0 {
		return ErrForwarding
	}
	b, e := collectForwardingObservation(ctx, t, tools, interfaces, true)
	if e != nil || !exactForwarding(a, b) {
		return ErrForwarding
	}
	return nil
}
