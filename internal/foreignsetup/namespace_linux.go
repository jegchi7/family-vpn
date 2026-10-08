//go:build linux

package foreignsetup

import (
	"context"
	"golang.org/x/sys/unix"
	"io"
	"net/netip"
	"os"
)

// ReadNamespaceIPv4Config reads only the fixed protected original stage and
// returns private bytes to the trusted network stager. Never serialize these
// bytes into a report/log/HTTP response. No namespace, tool or network calls.
func ReadNamespaceIPv4Config(ctx context.Context) ([]byte, IPv4Binding, error) {
	fail := func(e error) ([]byte, IPv4Binding, error) { return nil, IPv4Binding{}, e }
	if os.Geteuid() != 0 {
		return fail(ErrPlatform)
	}
	c, e := base(false)
	if e != nil {
		return fail(ErrStage)
	}
	defer c.close()
	parent := c[len(c)-1].fd
	d, e := dirAt(parent, "foreign-staging", true)
	if e != nil {
		return fail(ErrStage)
	}
	defer unix.Close(d.fd)
	x, e := readAt(d.fd, "xray.json")
	if e != nil {
		return fail(ErrStage)
	}
	defer x.close()
	h, e := readAt(d.fd, "ru-hop.json")
	if e != nil {
		return fail(ErrStage)
	}
	defer h.close()
	dup, e := unix.FcntlInt(uintptr(d.fd), unix.F_DUPFD_CLOEXEC, 0)
	if e != nil {
		return fail(ErrStage)
	}
	f := os.NewFile(uintptr(dup), "Foreign original private stage")
	names, e := f.Readdirnames(3)
	more, end := f.Readdirnames(1)
	f.Close()
	if e != nil && e != io.EOF || end != io.EOF || len(more) != 0 || len(names) != 2 || !(names[0] == "xray.json" && names[1] == "ru-hop.json" || names[1] == "xray.json" && names[0] == "ru-hop.json") {
		return fail(ErrStage)
	}
	config, e := NamespaceIPv4Config(x.data, h.data)
	if e != nil {
		return fail(ErrConfig)
	}
	var original xrayConfig
	if decode(x.data, &original) != nil {
		clear(config)
		return fail(ErrConfig)
	}
	r, e := netip.ParsePrefix(original.Routing.Rules[1].Source[0])
	foreign, he := ValidateRUHop(h.data)
	if e != nil || he != nil || !r.Addr().Is4() || r.Bits() != 32 {
		clear(config)
		return fail(ErrConfig)
	}
	var st unix.Stat_t
	if ctx.Err() != nil || c.check() != nil || x.check(d.fd) != nil || h.check(d.fd) != nil || unix.Fstat(d.fd, &st) != nil || !same(d.stat, st) || unix.Fstatat(parent, "foreign-staging", &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(d.stat, st) {
		clear(config)
		return fail(ErrStage)
	}
	return config, IPv4Binding{RUIPv4: r.Addr().String(), ForeignIPv4: foreign}, nil
}
