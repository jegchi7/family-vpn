//go:build linux

package netstand

import (
	"context"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

type forwardingHeldValue struct {
	parent item
	file   *os.File
	stat   unix.Stat_t
	name   string
}
type forwardingSource struct {
	chain    forwardingProcChain
	conf     item
	values   map[string]forwardingHeldValue
	expected map[string]int32
}

func (s *forwardingSource) close() {
	for _, value := range s.values {
		value.file.Close()
		unix.Close(value.parent.fd)
	}
	if s.conf.fd >= 0 {
		unix.Close(s.conf.fd)
	}
	s.chain.close()
	s.values = nil
	s.expected = nil
	s.chain = nil
	s.conf.fd = -1
}

func (s *forwardingSource) check() error {
	if s == nil || len(s.chain) == 0 || len(s.values) == 0 || s.chain.check() != nil {
		return ErrForwarding
	}
	var st unix.Stat_t
	if unix.Fstat(s.conf.fd, &st) != nil || !forwardingProcDirIdentity(s.conf.stat, st) || unix.Fstatat(s.chain[len(s.chain)-1].fd, "conf", &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !forwardingProcDirIdentity(s.conf.stat, st) {
		return ErrForwarding
	}
	for key, value := range s.values {
		if unix.Fstat(value.parent.fd, &st) != nil || !forwardingProcDirIdentity(value.parent.stat, st) || unix.Fstat(int(value.file.Fd()), &st) != nil || !forwardingProcIdentity(value.stat, st) || !forwardingProcFile(int(value.file.Fd()), st) || unix.Fstatat(value.parent.fd, value.name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !forwardingProcIdentity(value.stat, st) {
			return ErrForwarding
		}
		if key != "ip_forward" && (unix.Fstatat(s.conf.fd, value.parent.name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !forwardingProcDirIdentity(value.parent.stat, st)) {
			return ErrForwarding
		}
	}
	return nil
}

func openForwardingHeldValue(parent item, key string) (forwardingHeldValue, error) {
	var before, after unix.Stat_t
	if unix.Fstatat(parent.fd, key, &before, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return forwardingHeldValue{}, ErrForwarding
	}
	fd, e := unix.Openat(parent.fd, key, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if e != nil {
		return forwardingHeldValue{}, ErrForwarding
	}
	f := os.NewFile(uintptr(fd), "held-kernel-forwarding-value")
	if unix.Fstat(fd, &after) != nil || !forwardingProcIdentity(before, after) || !forwardingProcFile(fd, after) {
		f.Close()
		return forwardingHeldValue{}, ErrForwarding
	}
	return forwardingHeldValue{parent, f, before, key}, nil
}

func openForwardingSource(p *forwardingPreservation) (*forwardingSource, error) {
	c, e := forwardingDirectories([]string{"proc", "sys", "net", "ipv4"})
	if e != nil {
		return nil, ErrForwarding
	}
	s := &forwardingSource{chain: c, conf: item{fd: -1}, values: map[string]forwardingHeldValue{}, expected: map[string]int32{"ip_forward": 1, "all/accept_redirects": p.before.conf["all"]["accept_redirects"], "default/forwarding": p.before.conf["default"]["forwarding"]}}
	fail := func() (*forwardingSource, error) { s.close(); return nil, ErrForwarding }
	parent := c[len(c)-1]
	if s.conf, e = forwardingDirectoryAt(parent.fd, "conf"); e != nil {
		return fail()
	}
	dup, e := unix.Dup(parent.fd)
	if e != nil {
		return fail()
	}
	unix.CloseOnExec(dup)
	ip := parent
	ip.fd = dup
	value, e := openForwardingHeldValue(ip, "ip_forward")
	if e != nil {
		unix.Close(dup)
		return fail()
	}
	s.values["ip_forward"] = value
	for name, key := range map[string]string{"all": "accept_redirects", "default": "forwarding"} {
		iface, e := forwardingDirectoryAt(s.conf.fd, name)
		if e != nil {
			return fail()
		}
		value, e := openForwardingHeldValue(iface, key)
		if e != nil {
			unix.Close(iface.fd)
			return fail()
		}
		s.values[name+"/"+key] = value
	}
	for name := range p.before.links {
		iface, e := forwardingDirectoryAt(s.conf.fd, name)
		if e != nil {
			return fail()
		}
		value, e := openForwardingHeldValue(iface, "forwarding")
		if e != nil {
			unix.Close(iface.fd)
			return fail()
		}
		s.values[name+"/forwarding"] = value
		if name != p.uplink {
			s.expected[name+"/forwarding"] = p.before.conf[name]["forwarding"]
		}
	}
	if s.check() != nil {
		return fail()
	}
	return s, nil
}

func (s *forwardingSource) write(ctx context.Context, t Target, w forwardingWrite) error {
	key := w.key
	if w.interfaceName != "" {
		key = w.interfaceName + "/" + w.key
	}
	value, exists := s.values[key]
	want, permitted := s.expected[key]
	if !exists || !permitted || want != w.value || s.check() != nil || ctx.Err() != nil || scopeCheck(t) != nil || w.value != 0 && w.value != 1 {
		return ErrForwarding
	}
	data := []byte(strconv.FormatInt(int64(w.value), 10) + "\n")
	if _, e := value.file.Seek(0, 0); e != nil {
		return ErrForwarding
	}
	if n, e := value.file.Write(data); e != nil || n != len(data) || s.check() != nil || ctx.Err() != nil || scopeCheck(t) != nil {
		return ErrForwarding
	}
	return nil
}
