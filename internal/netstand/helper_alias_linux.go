//go:build linux

package netstand

import (
	"golang.org/x/sys/unix"
	"os"
	"runtime"
)

type toolAlias struct {
	dirs         directoryChain
	name, target string
	stat         unix.Stat_t
}

func (a toolAlias) check() error {
	var st unix.Stat_t
	var b [64]byte
	if a.dirs.check() != nil || unix.Fstatat(a.dirs[len(a.dirs)-1].fd, a.name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(a.stat, st) {
		return ErrProtected
	}
	n, e := unix.Readlinkat(a.dirs[len(a.dirs)-1].fd, a.name, b[:])
	if e != nil || n == len(b) || string(b[:n]) != a.target {
		return ErrProtected
	}
	return nil
}
func helperELF(f *os.File) error {
	var b [64]byte
	if n, e := f.ReadAt(b[:], 0); e != nil || n != len(b) || string(b[:4]) != "\x7fELF" || b[4] != 2 || b[5] != 1 {
		return ErrProtected
	}
	machine := uint16(b[18]) | uint16(b[19])<<8
	if runtime.GOARCH == "amd64" && machine != 62 || runtime.GOARCH == "arm64" && machine != 183 || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return ErrProtected
	}
	kind := uint16(b[16]) | uint16(b[17])<<8
	if kind != 2 && kind != 3 {
		return ErrProtected
	}
	return nil
}

// Ubuntu20 iproute2 installs /sbin/ip -> /bin/ip. Only this closed, package
// layout alias (or its canonical usr-merged spelling) is accepted. Every alias
// and physical descriptor remains checked; no PATH lookup or custom path flag.
func openIPAlias(aliasDirs directoryChain, aliasStat unix.Stat_t, pin string) (*pinnedTool, error) {
	fail := func(extra []toolAlias) (*pinnedTool, error) {
		aliasDirs.close()
		for _, a := range extra {
			a.dirs.close()
		}
		return nil, ErrProtected
	}
	var b [64]byte
	n, e := unix.Readlinkat(aliasDirs[len(aliasDirs)-1].fd, "ip", b[:])
	if e != nil || n == len(b) {
		return fail(nil)
	}
	target := string(b[:n])
	if target != "/bin/ip" && target != "/usr/bin/ip" {
		return fail(nil)
	}
	extras := []toolAlias{}
	parts := []string{"usr", "bin"}
	if target == "/bin/ip" {
		root, e := directories(nil, false)
		if e != nil {
			return fail(nil)
		}
		var st unix.Stat_t
		if unix.Fstatat(root[0].fd, "bin", &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
			root.close()
			return fail(nil)
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			n, e := unix.Readlinkat(root[0].fd, "bin", b[:])
			if e != nil || n < 0 || n == len(b) {
				root.close()
				return fail(nil)
			}
			s := string(b[:n])
			if st.Uid != 0 || st.Nlink != 1 || (s != "usr/bin" && s != "/usr/bin") {
				root.close()
				return fail(nil)
			}
			extras = append(extras, toolAlias{root, "bin", s, st})
		} else {
			root.close()
			if !protectedDir(st, false) {
				return fail(nil)
			}
			parts = []string{"bin"}
		}
	}
	c, e := directories(parts, false)
	if e != nil {
		return fail(extras)
	}
	parent := c[len(c)-1].fd
	var before, after unix.Stat_t
	if unix.Fstatat(parent, "ip", &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !protectedFile(before, 0755, 64*1024*1024) {
		c.close()
		return fail(extras)
	}
	fd, e := unix.Openat(parent, "ip", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if e != nil {
		c.close()
		return fail(extras)
	}
	f := os.NewFile(uintptr(fd), "canonical-pinned-ip")
	if unix.Fstat(fd, &after) != nil || !same(before, after) || helperELF(f) != nil {
		f.Close()
		c.close()
		return fail(extras)
	}
	aliases := append([]toolAlias{{aliasDirs, "ip", target, aliasStat}}, extras...)
	t := &pinnedTool{file: f, path: "/usr/sbin/ip", name: "ip", stat: before, dirs: c, hash: pin, aliases: aliases}
	if t.check() != nil {
		t.close()
		return nil, ErrProtected
	}
	return t, nil
}
