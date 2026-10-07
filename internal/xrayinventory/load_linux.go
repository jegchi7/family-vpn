//go:build linux

package xrayinventory

import (
	"context"
	"golang.org/x/sys/unix"
	"io"
	"os"
)

func protected(s unix.Stat_t, directory bool) bool {
	if s.Uid != 0 || s.Mode&(0022|07000) != 0 {
		return false
	}
	if directory {
		return s.Mode&unix.S_IFMT == unix.S_IFDIR
	}
	return s.Mode&unix.S_IFMT == unix.S_IFREG && s.Mode&0111 == 0 && s.Nlink == 1 && s.Size > 0 && s.Size <= MaxSize
}
func unchanged(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

type opened struct {
	fd   int
	name string
	stat unix.Stat_t
}

// readAt is private so production cannot accept a caller-supplied file path.
// Every component is opened relative to a checked directory descriptor.
func readAt(ctx context.Context, root int, parts []string) ([]byte, error) {
	return readAtUsing(ctx, root, parts, func(f *os.File) ([]byte, error) { return io.ReadAll(io.LimitReader(f, MaxSize+1)) })
}
func readAtUsing(ctx context.Context, root int, parts []string, read func(*os.File) ([]byte, error)) ([]byte, error) {
	if ctx.Err() != nil || len(parts) == 0 {
		return nil, ErrInventory
	}
	var initial unix.Stat_t
	if unix.Fstat(root, &initial) != nil || !protected(initial, true) {
		return nil, ErrInventory
	}
	chain := []opened{{fd: root, stat: initial}}
	defer func() {
		for _, v := range chain[1:] {
			unix.Close(v.fd)
		}
	}()
	for n, name := range parts {
		if ctx.Err() != nil {
			return nil, ErrInventory
		}
		directory := n != len(parts)-1
		var before unix.Stat_t
		parent := chain[len(chain)-1].fd
		if unix.Fstatat(parent, name, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !protected(before, directory) {
			return nil, ErrInventory
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY
		if directory {
			flags |= unix.O_DIRECTORY
		}
		fd, e := unix.Openat(parent, name, flags, 0)
		if e != nil {
			return nil, ErrInventory
		}
		var actual unix.Stat_t
		if unix.Fstat(fd, &actual) != nil || !protected(actual, directory) || !unchanged(before, actual) {
			unix.Close(fd)
			return nil, ErrInventory
		}
		chain = append(chain, opened{fd, name, actual})
	}
	last := chain[len(chain)-1]
	// Duplicate for os.File ownership; all chain descriptors remain available
	// for post-read checks. Dup's close-on-exec flag is set atomically.
	dup, e := unix.FcntlInt(uintptr(last.fd), unix.F_DUPFD_CLOEXEC, 0)
	if e != nil {
		return nil, ErrInventory
	}
	f := os.NewFile(uintptr(dup), "protected Xray inventory")
	defer f.Close()
	b, e := read(f)
	fail := func() ([]byte, error) { clear(b); return nil, ErrInventory }
	if e != nil || ctx.Err() != nil || int64(len(b)) != last.stat.Size || len(b) > MaxSize {
		return fail()
	}
	for n, v := range chain {
		var actual unix.Stat_t
		if unix.Fstat(v.fd, &actual) != nil || !unchanged(v.stat, actual) {
			return fail()
		}
		if n > 0 {
			if unix.Fstatat(chain[n-1].fd, v.name, &actual, unix.AT_SYMLINK_NOFOLLOW) != nil || !unchanged(v.stat, actual) {
				return fail()
			}
		}
	}
	return b, nil
}

func Require(ctx context.Context, pin string, expected Expected) error {
	if ctx.Err() != nil || !ValidPin(pin) || !expected.Valid() {
		return ErrInventory
	}
	root, e := unix.Open("/", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if e != nil {
		return ErrInventory
	}
	defer unix.Close(root)
	b, e := readAt(ctx, root, []string{"etc", "family-vpn", "xray-inventory.json"})
	if e != nil {
		return ErrInventory
	}
	defer clear(b)
	i, e := parse(b)
	if e != nil || ctx.Err() != nil {
		return ErrInventory
	}
	return i.check(pin, expected)
}
