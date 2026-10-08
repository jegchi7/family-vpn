//go:build linux

package coreinstall

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

func CanApply() bool { return os.Geteuid() == 0 }

func protectedDirectory(fd int) bool {
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && st.Uid == 0 && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&0022 == 0
}

func openParent() (int, error) {
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, ErrProtected
	}
	for _, name := range []string{"usr", "bin"} {
		if !protectedDirectory(fd) {
			unix.Close(fd)
			return -1, ErrProtected
		}
		next, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return -1, ErrProtected
		}
		fd = next
	}
	if !protectedDirectory(fd) {
		unix.Close(fd)
		return -1, ErrProtected
	}
	return fd, nil
}

func regularPinned(st *unix.Stat_t, a Artifact) bool {
	return st.Uid == 0 && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0755 && st.Nlink == 1 && st.Size == a.BinarySize
}

func sameStat(a, b *unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func verifyAt(parent int, a Artifact) error {
	fd, e := unix.Openat(parent, filepath.Base(a.Destination), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(e, unix.ENOENT) {
		return ErrUnavailable
	}
	if e != nil {
		return ErrConflict
	}
	f := os.NewFile(uintptr(fd), "pinned-core")
	defer f.Close()
	return verifyFile(f, a)
}

func verifyFile(f *os.File, a Artifact) error {
	var before, after unix.Stat_t
	if unix.Fstat(int(f.Fd()), &before) != nil || !regularPinned(&before, a) {
		return ErrConflict
	}
	if verifyELF(a, f) != nil {
		return ErrIntegrity
	}
	if _, e := f.Seek(0, io.SeekStart); e != nil {
		return ErrIntegrity
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, a.BinarySize+1))
	if e != nil || n != a.BinarySize || hex.EncodeToString(h.Sum(nil)) != a.BinarySHA256 {
		return ErrIntegrity
	}
	if unix.Fstat(int(f.Fd()), &after) != nil || !sameStat(&before, &after) {
		return ErrIntegrity
	}
	return nil
}

// VerifyInstalled reads the fixed root-owned regular file without execution.
func VerifyInstalled(core string) (Artifact, error) {
	a, e := Lookup(core, runtime.GOARCH)
	if e != nil {
		return Artifact{}, e
	}
	p, e := openParent()
	if e != nil {
		return Artifact{}, e
	}
	defer unix.Close(p)
	if e = verifyAt(p, a); e != nil {
		return Artifact{}, e
	}
	return a, nil
}

func temporary(parent int) (*os.File, string, error) {
	var entropy [16]byte
	if _, e := rand.Read(entropy[:]); e != nil {
		return nil, "", ErrProtected
	}
	name := ".family-vpn-core-" + hex.EncodeToString(entropy[:])
	fd, e := unix.Openat(parent, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return nil, "", ErrProtected
	}
	return os.NewFile(uintptr(fd), "private-core-stage"), name, nil
}

// publish never replaces a destination, including after a concurrent install.
func publish(parent int, name string, f *os.File, a Artifact) (bool, error) {
	if f.Chmod(0755) != nil || f.Sync() != nil || verifyFile(f, a) != nil {
		return false, ErrIntegrity
	}
	if e := unix.Renameat2(parent, name, parent, filepath.Base(a.Destination), unix.RENAME_NOREPLACE); e != nil {
		if errors.Is(e, unix.EEXIST) && verifyAt(parent, a) == nil {
			return false, nil
		}
		return false, ErrConflict
	}
	if unix.Fsync(parent) != nil {
		return true, ErrProtected
	}
	return true, nil
}

// Install is root-only and installs one binary. It never executes a core,
// creates a service/configuration or changes network settings.
func Install(ctx context.Context, core string) (Artifact, bool, error) {
	if !CanApply() {
		return Artifact{}, false, ErrPlatform
	}
	a, e := Lookup(core, runtime.GOARCH)
	if e != nil {
		return Artifact{}, false, e
	}
	p, e := openParent()
	if e != nil {
		return Artifact{}, false, e
	}
	defer unix.Close(p)
	e = verifyAt(p, a)
	if e == nil {
		return a, false, nil
	}
	if !errors.Is(e, ErrUnavailable) {
		return Artifact{}, false, ErrConflict
	}
	if ctx.Err() != nil {
		return Artifact{}, false, ErrDownload
	}
	archive, an, e := temporary(p)
	if e != nil {
		return Artifact{}, false, e
	}
	defer archive.Close()
	defer unix.Unlinkat(p, an, 0)
	client := downloadClient()
	defer client.CloseIdleConnections()
	if e = download(ctx, a, archive, client); e != nil {
		return Artifact{}, false, e
	}
	if _, e = archive.Seek(0, io.SeekStart); e != nil {
		return Artifact{}, false, ErrIntegrity
	}
	stage, sn, e := temporary(p)
	if e != nil {
		return Artifact{}, false, e
	}
	defer stage.Close()
	defer unix.Unlinkat(p, sn, 0)
	if e = extract(a, archive, stage); e != nil {
		return Artifact{}, false, e
	}
	if ctx.Err() != nil {
		return Artifact{}, false, ErrDownload
	}
	changed, e := publish(p, sn, stage, a)
	if e != nil {
		return a, changed, e
	}
	return a, changed, nil
}
