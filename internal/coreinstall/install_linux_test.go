//go:build linux

package coreinstall

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxProtectedDirectoryAndNoFollow(t *testing.T) {
	root := t.TempDir()
	fd, e := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	if protectedDirectory(fd) != (os.Geteuid() == 0) {
		t.Fatal("directory ownership")
	}
	if os.Chmod(root, 0777) != nil {
		t.Fatal("chmod")
	}
	if protectedDirectory(fd) {
		t.Fatal("writable directory trusted")
	}
	if _, _, e := Install(context.Background(), "invalid-core"); e == nil {
		t.Fatal("invalid selection accepted")
	}
}

func TestLinuxPinnedFileBoundary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership positive boundary requires Linux root")
	}
	root := t.TempDir()
	fd, e := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	b := syntheticELF("amd64")
	a := testArtifact("raw", b)
	name := filepath.Join(root, "synthetic")
	if os.WriteFile(name, b, 0755) != nil {
		t.Fatal("write")
	}
	if e = verifyAt(fd, a); e != nil {
		t.Fatal(e)
	}
	if os.Chmod(name, 0744) != nil {
		t.Fatal("chmod")
	}
	if verifyAt(fd, a) == nil {
		t.Fatal("mode trusted")
	}
	os.Chmod(name, 0755)
	link := filepath.Join(root, "linked")
	if os.Link(name, link) != nil {
		t.Fatal("link")
	}
	if verifyAt(fd, a) == nil {
		t.Fatal("hardlink trusted")
	}
	os.Remove(link)
	if os.Chown(name, 65534, 65534) != nil {
		t.Fatal("chown")
	}
	if verifyAt(fd, a) == nil {
		t.Fatal("non-root owner trusted")
	}
	os.Chown(name, 0, 0)
	os.Remove(name)
	if os.Symlink("missing", name) != nil {
		t.Fatal("symlink")
	}
	if verifyAt(fd, a) == nil {
		t.Fatal("symlink trusted")
	}
	os.Remove(name)
	if unix.Mkfifo(name, 0755) != nil {
		t.Fatal("fifo")
	}
	if verifyAt(fd, a) == nil {
		t.Fatal("fifo trusted")
	}
	os.Remove(name)
	if e = verifyAt(fd, a); !errors.Is(e, ErrUnavailable) {
		t.Fatal("missing file result")
	}
}

func TestLinuxAtomicPublicationAndConcurrentSamePin(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership publication boundary requires Linux root")
	}
	root := t.TempDir()
	fd, e := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	b := syntheticELF("amd64")
	a := testArtifact("raw", b)
	makeStage := func() (*os.File, string) {
		f, n, e := temporary(fd)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { f.Close(); unix.Unlinkat(fd, n, 0) })
		if _, e = f.Write(b); e != nil {
			t.Fatal(e)
		}
		return f, n
	}
	f, n := makeStage()
	changed, e := publish(fd, n, f, a)
	if e != nil || !changed {
		t.Fatal("first publication")
	}
	if e = verifyAt(fd, a); e != nil {
		t.Fatal(e)
	}
	f, n = makeStage()
	changed, e = publish(fd, n, f, a)
	if e != nil || changed {
		t.Fatal("same-pin race changed destination")
	}
	destination := filepath.Join(root, "synthetic")
	different := append([]byte{}, b...)
	different[len(different)-1] = 7
	if os.WriteFile(destination, different, 0755) != nil {
		t.Fatal("write conflicting private test file")
	}
	f, n = makeStage()
	changed, e = publish(fd, n, f, a)
	if !errors.Is(e, ErrConflict) || changed {
		t.Fatal("conflicting destination replaced")
	}
	after, e := os.ReadFile(destination)
	if e != nil || !bytes.Equal(after, different) {
		t.Fatal("conflict bytes overwritten")
	}
}
