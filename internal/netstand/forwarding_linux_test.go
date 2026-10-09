//go:build linux

package netstand

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Filesystem-only tests: ordinary files cannot impersonate kernel sysctls.
// These tests perform no namespace, route, firewall, sysctl or offload write.
func TestForwardingProcRejectsFilesAliasesAndWriteBeforeKernelIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "forwarding")
	if os.WriteFile(path, []byte("0\n"), 0600) != nil {
		t.Fatal("fixture")
	}
	fd, e := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	if _, e := forwardingProcValue(fd, "forwarding"); e == nil {
		t.Fatal("ordinary fixture accepted as proc source")
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		t.Fatal("fixture stat")
	}
	if _, e := openForwardingHeldValue(item{fd: fd, stat: st}, "forwarding"); e == nil {
		t.Fatal("ordinary fixture accepted as held proc write source")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "0\n" {
		t.Fatal("unverified source written")
	}
	if _, e := forwardingNamesAt(fd, 32); e == nil {
		t.Fatal("ordinary directory accepted as proc")
	}
	if os.Symlink("forwarding", filepath.Join(dir, "accept_redirects")) != nil {
		t.Fatal("fixture alias")
	}
	if _, e := forwardingProcValue(fd, "accept_redirects"); e == nil {
		t.Fatal("symlink proc source accepted")
	}
	if _, e := forwardingProcValue(fd, "../forwarding"); e == nil {
		t.Fatal("arbitrary key accepted")
	}
}

func TestForwardingReadOnlyUAPILayoutAndFeatureLimit(t *testing.T) {
	if unsafe.Sizeof(forwardingIfreq{}) != 40 || unsafe.Offsetof(forwardingIfreq{}.data) != 16 || unsafe.Offsetof(forwardingSSetInfo{}.count) != 16 || unsafe.Offsetof(forwardingStrings{}.data) != 12 || unsafe.Offsetof(forwardingFeatureWords{}.words) != 8 {
		t.Fatal("64-bit Linux UAPI layout changed")
	}
	if forwardingGSSetInfo != 0x37 || forwardingGStrings != 0x1b || forwardingGFeatures != 0x3a || forwardingFeatureSet != 4 || forwardingMaxFeatures != 256 {
		t.Fatal("closed read-only UAPI drift")
	}
}

func TestForwardingProcDirectoryVolatilityDoesNotChangeIdentity(t *testing.T) {
	a := unix.Stat_t{Dev: 1, Ino: 2, Uid: 0, Gid: 0, Mode: unix.S_IFDIR | 0555, Nlink: 3}
	b := a
	b.Nlink = 300
	b.Size = 99
	b.Mtim.Sec++
	b.Ctim.Sec++
	if !forwardingProcDirIdentity(a, b) || forwardingProcIdentity(a, b) {
		t.Fatal("directory volatility became identity, or file links ignored")
	}
	for _, mutate := range []func(*unix.Stat_t){
		func(s *unix.Stat_t) { s.Dev++ }, func(s *unix.Stat_t) { s.Ino++ },
		func(s *unix.Stat_t) { s.Uid++ }, func(s *unix.Stat_t) { s.Gid++ },
		func(s *unix.Stat_t) { s.Mode |= 0022 },
	} {
		b = a
		mutate(&b)
		if forwardingProcDirIdentity(a, b) {
			t.Fatal("directory identity or permission change accepted")
		}
	}
}
