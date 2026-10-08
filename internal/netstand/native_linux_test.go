//go:build linux

package netstand

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// These filesystem-only tests never execute ip/nft/sysctl/tc and never create
// a namespace, route, firewall object or VPN process.
func TestProtectedStagePublishesOnceAndRejectsAliases(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned private filesystem fixture requires Linux root")
	}
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("fixture mode")
	}
	fd, e := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	i, target, v, p := syntheticPlan(t)
	a, e := buildArtifacts(i, target, v, p)
	if e != nil {
		t.Fatal(e)
	}
	if stageAt(context.Background(), fd, a) != nil {
		t.Fatal("private stage rejected")
	}
	stage, e := directoryAt(fd, "network-staging", true)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(stage.fd)
	data, e := readProtected(stage.fd, "manifest.json")
	if e != nil || string(data) != string(a.Manifest) {
		t.Fatal("published bytes changed")
	}
	if stageAt(context.Background(), fd, a) == nil {
		t.Fatal("existing stage overwritten")
	}
	path := filepath.Join(dir, "network-staging", "host.nft")
	if os.Chmod(path, 0644) != nil {
		t.Fatal("fixture chmod")
	}
	if _, e := readProtected(stage.fd, "host.nft"); e == nil {
		t.Fatal("public artifact accepted")
	}
	if os.Chmod(path, 0600) != nil {
		t.Fatal("fixture restore")
	}
	if os.Link(path, filepath.Join(dir, "linked-artifact")) != nil {
		t.Fatal("fixture link")
	}
	if _, e := readProtected(stage.fd, "host.nft"); e == nil {
		t.Fatal("hardlinked artifact accepted")
	}
	if os.Symlink("manifest.json", filepath.Join(dir, "network-staging", "alias")) != nil {
		t.Fatal("fixture alias")
	}
	if _, e := readProtected(stage.fd, "alias"); e == nil {
		t.Fatal("symlink artifact accepted")
	}
}
func TestCancelledStagePublishesNothingAndRetainsExistingState(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned private filesystem fixture requires Linux root")
	}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	fd, e := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	i, target, v, p := syntheticPlan(t)
	a, _ := buildArtifacts(i, target, v, p)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if stageAt(ctx, fd, a) == nil {
		t.Fatal("cancelled publication succeeded")
	}
	files, e := os.ReadDir(dir)
	if e != nil || len(files) != 0 {
		t.Fatal("cancelled publication left artifacts")
	}
	if os.Symlink("elsewhere", filepath.Join(dir, "network-staging")) != nil {
		t.Fatal("fixture alias")
	}
	if stageAt(context.Background(), fd, a) == nil {
		t.Fatal("existing namespace alias overwritten")
	}
	if target, e := os.Readlink(filepath.Join(dir, "network-staging")); e != nil || target != "elsewhere" {
		t.Fatal("existing alias changed")
	}
}
