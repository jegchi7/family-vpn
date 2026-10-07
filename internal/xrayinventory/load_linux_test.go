//go:build linux

package xrayinventory

import (
	"bytes"
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func tree(t *testing.T) (string, int, []byte) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned descriptor fixture requires local root; native inventory acceptance separate")
	}
	d := t.TempDir()
	os.Chmod(d, 0700)
	os.Mkdir(filepath.Join(d, "etc"), 0755)
	os.Mkdir(filepath.Join(d, "etc", "family-vpn"), 0755)
	b, _, _ := fixture(t)
	if e := os.WriteFile(filepath.Join(d, "etc", "family-vpn", "xray-inventory.json"), b, 0644); e != nil {
		t.Fatal(e)
	}
	fd, e := unix.Open(d, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return d, fd, b
}

var parts = []string{"etc", "family-vpn", "xray-inventory.json"}

func TestProtectedDescriptorsRejectLinksPermissionsOwnersAndSpecialFiles(t *testing.T) {
	for _, kind := range []string{"valid", "directory_write", "file_write", "file_execute", "symlink_file", "symlink_parent", "hardlink", "directory_file", "fifo", "oversize", "empty"} {
		t.Run(kind, func(t *testing.T) {
			d, fd, want := tree(t)
			p := filepath.Join(d, "etc", "family-vpn", "xray-inventory.json")
			parent := filepath.Dir(p)
			switch kind {
			case "directory_write":
				os.Chmod(parent, 0777)
			case "file_write":
				os.Chmod(p, 0666)
			case "file_execute":
				os.Chmod(p, 0755)
			case "symlink_file":
				os.Rename(p, p+".original")
				os.Symlink(p+".original", p)
			case "symlink_parent":
				os.Rename(parent, parent+".original")
				os.Symlink(parent+".original", parent)
			case "hardlink":
				os.Link(p, p+".alias")
			case "directory_file":
				os.Remove(p)
				os.Mkdir(p, 0755)
			case "fifo":
				os.Remove(p)
				if e := unix.Mkfifo(p, 0600); e != nil {
					t.Fatal(e)
				}
			case "oversize":
				os.WriteFile(p, bytes.Repeat([]byte(" "), MaxSize+1), 0644)
			case "empty":
				os.WriteFile(p, nil, 0644)
			}
			b, e := readAt(context.Background(), fd, parts)
			if kind == "valid" {
				if e != nil || !bytes.Equal(b, want) {
					t.Fatal("protected read failed", e)
				}
				clear(b)
			} else if !errors.Is(e, ErrInventory) || b != nil {
				t.Fatal("unsafe file accepted", e)
			}
		})
	}
}

func TestReadRejectsReplacementMutationCancellationAndClearsBytes(t *testing.T) {
	for _, kind := range []string{"replace", "mode", "content", "directory_mode", "cancel", "read_error"} {
		t.Run(kind, func(t *testing.T) {
			d, fd, _ := tree(t)
			p := filepath.Join(d, "etc", "family-vpn", "xray-inventory.json")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var raw []byte
			b, e := readAtUsing(ctx, fd, parts, func(f *os.File) ([]byte, error) {
				raw, _ = io.ReadAll(io.LimitReader(f, MaxSize+1))
				switch kind {
				case "replace":
					os.Rename(p, p+".old")
					os.WriteFile(p, bytes.Clone(raw), 0644)
				case "mode":
					os.Chmod(p, 0666)
				case "content":
					os.WriteFile(p, append(bytes.Clone(raw), '\n'), 0644)
				case "directory_mode":
					os.Chmod(filepath.Dir(p), 0777)
				case "cancel":
					cancel()
				case "read_error":
					return raw, errors.New("private-inventory-error")
				}
				return raw, nil
			})
			if b != nil || !errors.Is(e, ErrInventory) || !bytes.Equal(raw, make([]byte, len(raw))) {
				t.Fatal("changed file accepted or raw retained", e)
			}
		})
	}
	_, fd, _ := tree(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if b, e := readAtUsing(ctx, fd, parts, func(*os.File) ([]byte, error) { t.Fatal("read after cancel"); return nil, nil }); b != nil || !errors.Is(e, ErrInventory) {
		t.Fatal("cancel bypass", e)
	}
}

// Unmapped foreign UIDs cannot be installed by chown in the current sandbox.
// Exercise the ownership policy directly, without claiming filesystem acceptance.
func TestRejectForeignOwnerMetadata(t *testing.T) {
	for _, directory := range []bool{true, false} {
		mode := uint32(unix.S_IFREG | 0644)
		if directory {
			mode = unix.S_IFDIR | 0755
		}
		stat := unix.Stat_t{Mode: mode, Uid: 0, Nlink: 1, Size: 1}
		if !protected(stat, directory) {
			t.Fatal("control metadata rejected")
		}
		for _, uid := range []uint32{1, 65534} {
			stat.Uid = uid
			if protected(stat, directory) {
				t.Fatal("foreign owner accepted")
			}
		}
	}
}
