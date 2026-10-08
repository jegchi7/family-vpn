//go:build linux

package netstand

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// These touch only private temporary files. They never execute network tools,
// create namespaces, alter routes/firewalls, or certify native VPN acceptance.
func journalTestDir(t *testing.T) (string, int) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root ownership filesystem test requires Linux root")
	}
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private directory unavailable")
	}
	fd, e := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		t.Fatal("private directory unavailable")
	}
	t.Cleanup(func() { unix.Close(fd) })
	return dir, fd
}
func TestOperationPrivateFenceNoResume(t *testing.T) {
	_, fd := journalTestDir(t)
	binding := strings.Repeat("a", 64)
	op, e := beginOperation(fd, binding)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := beginOperation(fd, binding); e == nil {
		t.Fatal("concurrent writer accepted")
	}
	if validateJournal(fd) == nil {
		t.Fatal("in-progress exclusive writer read as inactive")
	}
	if op.record(1, "progress") != nil || op.record(1, "failed") != nil {
		t.Fatal("bounded failure fence unavailable")
	}
	op.close()
	if validateJournal(fd) != nil {
		t.Fatal("well formed failed fence rejected")
	}
	if readOperation(fd, binding, 1) == nil {
		t.Fatal("failure became replay authority")
	}
	if _, e := beginOperation(fd, binding); e == nil {
		t.Fatal("failed writer resumed")
	}
	_, fd = journalTestDir(t)
	op, e = beginOperation(fd, binding)
	if e != nil {
		t.Fatal(e)
	}
	defer op.close()
	if op.record(1, "progress") != nil || op.record(1, "complete") != nil {
		t.Fatal("completion fence unavailable")
	}
	op.close()
	if readOperation(fd, binding, 1) != nil {
		t.Fatal("matching complete fence rejected")
	}
	if readOperation(fd, binding, 2) == nil || readOperation(fd, strings.Repeat("b", 64), 1) == nil {
		t.Fatal("changed plan/count accepted")
	}
}
func TestOperationRejectsPrivateFileAliasesAndChanges(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "mode", "truncate", "replace"} {
		t.Run(kind, func(t *testing.T) {
			dir, fd := journalTestDir(t)
			binding := strings.Repeat("a", 64)
			op, e := beginOperation(fd, binding)
			if e != nil {
				t.Fatal(e)
			}
			op.close()
			name := filepath.Join(dir, journalName)
			switch kind {
			case "symlink":
				target := filepath.Join(dir, "original")
				if os.Rename(name, target) != nil || os.Symlink(target, name) != nil {
					t.Fatal("test alias unavailable")
				}
			case "hardlink":
				if os.Link(name, filepath.Join(dir, "alias")) != nil {
					t.Fatal("test alias unavailable")
				}
			case "mode":
				if os.Chmod(name, 0644) != nil {
					t.Fatal("test mutation unavailable")
				}
			case "truncate":
				if os.Truncate(name, 3) != nil {
					t.Fatal("test mutation unavailable")
				}
			case "replace":
				if os.Remove(name) != nil || os.WriteFile(name, []byte("{}\n"), 0600) != nil {
					t.Fatal("test mutation unavailable")
				}
			}
			if validateJournal(fd) == nil {
				t.Fatal("changed private fence accepted")
			}
		})
	}
	dir, fd := journalTestDir(t)
	op, e := beginOperation(fd, strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	defer op.close()
	if os.Chmod(filepath.Join(dir, journalName), 0644) != nil {
		t.Fatal("test mutation unavailable")
	}
	if op.record(1, "progress") == nil {
		t.Fatal("live changed metadata accepted")
	}
}
