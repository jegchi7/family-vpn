//go:build linux

package foreignsetup

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func parentForTest(t *testing.T) (int, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("protected staging ownership requires Linux root")
	}
	p := t.TempDir()
	if os.Chmod(p, 0700) != nil {
		t.Fatal("test directory permission")
	}
	fd, e := unix.Open(p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal("test descriptor")
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd, p
}

func TestPrivateStageAtomicCheckAndPreserve(t *testing.T) {
	fd, p := parentForTest(t)
	s, e := stageAt(context.Background(), fd, inputs())
	if e != nil || !s.ConfigurationValidated || s.Ready || s.RuntimeInstalled {
		t.Fatal("private stage creation")
	}
	checked, e := checkAt(context.Background(), fd, false)
	if e != nil || !checked.ConfigurationValidated || checked.NativeSyntaxValidated || checked.Ready {
		t.Fatal("private stage positive readback", e)
	}
	before, _ := os.ReadFile(filepath.Join(p, "foreign-staging", "xray.json"))
	defer clear(before)
	if _, e := stageAt(context.Background(), fd, inputs()); !errors.Is(e, ErrStage) {
		t.Fatal("existing stage overwritten")
	}
	after, _ := os.ReadFile(filepath.Join(p, "foreign-staging", "xray.json"))
	defer clear(after)
	if string(before) != string(after) {
		t.Fatal("existing private bytes changed")
	}
	entries, _ := os.ReadDir(p)
	if len(entries) != 1 || entries[0].Name() != "foreign-staging" {
		t.Fatal("partial staging left behind")
	}
	st, _ := os.Stat(filepath.Join(p, "foreign-staging"))
	if st.Mode().Perm() != 0700 {
		t.Fatal("stage directory broad permissions")
	}
	for _, name := range []string{"xray.json", "ru-hop.json"} {
		st, _ := os.Stat(filepath.Join(p, "foreign-staging", name))
		if st.Mode().Perm() != 0600 {
			t.Fatal("stage file broad permissions")
		}
	}
}

func TestPrivateStageRejectsAliasesPermissionsAndExtras(t *testing.T) {
	for _, kind := range []string{"symlink_dir", "symlink_file", "hardlink", "world_file", "world_dir", "fifo", "extra", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			fd, p := parentForTest(t)
			if _, e := stageAt(context.Background(), fd, inputs()); e != nil {
				t.Fatal("stage setup")
			}
			d := filepath.Join(p, "foreign-staging")
			x := filepath.Join(d, "xray.json")
			switch kind {
			case "symlink_dir":
				if os.Rename(d, filepath.Join(p, "original")) != nil || os.Symlink(filepath.Join(p, "original"), d) != nil {
					t.Fatal("directory alias setup")
				}
			case "symlink_file":
				if os.Rename(x, filepath.Join(p, "original.json")) != nil || os.Symlink(filepath.Join(p, "original.json"), x) != nil {
					t.Fatal("file alias setup")
				}
			case "hardlink":
				if os.Link(x, filepath.Join(p, "copy.json")) != nil {
					t.Fatal("hardlink setup")
				}
			case "world_file":
				os.Chmod(x, 0644)
			case "world_dir":
				os.Chmod(d, 0755)
			case "fifo":
				os.Remove(x)
				if unix.Mkfifo(x, 0600) != nil {
					t.Fatal("special file setup")
				}
			case "extra":
				os.WriteFile(filepath.Join(d, "unrequested.json"), []byte(`{}`), 0600)
			case "malformed":
				os.WriteFile(x, []byte(`{"secret":"sensitive-input-marker"}`), 0600)
			}
			s, e := checkAt(context.Background(), fd, false)
			if e == nil || s.ConfigurationValidated || s.NativeSyntaxValidated || s.Ready {
				t.Fatal("unsafe private stage accepted")
			}
			if e.Error() != ErrStage.Error() && e.Error() != ErrConfig.Error() {
				t.Fatal("private stage detail leaked")
			}
		})
	}
}

func TestStageCancelledAndInvalidHaveNoPartialFiles(t *testing.T) {
	fd, p := parentForTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := stageAt(ctx, fd, inputs()); e == nil {
		t.Fatal("cancelled stage")
	}
	i := inputs()
	i.RUSource = "127.0.0.1"
	if _, e := stageAt(context.Background(), fd, i); !errors.Is(e, ErrInput) {
		t.Fatal("invalid stage input")
	}
	entries, _ := os.ReadDir(p)
	if len(entries) != 0 {
		t.Fatal("partial stage after failure")
	}
}

func TestPrivateStageFailsForUnprivilegedCLI(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged CLI check requires non-root UID")
	}
	if s, e := Stage(context.Background(), inputs()); !errors.Is(e, ErrPlatform) || s.ConfigurationValidated || s.Ready {
		t.Fatal("unprivileged stage accepted")
	}
	if s, e := Check(context.Background(), false); !errors.Is(e, ErrPlatform) || s.ConfigurationValidated || s.Ready {
		t.Fatal("unprivileged stage read accepted")
	}
}
