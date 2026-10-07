package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

var ctx = context.Background()

func portalForTest(t *testing.T) (*PortalStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "portal", "state.db")
	p, e := OpenPortal(ctx, path, false)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { p.Close() })
	return p, path
}
func TestPersistentSeedAndOwnership(t *testing.T) {
	p, path := portalForTest(t)
	start := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	if e := p.SeedDemo(ctx, start); e != nil {
		t.Fatal(e)
	}
	if e := p.RenameDemo(ctx, "dev-other", "x", 1); !errors.Is(e, ErrNotFound) {
		t.Fatalf("foreign mutation: %v", e)
	}
	if e := p.RenameDemo(ctx, "dev-iphone", "Сохранённый телефон", 1); e != nil {
		t.Fatal(e)
	}
	if e := p.SeedDemo(ctx, start.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	p.Close()
	p, e := OpenPortal(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	devices, e := p.DevicesForOwner(ctx, "demo-family")
	if e != nil || len(devices) != 2 {
		t.Fatalf("%v %v", devices, e)
	}
	if devices[0].Name != "Сохранённый телефон" {
		t.Fatal("seed overwrote persisted edit")
	}
	if _, ok, e := p.ProfileForOwner(ctx, "demo-family", "p-other"); e != nil || ok {
		t.Fatal("ownership leak")
	}
	samples, e := p.HealthSamples(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if !samples[0].MeasuredAt.Equal(start) {
		t.Fatal("seed refreshed a stale measurement")
	}
	if samples[0].At(start.Add(time.Hour)).Status != "unknown" {
		t.Fatal("stale is not unknown")
	}
	if _, e = p.db.Exec("DELETE FROM devices"); e == nil {
		t.Fatal("read-only connection wrote")
	}
}
func TestMigrationHistoryAndIdentity(t *testing.T) {
	for _, test := range []string{"future", "checksum", "gap", "wrong-kind"} {
		t.Run(test, func(t *testing.T) {
			p, path := portalForTest(t)
			switch test {
			case "future":
				p.db.Exec("PRAGMA user_version=999")
			case "checksum":
				p.db.Exec("UPDATE schema_migrations SET checksum='wrong'")
			case "gap":
				p.db.Exec("DELETE FROM schema_migrations")
			case "wrong-kind":
			}
			p.Close()
			before, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			k := Portal
			if test == "wrong-kind" {
				k = Control
			}
			for _, readOnly := range []bool{false, true} {
				d, e := Open(ctx, path, k, readOnly)
				if d != nil {
					d.Close()
				}
				if !errors.Is(e, ErrSchema) {
					t.Fatalf("mode=%t err=%v", readOnly, e)
				}
			}
			after, _ := os.ReadFile(path)
			if sha256.Sum256(before) != sha256.Sum256(after) {
				t.Fatal("rejected database was modified")
			}
		})
	}
}
func TestFailedMigrationRollsBack(t *testing.T) {
	p, _ := portalForTest(t)
	steps, e := plan(Portal)
	if e != nil {
		t.Fatal(e)
	}
	statement := "CREATE TABLE must_not_survive(id INTEGER); INSERT INTO table_that_does_not_exist VALUES(1);"
	h := sha256.Sum256([]byte(statement))
	steps = append(steps, migration{len(steps) + 1, "test_broken.sql", statement, hex.EncodeToString(h[:])})
	if e = migrate(ctx, p.db, Portal, steps); e == nil {
		t.Fatal("broken migration succeeded")
	}
	var version, count int
	p.db.QueryRow("PRAGMA user_version").Scan(&version)
	p.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='must_not_survive'").Scan(&count)
	if version != len(steps)-1 || count != 0 {
		t.Fatalf("partial migration: version %d count %d", version, count)
	}
	var migrations int
	p.db.QueryRow("SELECT count(*) FROM schema_migrations").Scan(&migrations)
	if migrations != len(steps)-1 {
		t.Fatal("partial history")
	}
}
func TestConcurrentExpectedRevision(t *testing.T) {
	p, path := portalForTest(t)
	if e := p.SeedDemo(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	other, e := OpenPortal(ctx, path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	results := make(chan error, 2)
	var start sync.WaitGroup
	start.Add(1)
	for _, s := range []*PortalStore{p, other} {
		go func(s *PortalStore) { start.Wait(); results <- s.RenameDemo(ctx, "dev-iphone", "Новое имя", 1) }(s)
	}
	start.Done()
	successes, conflicts := 0, 0
	for i := 0; i < 2; i++ {
		e := <-results
		if e == nil {
			successes++
		} else if errors.Is(e, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("success %d conflict %d", successes, conflicts)
	}
	var count int
	p.db.QueryRow("SELECT count(*) FROM audit_events WHERE action='device.rename'").Scan(&count)
	if count != 1 {
		t.Fatal("incorrect audit count")
	}
}
func TestConstraintsAndStoreSeparation(t *testing.T) {
	p, _ := portalForTest(t)
	if e := p.SeedDemo(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	bad := []string{
		"INSERT INTO devices(id,user_id,name,os,state,created_at) VALUES('bad','missing','x','ios','pending','now')",
		"INSERT INTO profiles(id,device_id,protocol,generation,state,format) VALUES('duplicate','dev-iphone','awg',1,'ready','txt')",
		"UPDATE devices SET state='invented' WHERE id='dev-iphone'",
		"INSERT INTO sessions(token_hash,user_id,created_at,last_seen_at,expires_at,auth_time) VALUES(X'00','demo-family','a','a','a','a')",
		"SELECT * FROM operations", "SELECT * FROM gateway_peers",
	}
	for _, q := range bad {
		if _, e := p.db.Exec(q); e == nil {
			t.Fatalf("accepted invalid statement %s", q)
		}
	}
	c, e := OpenControl(ctx, filepath.Join(t.TempDir(), "control", "state.db"), false)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if e = c.RecordRevocation(ctx, "profile", 1, "rotation"); e != nil {
		t.Fatal(e)
	}
	if e = c.RecordRevocation(ctx, "profile", 1, "retry"); e != nil {
		t.Fatal(e)
	}
	if _, e = c.db.Exec("DELETE FROM revocations"); e == nil {
		t.Fatal("tombstone deleted")
	}
	if _, e = c.db.Exec("UPDATE revocations SET generation=2"); e == nil {
		t.Fatal("tombstone mutated")
	}
	if ok, e := c.IsRevoked(ctx, "profile", 1); e != nil || !ok {
		t.Fatal("lost revocation")
	}
	if _, e = c.db.Exec("SELECT * FROM profiles"); e == nil {
		t.Fatal("portal table in control DB")
	}
	var v int
	c.db.QueryRow("PRAGMA user_version").Scan(&v)
	if v != 4 {
		t.Fatal("control migrations missing")
	}
}
func TestPrivateFilesAndSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions test; Windows ACL setup is not implemented")
	}
	p, path := portalForTest(t)
	info, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	p.Close()
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if d, e := OpenPortal(ctx, path, false); e == nil {
		d.Close()
		t.Fatal("accepted permissive file")
	}
	os.Chmod(path, 0600)
	alias := filepath.Join(filepath.Dir(path), "alias.db")
	if e = os.Symlink(path, alias); e != nil {
		t.Fatal(e)
	}
	if d, e := OpenPortal(ctx, alias, true); e == nil {
		d.Close()
		t.Fatal("accepted symlink")
	}
}
func TestUnmarkedDatabaseIsNotDemo(t *testing.T) {
	p, _ := portalForTest(t)
	if e := p.AssertDemo(ctx); e == nil {
		t.Fatal("unmarked database served as demo")
	}
}

func TestUnownedVersionIsRejected(t *testing.T) {
	path, e := privatePath(filepath.Join(t.TempDir(), "private", "state.db"), true)
	if e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("PRAGMA user_version=999"); e != nil {
		t.Fatal(e)
	}
	db.Close()
	if d, e := OpenPortal(ctx, path, false); !errors.Is(e, ErrSchema) {
		if d != nil {
			d.Close()
		}
		t.Fatalf("unowned version accepted: %v", e)
	}
}

func TestControlSeedRejectsUnmarkedData(t *testing.T) {
	c, e := OpenControl(ctx, filepath.Join(t.TempDir(), "control", "state.db"), false)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if e = c.RecordRevocation(ctx, "profile", 1, "test"); e != nil {
		t.Fatal(e)
	}
	if e = c.SeedDemo(ctx); e == nil {
		t.Fatal("populated store relabeled as demo")
	}
	if e = c.AssertDemo(ctx); e == nil {
		t.Fatal("demo marker leaked from failed seed")
	}
}
