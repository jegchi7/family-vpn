package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"familyvpn.local/platform/internal/auth"
	"path/filepath"
	"testing"
	"time"
)

func authStore(t *testing.T) (*PortalStore, *auth.Service, *time.Time, string) {
	t.Helper()
	p, path := portalForTest(t)
	if e := p.InitializeLocalAuth(ctx); e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	s, e := auth.New(p, func() time.Time { return now }, time.Hour, 10*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	return p, s, &now, path
}
func enroll(t *testing.T, s *auth.Service, login string) (auth.Result, string) {
	t.Helper()
	token, e := s.IssueInvite(ctx, login, "Local test", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	password := auth.RandomToken()
	r, e := s.Accept(ctx, "127.0.0.1", token, password)
	if e != nil {
		t.Fatal(e)
	}
	return r, password
}
func TestAuthSessionLifecycleAndOwnership(t *testing.T) {
	p, s, now, path := authStore(t)
	r, password := enroll(t, s, "alice")
	other, _ := enroll(t, s, "bob")
	for _, u := range []auth.Result{r, other} {
		if _, e := p.db.Exec("INSERT INTO devices(id,user_id,name,os,state,created_at) VALUES(?,?,?,'ios','pending',?)", u.ID, u.ID, u.DisplayName, stamp(*now)); e != nil {
			t.Fatal(e)
		}
	}
	ds, e := p.DevicesForOwner(ctx, r.ID)
	if e != nil || len(ds) != 1 || ds[0].ID != r.ID {
		t.Fatal("ownership failure")
	}
	var stored []byte
	if e = p.db.QueryRow("SELECT token_hash FROM sessions WHERE user_id=?", r.ID).Scan(&stored); e != nil {
		t.Fatal(e)
	}
	if bytes.Equal(stored, []byte(r.Token)) || !bytes.Equal(stored, auth.TokenHash(r.Token)) {
		t.Fatal("plaintext session")
	}
	p.Close()
	p, e = OpenExistingPortal(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	s.Repo = p
	if _, e = s.Authenticate(ctx, r.Token); e != nil {
		t.Fatal("session did not survive reopen", e)
	}
	if _, e = s.Login(ctx, "127.0.0.1", "ALICE", password); e != nil {
		t.Fatal(e)
	}
	if e = s.Logout(ctx, r.Token); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Authenticate(ctx, r.Token); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("logout did not revoke")
	}
	*now = now.Add(10 * time.Minute)
	if _, e = s.Authenticate(ctx, other.Token); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("idle expiry bypass")
	}
	if e = s.Touch(ctx, other.Token); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("touch resurrected idle session")
	}
}
func TestAuthAbsoluteExpiryAndNoGETActivity(t *testing.T) {
	p, s, now, _ := authStore(t)
	r, _ := enroll(t, s, "alice")
	*now = now.Add(9 * time.Minute)
	if _, e := s.Authenticate(ctx, r.Token); e != nil {
		t.Fatal(e)
	}
	var seen string
	p.db.QueryRow("SELECT last_seen_at FROM sessions WHERE token_hash=?", auth.TokenHash(r.Token)).Scan(&seen)
	if seen != stamp(r.AuthTime) {
		t.Fatal("read changed idle timestamp")
	}
	for i := 0; i < 6; i++ {
		if e := s.Touch(ctx, r.Token); e != nil {
			t.Fatal(e)
		}
		*now = now.Add(9 * time.Minute)
	}
	if _, e := s.Authenticate(ctx, r.Token); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("absolute expiry bypass")
	}
}
func TestInviteRaceAndRollback(t *testing.T) {
	p, s, now, path := authStore(t)
	token, e := s.IssueInvite(ctx, "alice", "Alice", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := auth.HashPassword(auth.RandomToken())
	if e != nil {
		t.Fatal(e)
	}
	other, e := OpenExistingPortal(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	errorsCh := make(chan error, 2)
	start := make(chan struct{})
	for _, db := range []*PortalStore{p, other} {
		go func(db *PortalStore) {
			<-start
			_, e := db.AcceptInvite(ctx, auth.TokenHash(token), encoded, auth.TokenHash(auth.RandomToken()), *now, now.Add(time.Hour))
			errorsCh <- e
		}(db)
	}
	close(start)
	success, denied := 0, 0
	for i := 0; i < 2; i++ {
		e := <-errorsCh
		if e == nil {
			success++
		} else if errors.Is(e, auth.ErrDenied) {
			denied++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || denied != 1 {
		t.Fatal("invite race", success, denied)
	}
	var n int
	p.db.QueryRow("SELECT count(*) FROM sessions").Scan(&n)
	if n != 1 {
		t.Fatal("duplicate session")
	}
	token, e = s.IssueInvite(ctx, "bob", "Bob", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.db.Exec("CREATE TRIGGER deny_session BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT,'test failure'); END"); e != nil {
		t.Fatal(e)
	}
	if _, e = p.AcceptInvite(ctx, auth.TokenHash(token), encoded, auth.TokenHash(auth.RandomToken()), *now, now.Add(time.Hour)); e == nil {
		t.Fatal("expected failure")
	}
	p.db.QueryRow("SELECT count(*) FROM one_time_tokens WHERE token_hash=? AND consumed_at IS NULL", auth.TokenHash(token)).Scan(&n)
	if n != 1 {
		t.Fatal("failed activation consumed invitation")
	}
	p.db.QueryRow("SELECT count(*) FROM credentials c JOIN users u ON u.id=c.user_id WHERE u.login='bob'").Scan(&n)
	if n != 0 {
		t.Fatal("partial credential survived")
	}
}
func TestExpiredInviteAndRoleRestrictions(t *testing.T) {
	p, s, now, _ := authStore(t)
	token, e := s.IssueInvite(ctx, "alice", "Alice", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	*now = now.Add(time.Minute)
	if _, e = s.Accept(ctx, "127.0.0.1", token, auth.RandomToken()); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("expired invite accepted")
	}
	r, password := enroll(t, s, "bob")
	for _, change := range []string{"UPDATE users SET role='admin' WHERE login='bob'", "UPDATE users SET role='user',state='disabled' WHERE login='bob'"} {
		if _, e = p.db.Exec(change); e != nil {
			t.Fatal(e)
		}
		if _, e = s.Login(ctx, "127.0.0.1", "bob", password); !errors.Is(e, auth.ErrDenied) {
			t.Fatal("role/state login allowed", e)
		}
		if _, e = s.Authenticate(ctx, r.Token); !errors.Is(e, auth.ErrDenied) {
			t.Fatal("role/state session allowed")
		}
	}
}
func TestRateLimitsPersistAndExpire(t *testing.T) {
	p, _, now, path := authStore(t)
	ip := auth.TokenHash("ip")
	account := auth.TokenHash("account")
	for i := 0; i < 5; i++ {
		if e := p.ReserveAttempts(ctx, ip, account, *now); e != nil {
			t.Fatal(e)
		}
	}
	p.Close()
	p, e := OpenExistingPortal(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if e = p.ReserveAttempts(ctx, auth.TokenHash("another-ip"), account, *now); !errors.Is(e, auth.ErrLimited) {
		t.Fatal("account limit lost after restart")
	}
	for i := 0; i < 25; i++ {
		if e = p.ReserveAttempts(ctx, ip, auth.TokenHash(auth.RandomToken()), *now); e != nil {
			t.Fatal(e)
		}
	}
	if e = p.ReserveAttempts(ctx, ip, auth.TokenHash(auth.RandomToken()), *now); !errors.Is(e, auth.ErrLimited) {
		t.Fatal("IP limit missing")
	}
	*now = now.Add(auth.Window)
	if e = p.ReserveAttempts(ctx, ip, account, *now); e != nil {
		t.Fatal("window did not expire", e)
	}
}
func TestAuthModeSeparationAndRuntimeSchema(t *testing.T) {
	p, path := portalForTest(t)
	if e := p.SeedDemo(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	if e := p.InitializeLocalAuth(ctx); e == nil {
		t.Fatal("demo relabeled")
	}
	if e := p.AssertLocalAuth(ctx); e == nil {
		t.Fatal("demo accepted as auth")
	}
	if _, e := p.db.Exec("PRAGMA user_version=1; DELETE FROM schema_migrations WHERE version=2"); e != nil {
		t.Fatal(e)
	}
	p.Close()
	if d, e := OpenExistingPortal(ctx, path); !errors.Is(e, ErrSchema) {
		if d != nil {
			d.Close()
		}
		t.Fatal("runtime migrated old schema")
	}
	if d, e := OpenExistingPortal(context.Background(), filepath.Join(t.TempDir(), "missing", "state.db")); e == nil {
		d.Close()
		t.Fatal("runtime created store")
	}
}

func TestUpgradeV1PreservesDemo(t *testing.T) {
	path, e := privatePath(filepath.Join(t.TempDir(), "portal", "state.db"), true)
	if e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	steps, e := plan(Portal)
	if e != nil {
		t.Fatal(e)
	}
	if e = migrate(ctx, db, Portal, steps[:1]); e != nil {
		t.Fatal(e)
	}
	old := &PortalStore{&Database{db: db, kind: Portal}}
	if e = old.SeedDemo(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	if e = old.RenameDemo(ctx, "dev-iphone", "Preserved v1 name", 1); e != nil {
		t.Fatal(e)
	}
	old.Close()
	if ro, e := OpenPortal(ctx, path, true); !errors.Is(e, ErrSchema) {
		if ro != nil {
			ro.Close()
		}
		t.Fatal("old runtime schema accepted")
	}
	current, e := OpenPortal(ctx, path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer current.Close()
	if e = current.SeedDemo(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	devices, e := current.DevicesForOwner(ctx, "demo-family")
	if e != nil || len(devices) != 2 || devices[0].Name != "Preserved v1 name" {
		t.Fatal("upgrade changed prior data")
	}
	if e = current.AssertDemo(ctx); e != nil {
		t.Fatal(e)
	}
}
