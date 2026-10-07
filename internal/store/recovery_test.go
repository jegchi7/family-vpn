package store

import (
	"bytes"
	"database/sql"
	"errors"
	"familyvpn.local/platform/internal/auth"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func requireDenied(t *testing.T, e error) {
	t.Helper()
	if !errors.Is(e, auth.ErrDenied) {
		t.Fatalf("expected authentication refusal, got %v", e)
	}
}
func TestRecoveryRevokesImmediatelyAndPreservesOwnership(t *testing.T) {
	p, s, now, path := authStore(t)
	alice, oldPassword := enroll(t, s, "alice")
	bob, _ := enroll(t, s, "bob")
	second, e := s.Login(ctx, "127.0.0.1", "alice", oldPassword)
	if e != nil {
		t.Fatal(e)
	}
	id, cachedHash, e := p.PasswordCredential(ctx, "alice")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.db.Exec("INSERT INTO devices(id,user_id,name,os,state,created_at) VALUES('keep-device',?,'Phone','ios','active',?)", alice.ID, stamp(*now)); e != nil {
		t.Fatal(e)
	}
	if _, e = p.db.Exec("INSERT INTO profiles(id,device_id,protocol,generation,state,format) VALUES('keep-profile','keep-device','awg',1,'ready','txt')"); e != nil {
		t.Fatal(e)
	}
	token, e := s.IssueRecovery(ctx, "ALICE", auth.RecoveryTTL)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range []auth.Result{alice, second} {
		_, e = s.Authenticate(ctx, r.Token)
		requireDenied(t, e)
	}
	_, e = s.Login(ctx, "127.0.0.1", "alice", oldPassword)
	requireDenied(t, e)
	// A login whose KDF began before reset must not create a session afterwards.
	_, e = p.CreateSession(ctx, id, cachedHash, auth.TokenHash(auth.RandomToken()), *now, now.Add(time.Hour))
	requireDenied(t, e)
	if _, e = s.Authenticate(ctx, bob.Token); e != nil {
		t.Fatal("other user revoked", e)
	}
	var stored []byte
	if e = p.db.QueryRow("SELECT token_hash FROM one_time_tokens WHERE user_id=? AND purpose='recovery'", alice.ID).Scan(&stored); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(stored, auth.TokenHash(token)) || bytes.Equal(stored, []byte(token)) {
		t.Fatal("recovery storage is not hashed")
	}
	p.Close()
	p, e = OpenExistingPortal(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	s.Repo = p
	newPassword := auth.RandomToken()
	if e = s.Recover(ctx, "127.0.0.1", token, newPassword); e != nil {
		t.Fatal(e)
	}
	var n int
	p.db.QueryRow("SELECT count(*) FROM sessions WHERE user_id=? AND revoked_at IS NULL", alice.ID).Scan(&n)
	if n != 0 {
		t.Fatal("recovery automatically logged user in")
	}
	r, e := s.Login(ctx, "127.0.0.1", "alice", newPassword)
	if e != nil || r.ID != alice.ID {
		t.Fatal("account identity not preserved", e)
	}
	if profile, ok, e := p.ProfileForOwner(ctx, alice.ID, "keep-profile"); e != nil || !ok || profile.State != "ready" {
		t.Fatal("recovery changed profile")
	}
	requireDenied(t, s.Recover(ctx, "127.0.0.1", token, auth.RandomToken()))
	_, e = s.Login(ctx, "127.0.0.1", "alice", oldPassword)
	requireDenied(t, e)
	var auditText string
	p.db.QueryRow("SELECT group_concat(actor||action||object_ref,' ') FROM audit_events").Scan(&auditText)
	for _, secret := range []string{token, newPassword, oldPassword, cachedHash, alice.Token} {
		if strings.Contains(auditText, secret) {
			t.Fatal("secret in audit")
		}
	}
}
func TestRecoveryExpirySupersessionAndPurpose(t *testing.T) {
	p, s, now, _ := authStore(t)
	_, old := enroll(t, s, "alice")
	a, e := s.IssueRecovery(ctx, "alice", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.IssueRecovery(ctx, "alice", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	requireDenied(t, s.Recover(ctx, "127.0.0.1", a, auth.RandomToken()))
	var revoked sql.NullString
	var consumed sql.NullString
	if e = p.db.QueryRow("SELECT revoked_at,consumed_at FROM one_time_tokens WHERE token_hash=?", auth.TokenHash(a)).Scan(&revoked, &consumed); e != nil {
		t.Fatal(e)
	}
	if !revoked.Valid || consumed.Valid {
		t.Fatal("revocation confused with consumption")
	}
	_, e = s.Accept(ctx, "127.0.0.1", b, auth.RandomToken())
	requireDenied(t, e)
	invite, e := s.IssueInvite(ctx, "bob", "Bob", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	requireDenied(t, s.Recover(ctx, "127.0.0.1", invite, auth.RandomToken()))
	*now = now.Add(time.Minute)
	requireDenied(t, s.Recover(ctx, "127.0.0.1", b, auth.RandomToken()))
	_, e = s.Login(ctx, "127.0.0.1", "alice", old)
	requireDenied(t, e)
	c, e := s.IssueRecovery(ctx, "alice", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Recover(ctx, "127.0.0.1", c, auth.RandomToken()); e != nil {
		t.Fatal("cannot replace expired recovery", e)
	}
}
func TestRecoveryRace(t *testing.T) {
	p, s, now, path := authStore(t)
	enroll(t, s, "alice")
	token, e := s.IssueRecovery(ctx, "alice", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	hash, e := auth.HashPassword(auth.RandomToken())
	if e != nil {
		t.Fatal(e)
	}
	other, e := OpenExistingPortal(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, db := range []*PortalStore{p, other} {
		go func(db *PortalStore) { <-start; results <- db.CompleteRecovery(ctx, auth.TokenHash(token), hash, *now) }(db)
	}
	close(start)
	success, denied := 0, 0
	for i := 0; i < 2; i++ {
		e := <-results
		if e == nil {
			success++
		} else if errors.Is(e, auth.ErrDenied) {
			denied++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || denied != 1 {
		t.Fatal("concurrent recovery was not single-use")
	}
	var n int
	p.db.QueryRow("SELECT count(*) FROM audit_events WHERE action='recovery.complete'").Scan(&n)
	if n != 1 {
		t.Fatal("duplicate audit transition")
	}
}
func TestRecoveryTransactionsRollback(t *testing.T) {
	p, s, now, _ := authStore(t)
	r, password := enroll(t, s, "alice")
	// Failed issuance must not revoke access or leave an invisible token behind.
	if _, e := p.db.Exec("CREATE TRIGGER fail_recovery_audit BEFORE INSERT ON audit_events WHEN NEW.action='recovery.issue' BEGIN SELECT RAISE(ABORT,'test'); END"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.IssueRecovery(ctx, "alice", time.Hour); e == nil {
		t.Fatal("expected issuance failure")
	}
	if _, e := s.Authenticate(ctx, r.Token); e != nil {
		t.Fatal("failed issue revoked session")
	}
	if _, e := s.Login(ctx, "127.0.0.1", "alice", password); e != nil {
		t.Fatal("failed issue removed password")
	}
	var n int
	p.db.QueryRow("SELECT count(*) FROM one_time_tokens WHERE purpose='recovery'").Scan(&n)
	if n != 0 {
		t.Fatal("partial token")
	}
	p.db.Exec("DROP TRIGGER fail_recovery_audit")
	token, e := s.IssueRecovery(ctx, "alice", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.db.Exec("CREATE TRIGGER fail_recovery_password BEFORE INSERT ON credentials BEGIN SELECT RAISE(ABORT,'test'); END"); e != nil {
		t.Fatal(e)
	}
	encoded, e := auth.HashPassword(auth.RandomToken())
	if e != nil {
		t.Fatal(e)
	}
	if e = p.CompleteRecovery(ctx, auth.TokenHash(token), encoded, *now); e == nil {
		t.Fatal("expected credential failure")
	}
	p.db.QueryRow("SELECT count(*) FROM one_time_tokens WHERE token_hash=? AND consumed_at IS NULL AND revoked_at IS NULL", auth.TokenHash(token)).Scan(&n)
	if n != 1 {
		t.Fatal("failed completion consumed token")
	}
	p.db.Exec("DROP TRIGGER fail_recovery_password")
	if e = p.CompleteRecovery(ctx, auth.TokenHash(token), encoded, *now); e != nil {
		t.Fatal(e)
	}
}
func TestRecoveryRoleStateAndCredentialRestrictions(t *testing.T) {
	for _, kind := range []string{"admin", "disabled", "passkey"} {
		t.Run(kind, func(t *testing.T) {
			p, s, now, _ := authStore(t)
			r, _ := enroll(t, s, "alice")
			token, e := s.IssueRecovery(ctx, "alice", time.Hour)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "admin":
				_, e = p.db.Exec("UPDATE users SET role='admin' WHERE id=?", r.ID)
			case "disabled":
				_, e = p.db.Exec("UPDATE users SET state='disabled' WHERE id=?", r.ID)
			case "passkey":
				_, e = p.db.Exec("INSERT INTO credentials(id,user_id,kind,created_at) VALUES(?,?,'passkey',?)", auth.RandomToken(), r.ID, stamp(*now))
			}
			if e != nil {
				t.Fatal(e)
			}
			_, e = s.IssueRecovery(ctx, "alice", time.Hour)
			requireDenied(t, e)
			requireDenied(t, s.Recover(ctx, "127.0.0.1", token, auth.RandomToken()))
		})
	}
	_, s, _, _ := authStore(t)
	_, e := s.IssueRecovery(ctx, "missing", time.Hour)
	requireDenied(t, e)
	if _, e = s.IssueRecovery(ctx, "valid", 2*time.Hour); !errors.Is(e, auth.ErrInput) {
		t.Fatal("excessive TTL accepted")
	}
}
func TestReissueInvite(t *testing.T) {
	p, s, now, _ := authStore(t)
	a, e := s.IssueInvite(ctx, "alice", "Alice", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.IssueRecovery(ctx, "alice", time.Minute); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("invited user recovered")
	}
	*now = now.Add(time.Minute)
	b, e := s.ReissueInvite(ctx, "alice", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.Accept(ctx, "127.0.0.1", a, auth.RandomToken())
	requireDenied(t, e)
	r, e := s.Accept(ctx, "127.0.0.1", b, auth.RandomToken())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReissueInvite(ctx, "alice", time.Hour); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("active user re-enrolled")
	}
	var n int
	p.db.QueryRow("SELECT count(*) FROM users WHERE id=? AND login='alice'", r.ID).Scan(&n)
	if n != 1 {
		t.Fatal("duplicate user")
	}
}

func TestRecoveryRateLimitDoesNotConsumeToken(t *testing.T) {
	_, s, now, _ := authStore(t)
	enroll(t, s, "alice")
	token, e := s.IssueRecovery(ctx, "alice", auth.RecoveryTTL)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 5; i++ {
		requireDenied(t, s.Recover(ctx, "127.0.0.1", token, "short"))
	}
	if e = s.Recover(ctx, "127.0.0.1", token, auth.RandomToken()); !errors.Is(e, auth.ErrLimited) {
		t.Fatal("recovery did not use rate limiter")
	}
	*now = now.Add(auth.Window + time.Second)
	if e = s.Recover(ctx, "127.0.0.1", token, auth.RandomToken()); e != nil {
		t.Fatal("rate limit consumed token", e)
	}
}

func TestUpgradeV2KeepsExistingSessionsAndInvitations(t *testing.T) {
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
	if e = migrate(ctx, db, Portal, steps[:2]); e != nil {
		t.Fatal(e)
	}
	old := &PortalStore{&Database{db: db, kind: Portal}}
	if e = old.InitializeLocalAuth(ctx); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	userID := auth.RandomToken()
	password := auth.RandomToken()
	encoded, e := auth.HashPassword(password)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("INSERT INTO users(id,login,display_name,role,state,created_at) VALUES(?,'alice','Alice','user','active',?)", userID, stamp(now)); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("INSERT INTO credentials(id,user_id,kind,password_hash,created_at) VALUES(?,?,'password',?,?)", auth.RandomToken(), userID, encoded, stamp(now)); e != nil {
		t.Fatal(e)
	}
	rawSession := auth.RandomToken()
	if _, e = old.CreateSession(ctx, userID, encoded, auth.TokenHash(rawSession), now, now.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	invite := auth.RandomToken()
	if e = old.CreateInvite(ctx, auth.RandomToken(), "bob", "Bob", auth.TokenHash(invite), now, now.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	old.Close()
	current, e := OpenPortal(ctx, path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer current.Close()
	s, e := auth.New(current, func() time.Time { return now }, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	if r, e := s.Authenticate(ctx, rawSession); e != nil || r.ID != userID {
		t.Fatal("upgrade lost session", e)
	}
	if _, e = s.Accept(ctx, "127.0.0.1", invite, auth.RandomToken()); e != nil {
		t.Fatal("upgrade invalidated pending invitation", e)
	}
	if _, e = s.IssueRecovery(ctx, "alice", auth.RecoveryTTL); e != nil {
		t.Fatal("upgraded user cannot recover", e)
	}
}
