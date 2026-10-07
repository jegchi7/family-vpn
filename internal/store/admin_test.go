package store

import (
	"context"
	"crypto/rand"
	"errors"
	"familyvpn.local/platform/internal/adminauth"
	"familyvpn.local/platform/internal/auth"
	"github.com/pquerna/otp/totp"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type adminFixture struct {
	a                      *AdminStore
	s                      *adminauth.Service
	now                    time.Time
	secret, password, path string
	v                      *adminauth.Vault
}

func newAdminFixture(t *testing.T) *adminFixture {
	t.Helper()
	f := &adminFixture{now: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC), password: auth.RandomToken(), path: filepath.Join(t.TempDir(), "private", "admin.db")}
	var e error
	f.a, e = OpenAdmin(context.Background(), f.path, true)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.a.Close() })
	b := make([]byte, 32)
	rand.Read(b)
	f.v, e = adminauth.NewVault(b)
	if e != nil {
		t.Fatal(e)
	}
	f.s, e = adminauth.New(f.a, f.v, func() time.Time { return f.now })
	if e != nil {
		t.Fatal(e)
	}
	f.secret, e = f.s.Enroll(context.Background(), "operator", "Operator", f.password, false)
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *adminFixture) code(t *testing.T) string {
	t.Helper()
	c, e := totp.GenerateCode(f.secret, f.now)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func (f *adminFixture) activate(t *testing.T) {
	t.Helper()
	if e := f.s.Confirm(context.Background(), "operator", f.code(t)); e != nil {
		t.Fatal(e)
	}
	f.now = f.now.Add(30 * time.Second)
}
func (f *adminFixture) challenge(t *testing.T, binding string) adminauth.Challenge {
	t.Helper()
	c, e := f.s.Login(context.Background(), "127.0.0.1", binding, "operator", f.password)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestAdminEnrollmentAndSessionBoundary(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	binding := auth.RandomToken()
	if _, e := f.s.Login(ctx, "local", binding, "operator", f.password); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("unconfirmed login", e)
	}
	f.activate(t)
	if e := f.s.Confirm(ctx, "operator", f.code(t)); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("enrollment replay", e)
	}
	ch := f.challenge(t, binding)
	var n int
	f.a.db.QueryRow("SELECT count(*) FROM sessions").Scan(&n)
	if n != 0 {
		t.Fatal("first factor created session")
	}
	if _, e := f.s.Finish(ctx, "local", auth.RandomToken(), ch.Token, f.code(t)); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("binding bypass", e)
	}
	result, e := f.s.Finish(ctx, "local", binding, ch.Token, f.code(t))
	if e != nil {
		t.Fatal(e)
	}
	if result.Role != "admin" || result.ExpiresAt.Sub(f.now) != adminauth.TTL {
		t.Fatal("session policy")
	}
	if _, e = f.s.Authenticate(ctx, result.Token); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Finish(ctx, "local", binding, ch.Token, f.code(t)); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("challenge replay", e)
	}
	ch = f.challenge(t, binding)
	if _, e = f.s.Finish(ctx, "local", binding, ch.Token, f.code(t)); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("TOTP replay across challenges", e)
	}
	f.now = f.now.Add(adminauth.Idle)
	if _, e = f.s.Authenticate(ctx, result.Token); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("idle boundary", e)
	}
	if e = f.s.Touch(ctx, result.Token); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("touch resurrected session", e)
	}
}
func TestAdminChallengeExpiryLimitsAndInvalidation(t *testing.T) {
	f := newAdminFixture(t)
	f.activate(t)
	ctx := context.Background()
	binding := auth.RandomToken()
	old := f.challenge(t, binding)
	ch := f.challenge(t, binding)
	if _, e := f.s.Finish(ctx, "ip", binding, old.Token, f.code(t)); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("replaced challenge accepted", e)
	}
	for range 5 {
		if _, e := f.s.Finish(ctx, "ip", binding, ch.Token, "invalid"); !errors.Is(e, auth.ErrDenied) {
			t.Fatal(e)
		}
	}
	// Bypass outer limiter to exercise durable attempt cap itself.
	if _, e := f.a.AdminFinish(ctx, auth.TokenHash(ch.Token), auth.TokenHash(binding), "", auth.TokenHash(auth.RandomToken()), f.now, f.now.Add(adminauth.TTL), func(c adminauth.Credential, s string) (int64, error) {
		t.Fatal("exhausted challenge reached verifier")
		return 0, nil
	}); !errors.Is(e, auth.ErrDenied) {
		t.Fatal(e)
	}
	f.now = f.now.Add(5 * time.Minute)
	ch = f.challenge(t, binding)
	f.now = f.now.Add(adminauth.ChallengeTTL)
	if _, e := f.s.Finish(ctx, "ip", binding, ch.Token, f.code(t)); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("expired challenge", e)
	}
}
func TestAdminResetDisableAndStalePassword(t *testing.T) {
	f := newAdminFixture(t)
	f.activate(t)
	ctx := context.Background()
	binding := auth.RandomToken()
	ch := f.challenge(t, binding)
	result, e := f.s.Finish(ctx, "ip", binding, ch.Token, f.code(t))
	if e != nil {
		t.Fatal(e)
	}
	cached, e := f.a.AdminCredential(ctx, "operator")
	if e != nil {
		t.Fatal(e)
	}
	ch = f.challenge(t, binding)
	newPassword := auth.RandomToken()
	secret, e := f.s.Enroll(ctx, "operator", "Operator", newPassword, true)
	if e != nil {
		t.Fatal(e)
	}
	id, e := f.a.AdminID(ctx, "operator")
	if e != nil || id != cached.ID {
		t.Fatal("reset changed identity", e)
	}
	if _, e = f.s.Authenticate(ctx, result.Token); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("reset session", e)
	}
	if _, e = f.s.Finish(ctx, "ip", binding, ch.Token, f.code(t)); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("reset challenge", e)
	}
	if e = f.a.AdminChallenge(ctx, cached, auth.TokenHash(auth.RandomToken()), auth.TokenHash(binding), f.now, f.now.Add(time.Minute)); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("stale password issued challenge", e)
	}
	f.secret = secret
	f.password = newPassword
	f.activate(t)
	ch = f.challenge(t, binding)
	if e = f.a.AdminDisable(ctx, "operator", f.now); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Finish(ctx, "ip", binding, ch.Token, f.code(t)); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("disabled challenge", e)
	}
}
func TestAdminConcurrentFinishAndAuditRollback(t *testing.T) {
	f := newAdminFixture(t)
	f.activate(t)
	ctx := context.Background()
	binding := auth.RandomToken()
	ch := f.challenge(t, binding)
	other, e := OpenAdmin(ctx, f.path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	s2, e := adminauth.New(other, f.v, func() time.Time { return f.now })
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.a.db.Exec(`CREATE TRIGGER fail_admin_audit BEFORE INSERT ON audit_events WHEN NEW.action='admin.session.login' BEGIN SELECT RAISE(ABORT,'test'); END`)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Finish(ctx, "ip", binding, ch.Token, f.code(t)); e == nil {
		t.Fatal("audit failure accepted")
	}
	f.a.db.Exec("DROP TRIGGER fail_admin_audit")
	code := f.code(t)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, s := range []*adminauth.Service{f.s, s2} {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := s.Finish(ctx, "ip", binding, ch.Token, code); errs <- e }()
	}
	wg.Wait()
	close(errs)
	successes := 0
	for e := range errs {
		if e == nil {
			successes++
		} else if !errors.Is(e, auth.ErrDenied) {
			t.Fatal(e)
		}
	}
	if successes != 1 {
		t.Fatalf("successes %d", successes)
	}
	var n int
	f.a.db.QueryRow("SELECT count(*) FROM sessions").Scan(&n)
	if n != 1 {
		t.Fatal(n)
	}
}
func TestAdminKeyIsolationExpiryAndRestart(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	var raw []byte
	f.a.db.QueryRow("SELECT encrypted_secret FROM admin_accounts").Scan(&raw)
	if string(raw) == f.secret {
		t.Fatal("plaintext secret")
	}
	bad := make([]byte, 32)
	rand.Read(bad)
	v, _ := adminauth.NewVault(bad)
	if _, e := adminauth.New(f.a, v, nil); !errors.Is(e, adminauth.ErrKey) {
		t.Fatal("wrong master accepted", e)
	}
	if _, e := OpenExistingPortal(ctx, f.path); !errors.Is(e, ErrSchema) {
		t.Fatal("admin DB opened as portal", e)
	}
	if e := (&PortalStore{f.a.Database}).CreateRecovery(ctx, "operator", auth.TokenHash(auth.RandomToken()), f.now, f.now.Add(time.Minute)); e == nil {
		t.Fatal("user recovery reached admin DB")
	}
	f.now = f.now.Add(adminauth.EnrollmentTTL)
	if e := f.s.Confirm(ctx, "operator", f.code(t)); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("expired enrollment", e)
	}
	f.now = f.now.Add(time.Minute)
	f.secret, _ = f.s.Enroll(ctx, "operator", "Operator", f.password, true)
	f.activate(t)
	b := auth.RandomToken()
	ch := f.challenge(t, b)
	result, e := f.s.Finish(ctx, "ip", b, ch.Token, f.code(t))
	if e != nil {
		t.Fatal(e)
	}
	// Persistent session and replay counter survive a second runtime process.
	other, e := OpenAdmin(ctx, f.path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	s, e := adminauth.New(other, f.v, func() time.Time { return f.now })
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Authenticate(ctx, result.Token); e != nil {
		t.Fatal(e)
	}
	f.now = f.now.Add(adminauth.TTL)
	if _, e = s.Authenticate(ctx, result.Token); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("absolute expiration", e)
	}
}

func TestAdminResetRollbackAndAbsoluteLifetime(t *testing.T) {
	f := newAdminFixture(t)
	f.activate(t)
	ctx := context.Background()
	binding := auth.RandomToken()
	ch := f.challenge(t, binding)
	result, e := f.s.Finish(ctx, "ip", binding, ch.Token, f.code(t))
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.a.db.Exec(`CREATE TRIGGER fail_reset_audit BEFORE INSERT ON audit_events WHEN NEW.action='admin.reset' BEGIN SELECT RAISE(ABORT,'test'); END`)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Enroll(ctx, "operator", "Operator", auth.RandomToken(), true); e == nil {
		t.Fatal("failed audit allowed reset")
	}
	if _, e = f.s.Authenticate(ctx, result.Token); e != nil {
		t.Fatal("failed reset revoked original session", e)
	}
	c, e := f.a.AdminCredential(ctx, "operator")
	if e != nil || !auth.VerifyPassword(f.password, c.PasswordHash) {
		t.Fatal("failed reset changed credential", e)
	}
	if _, e = f.a.db.Exec("DROP TRIGGER fail_reset_audit"); e != nil {
		t.Fatal(e)
	}
	// Keep idle fresh throughout the absolute lifetime: touch must never extend expiry.
	for i := 0; i < 35; i++ {
		f.now = f.now.Add(20 * time.Minute)
		if e = f.s.Touch(ctx, result.Token); e != nil {
			t.Fatal(e)
		}
	}
	f.now = f.now.Add(20 * time.Minute)
	if _, e = f.s.Authenticate(ctx, result.Token); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("absolute TTL was extended by touch", e)
	}
	if e = f.s.Touch(ctx, result.Token); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("touch revived absolute-expired session", e)
	}
}
