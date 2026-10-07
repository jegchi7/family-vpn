package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"familyvpn.local/platform/internal/adminauth"
	"familyvpn.local/platform/internal/app"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/store"
	"github.com/pquerna/otp/totp"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func standFixture(t *testing.T) (string, string) {
	t.Helper()
	base := filepath.Join(t.TempDir(), "stand space # percent%")
	root, web := filepath.Join(base, "users"), filepath.Join(base, "web")
	p, e := store.OpenPortal(context.Background(), filepath.Join(root, "portal", "state.db"), false)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.InitializeLocalAuth(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	if e = app.CreateLocalCertificate(root); e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll(filepath.Join(web, "assets"), 0700); e != nil {
		t.Fatal(e)
	}
	for path, data := range map[string]string{"index.html": `<html><div id="app"></div><script type="module" src="/assets/main.js"></script></html>`, "assets/main.js": "document.getElementById('app').textContent='stand';"} {
		if e = os.WriteFile(filepath.Join(web, path), []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
	}
	return root, web
}

func checkStandReport(t *testing.T, args []string, want string, blocker string) {
	t.Helper()
	var out bytes.Buffer
	e := runStandCheck(args, &out)
	var report struct {
		Status   string   `json:"status"`
		Blockers []string `json:"blockers"`
		ReadOnly bool     `json:"read_only"`
		Sidecars bool     `json:"sqlite_sidecars_possible"`
		Network  bool     `json:"network_changed"`
		Ready    bool     `json:"vpn_ready"`
		Delivery bool     `json:"profile_delivery_available"`
	}
	if json.Unmarshal(out.Bytes(), &report) != nil || report.Status != want || !report.ReadOnly || !report.Sidecars || report.Network || report.Ready || report.Delivery || (e != nil) != (want == "blocked") {
		t.Fatal("report policy/exit mismatch")
	}
	if blocker != "" {
		found := false
		for _, code := range report.Blockers {
			found = found || code == blocker
		}
		if !found {
			t.Fatal("missing safe blocker")
		}
	} else if len(report.Blockers) != 0 {
		t.Fatal("unexpected blocker")
	}
	for _, arg := range args {
		if len(arg) > 3 && !strings.HasPrefix(arg, "--") && (bytes.Contains(out.Bytes(), []byte(arg)) || (e != nil && strings.Contains(e.Error(), arg))) {
			t.Fatal("diagnostic exposed input")
		}
	}
}

func TestStandCheckPortalReadOnlyNoPermissionsOrControl(t *testing.T) {
	root, web := standFixture(t)
	path := filepath.Join(root, "portal", "state.db")
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	args := []string{"--portal-root", root, "--web-dir", web}
	checkStandReport(t, args, "ok", "")
	after, e := os.ReadFile(path)
	if e != nil || sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("diagnostic changed database")
	}
	if _, e = os.Stat(filepath.Join(root, "control")); !os.IsNotExist(e) {
		t.Fatal("diagnostic opened control store")
	}
	if _, e = os.Stat(filepath.Join(root, "profile-secrets")); !os.IsNotExist(e) {
		t.Fatal("diagnostic created key")
	}
	if e = os.Remove(filepath.Join(web, "assets", "main.js")); e != nil {
		t.Fatal(e)
	}
	checkStandReport(t, args, "blocked", "WEB_ASSETS_UNAVAILABLE")
	if e = os.Remove(filepath.Join(root, "tls", "local-key.pem")); e != nil {
		t.Fatal(e)
	}
	checkStandReport(t, args, "blocked", "PORTAL_TLS_UNAVAILABLE_OR_EXPIRED")
}

func TestStandCheckRejectsMissingDemoAndMalformedArguments(t *testing.T) {
	root, web := standFixture(t)
	missing := filepath.Join(t.TempDir(), "never-created")
	checkStandReport(t, []string{"--portal-root", missing, "--web-dir", web}, "blocked", "PORTAL_DB_UNAVAILABLE")
	if _, e := os.Stat(missing); !os.IsNotExist(e) {
		t.Fatal("diagnostic created state")
	}
	checkStandReport(t, []string{"--portal-root", root, "--unknown", auth.RandomToken()}, "blocked", "INVALID_ARGUMENTS")
	checkStandReport(t, []string{"--portal-root", root, "positional"}, "blocked", "INVALID_ARGUMENTS")
	demo := filepath.Join(t.TempDir(), "demo")
	p, e := store.OpenPortal(context.Background(), filepath.Join(demo, "portal", "state.db"), false)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.SeedDemo(context.Background(), time.Now()); e != nil {
		t.Fatal(e)
	}
	p.Close()
	if e = app.CreateLocalCertificate(demo); e != nil {
		t.Fatal(e)
	}
	checkStandReport(t, []string{"--portal-root", demo, "--web-dir", web}, "blocked", "PORTAL_DATASET_INVALID")
}

func TestStandCheckAdminRequiresConfirmedMFAAndLinux(t *testing.T) {
	root, web := standFixture(t)
	base := filepath.Dir(root)
	admin := filepath.Join(base, "admin")
	key := filepath.Join(base, "admin-secrets", "master.key")
	args := []string{"--portal-root", root, "--web-dir", web, "--admin-root", admin, "--master-key", key, "--require-admin"}
	if runtime.GOOS != "linux" {
		checkStandReport(t, args, "blocked", "ADMIN_STAND_REQUIRES_LINUX")
		if _, e := os.Stat(admin); !os.IsNotExist(e) {
			t.Fatal("unsupported OS created admin state")
		}
		return
	}
	ctx := context.Background()
	if e := os.MkdirAll(filepath.Dir(key), 0700); e != nil {
		t.Fatal(e)
	}
	if e := adminauth.CreateKey(key); e != nil {
		t.Fatal(e)
	}
	v, e := adminauth.LoadKey(key)
	if e != nil {
		t.Fatal(e)
	}
	a, e := store.OpenAdmin(ctx, filepath.Join(admin, "auth", "state.db"), true)
	if e != nil {
		t.Fatal(e)
	}
	if e = app.CreateLocalCertificate(admin); e != nil {
		t.Fatal(e)
	}
	a.Close()
	checkStandReport(t, args, "blocked", "ADMIN_MFA_ENROLLMENT_REQUIRED")
	a, e = store.OpenAdmin(ctx, filepath.Join(admin, "auth", "state.db"), false)
	if e != nil {
		t.Fatal(e)
	}
	s, e := adminauth.New(a, v, nil)
	if e != nil {
		t.Fatal(e)
	}
	secret, e := s.Enroll(ctx, "operator", "Test operator", auth.RandomToken(), false)
	if e != nil {
		t.Fatal(e)
	}
	a.Close()
	checkStandReport(t, args, "blocked", "ADMIN_MFA_ENROLLMENT_REQUIRED")
	a, e = store.OpenAdmin(ctx, filepath.Join(admin, "auth", "state.db"), false)
	if e != nil {
		t.Fatal(e)
	}
	s, e = adminauth.New(a, v, nil)
	if e != nil {
		t.Fatal(e)
	}
	code, e := totp.GenerateCode(secret, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Confirm(ctx, "operator", code); e != nil {
		t.Fatal(e)
	}
	a.Close()
	path := filepath.Join(admin, "auth", "state.db")
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	checkStandReport(t, args, "ok", "")
	after, e := os.ReadFile(path)
	if e != nil || sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("diagnostic changed admin credentials/state")
	}
	checkStandReport(t, []string{"--portal-root", root, "--web-dir", web, "--admin-root", root, "--master-key", key, "--require-admin"}, "blocked", "ADMIN_STATE_OR_KEY_LOCATION_INVALID")
	checkStandReport(t, []string{"--portal-root", root, "--web-dir", web, "--admin-root", admin, "--master-key", filepath.Join(admin, "master.key"), "--require-admin"}, "blocked", "ADMIN_STATE_OR_KEY_LOCATION_INVALID")
}
