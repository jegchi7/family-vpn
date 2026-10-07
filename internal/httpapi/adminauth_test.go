package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"familyvpn.local/platform/internal/adminauth"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/store"
	"github.com/pquerna/otp/totp"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminHTTPMFAAndPublicIsolation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	a, e := store.OpenAdmin(ctx, filepath.Join(root, "admin", "state.db"), true)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	p, e := store.OpenPortal(ctx, filepath.Join(root, "portal", "state.db"), false)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if e = p.InitializeLocalAuth(ctx); e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	key := make([]byte, 32)
	rand.Read(key)
	v, _ := adminauth.NewVault(key)
	s, e := adminauth.New(a, v, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	password := auth.RandomToken()
	secret, e := s.Enroll(ctx, "operator", "Admin", password, false)
	if e != nil {
		t.Fatal(e)
	}
	code, _ := totp.GenerateCode(secret, now)
	if e = s.Confirm(ctx, "operator", code); e != nil {
		t.Fatal(e)
	}
	now = now.Add(30 * time.Second)
	ts := httptest.NewUnstartedServer(nil)
	host := ts.Listener.Addr().String()
	ts.Config.Handler = New(Options{Host: host, Store: p, Admin: true, AdminAuth: s, AdminData: p})
	ts.StartTLS()
	defer ts.Close()
	client := ts.Client()
	client.Jar, _ = cookiejar.New(nil)
	request := func(method, path string, body any, csrf, origin string) (int, http.Header, []byte) {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		req.Header.Set("X-CSRF-Token", csrf)
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, res.Header, b
	}
	check := func(got, want int) {
		t.Helper()
		if got != want {
			t.Fatalf("status %d want %d", got, want)
		}
	}
	status, _, _ := request("GET", "/api/v1/admin/overview", nil, "", "")
	check(status, 401)
	status, _, raw := request("GET", "/api/v1/auth/bootstrap", nil, "", "")
	check(status, 200)
	var bootstrap map[string]string
	json.Unmarshal(raw, &bootstrap)
	if bootstrap["mode"] != "local-admin" {
		t.Fatal("wrong bootstrap")
	}
	csrf := bootstrap["csrf_token"]
	body := map[string]string{"login": "operator", "password": password}
	status, _, _ = request("POST", "/api/v1/auth/admin/password", body, csrf, "https://attacker.invalid")
	check(status, 403)
	status, _, _ = request("POST", "/api/v1/auth/admin/password", body, "", ts.URL)
	check(status, 403)
	status, _, _ = request("POST", "/api/v1/auth/admin/password?token=x", body, csrf, ts.URL)
	check(status, 400)
	status, head, raw := request("POST", "/api/v1/auth/admin/password", body, csrf, ts.URL)
	check(status, 200)
	if len(head.Values("Set-Cookie")) != 0 {
		t.Fatal("first factor set cookie")
	}
	var ch adminauth.Challenge
	json.Unmarshal(raw, &ch)
	status, _, _ = request("GET", "/api/v1/admin/overview", nil, "", "")
	check(status, 401)
	code, _ = totp.GenerateCode(secret, now)
	status, head, raw = request("POST", "/api/v1/auth/admin/totp", map[string]string{"challenge": ch.Token, "code": code}, csrf, ts.URL)
	check(status, 200)
	var session string
	for _, c := range (&http.Response{Header: head}).Cookies() {
		if c.Name == adminSessionCookie {
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.MaxAge != 43200 || c.Domain != "" {
				t.Fatal("admin cookie policy")
			}
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("no MFA session")
	}
	if strings.Contains(string(raw), session) || strings.Contains(string(raw), secret) {
		t.Fatal("secret in response")
	}
	status, _, _ = request("GET", "/api/v1/admin/overview", nil, "", "")
	check(status, 200)
	for _, route := range []string{"users", "devices", "audit"} {
		status, head, raw = request("GET", "/api/v1/admin/"+route, nil, "", "")
		check(status, 200)
		if head.Get("Cache-Control") != "no-store" || head.Get("Referrer-Policy") != "no-referrer" || strings.Contains(string(raw), secret) || strings.Contains(string(raw), session) || strings.Contains(string(raw), password) {
			t.Fatal("unsafe admin view")
		}
	}
	for _, query := range []string{"?limit=0", "?limit=101", "?limit=25&limit=1", "?after=invalid", "?token=secret", "?after=%zz", "?state=invalid"} {
		status, _, _ = request("GET", "/api/v1/admin/devices"+query, nil, "", "")
		check(status, 400)
	}
	status, _, raw = request("GET", "/api/v1/me", nil, "", "")
	check(status, 200)
	var me map[string]any
	json.Unmarshal(raw, &me)
	if me["role"] != "admin" || me["mode"] != "local-admin" {
		t.Fatal("identity")
	}
	status, _, _ = request("POST", "/api/v1/auth/recovery/consume", map[string]string{}, me["csrf_token"].(string), ts.URL)
	check(status, 404)
	status, _, _ = request("POST", "/api/v1/devices", map[string]string{}, me["csrf_token"].(string), ts.URL)
	check(status, 404)
	// Even copying the raw admin session into a user cookie cannot cross the separate database/router boundary.
	us, _ := auth.New(p, nil, 0, 0)
	public := New(Options{Host: host, Store: p, Auth: us})
	for _, path := range []string{"/api/v1/me", "/api/v1/admin/overview", "/api/v1/auth/admin/password", "/api/v1/admin/users", "/api/v1/admin/devices", "/api/v1/admin/audit"} {
		req := httptest.NewRequest("GET", "https://"+host+path, nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
		req.AddCookie(&http.Cookie{Name: adminSessionCookie, Value: session})
		w := httptest.NewRecorder()
		public.ServeHTTP(w, req)
		want := 404
		if path == "/api/v1/me" {
			want = 401
		}
		check(w.Code, want)
	}
	status, _, _ = request("POST", "/api/v1/auth/logout", map[string]string{}, me["csrf_token"].(string), ts.URL)
	check(status, 204)
	status, _, _ = request("GET", "/api/v1/admin/overview", nil, "", "")
	check(status, 401)
}
