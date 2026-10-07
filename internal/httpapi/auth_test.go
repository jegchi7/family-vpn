package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/guides"
	"familyvpn.local/platform/internal/store"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTLSAuthenticationBoundary(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "portal", "state.db")
	p, e := store.OpenPortal(ctx, dbPath, false)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if e = p.InitializeLocalAuth(ctx); e != nil {
		t.Fatal(e)
	}
	s, e := auth.New(p, nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	token, e := s.IssueInvite(ctx, "alice", "Alice", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	ts := httptest.NewUnstartedServer(nil)
	host := ts.Listener.Addr().String()
	catalog, _ := guides.Load()
	ts.Config.Handler = New(Options{Host: host, Store: p, Auth: s, Guides: catalog})
	ts.StartTLS()
	defer ts.Close()
	client := ts.Client()
	client.Jar, _ = cookiejar.New(nil)
	request := func(method, path, body, csrf, origin string) (int, http.Header, []byte) {
		t.Helper()
		req, e := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		if method == "POST" {
			req.Header.Set("Content-Type", "application/json")
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		b, e := io.ReadAll(resp.Body)
		if e != nil {
			t.Fatal(e)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("cache enabled")
		}
		return resp.StatusCode, resp.Header, b
	}
	check := func(got, want int) {
		t.Helper()
		if got != want {
			t.Fatalf("HTTP %d wanted %d", got, want)
		}
	}
	code, _, _ := request("GET", "/api/v1/devices", "", "", "")
	check(code, 401)
	code, _, _ = request("GET", "/api/v1/instructions/portal-ios/offline", "", "", "")
	check(code, 401)
	code, _, _ = request("GET", "/api/v1/admin/overview", "", "", "")
	check(code, 404)
	code, _, b := request("GET", "/api/v1/auth/bootstrap", "", "", "")
	check(code, 200)
	var bootstrap struct {
		CSRF string `json:"csrf_token"`
	}
	if e = json.Unmarshal(b, &bootstrap); e != nil {
		t.Fatal(e)
	}
	password := auth.RandomToken()
	body, _ := json.Marshal(map[string]string{"token": token, "password": password})
	for _, origin := range []string{"", "https://attacker.invalid", ts.URL + "/"} {
		code, _, _ = request("POST", "/api/v1/auth/invitations/accept", string(body), bootstrap.CSRF, origin)
		check(code, 403)
	}
	code, _, _ = request("POST", "/api/v1/auth/invitations/accept", string(body), "", ts.URL)
	check(code, 403)
	code, _, _ = request("POST", "/api/v1/auth/invitations/accept", string(body)+"{}", bootstrap.CSRF, ts.URL)
	check(code, 400)
	code, headers, b := request("POST", "/api/v1/auth/invitations/accept", string(body), bootstrap.CSRF, ts.URL)
	check(code, 200)
	var result auth.Result
	if e = json.Unmarshal(b, &result); e != nil {
		t.Fatal(e)
	}
	cookies := (&http.Response{Header: headers}).Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == sessionCookie {
			found = true
			if !c.HttpOnly || !c.Secure || c.Domain != "" || c.Path != "/" || c.SameSite != http.SameSiteLaxMode || !auth.ValidToken(c.Value) {
				t.Fatal("cookie flags")
			}
		}
	}
	if !found {
		t.Fatal("session cookie missing")
	}
	code, _, b = request("GET", "/api/v1/me", "", "", "")
	check(code, 200)
	if strings.Contains(string(b), token) || strings.Contains(string(b), password) {
		t.Fatal("credential leak")
	}
	code, _, b = request("GET", "/api/v1/devices", "", "", "")
	check(code, 200)
	if string(b) != "{\"items\":[]}\n" {
		t.Fatal("new account received devices")
	}
	code, guideHeaders, guideBytes := request("GET", "/api/v1/instructions/portal-ios/offline", "", "", "")
	check(code, 200)
	if guideHeaders.Get("Content-Type") != "text/html; charset=utf-8" || guideHeaders.Get("Content-Disposition") != `attachment; filename="family-vpn-guide-portal-ios-v1.html"` || guideHeaders.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("unsafe offline response headers")
	}
	if strings.Contains(string(guideBytes), token) || strings.Contains(string(guideBytes), password) || strings.Contains(string(guideBytes), result.ID) {
		t.Fatal("personalized offline content")
	}
	code, _, _ = request("GET", "/api/v1/instructions/missing/offline", "", "", "")
	check(code, 404)
	code, _, _ = request("GET", "/api/v1/instructions/portal-ios/offline?token=unexpected", "", "", "")
	check(code, 400)
	// Real SQLite records for two authenticated users prove HTTP uses session ownership.
	otherInvite, e := s.IssueInvite(ctx, "bob", "Bob", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	other, e := s.Accept(ctx, "127.0.0.1", otherInvite, auth.RandomToken())
	if e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", dbPath)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	for _, v := range []struct{ id, user string }{{"owned-device", result.ID}, {"dev-other", other.ID}} {
		if _, e = db.Exec("INSERT INTO devices(id,user_id,name,os,state,created_at) VALUES(?,?,?,'ios','active','2026-09-29T00:00:00Z')", v.id, v.user, v.id); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = db.Exec("INSERT INTO profiles(id,device_id,protocol,generation,state,format) VALUES('p-other','dev-other','awg',1,'ready','txt')"); e != nil {
		t.Fatal(e)
	}
	code, _, b = request("GET", "/api/v1/devices?user_id="+other.ID, "", "", "")
	check(code, 200)
	if !strings.Contains(string(b), "owned-device") || strings.Contains(string(b), "dev-other") {
		t.Fatal("HTTP session ownership leak")
	}
	code, _, _ = request("GET", "/api/v1/devices/owned-device", "", "", "")
	check(code, 200)
	for _, path := range []string{"/api/v1/devices/dev-other", "/api/v1/profiles/p-other/download", "/api/v1/admin/overview"} {
		code, _, _ = request("GET", path, "", "", "")
		check(code, 404)
	}
	code, _, _ = request("POST", "/api/v1/auth/logout", "{}", "", ts.URL)
	check(code, 403)
	code, _, _ = request("POST", "/api/v1/auth/session/touch", "{}", result.CSRF, ts.URL)
	check(code, 204)
	u, _ := url.Parse(ts.URL)
	oldCookies := client.Jar.Cookies(u)
	code, _, _ = request("POST", "/api/v1/auth/logout", "{}", result.CSRF, ts.URL)
	check(code, 204)
	code, _, _ = request("GET", "/api/v1/me", "", "", "")
	check(code, 401)
	// Replay the old session cookie after logout, not merely an empty jar.
	client.Jar.SetCookies(u, oldCookies)
	code, _, _ = request("GET", "/api/v1/me", "", "", "")
	check(code, 401)
	code, _, b = request("GET", "/api/v1/auth/bootstrap", "", "", "")
	check(code, 200)
	json.Unmarshal(b, &bootstrap)
	code, _, _ = request("POST", "/api/v1/auth/invitations/accept", string(body), bootstrap.CSRF, ts.URL)
	check(code, 401)
	loginBody, _ := json.Marshal(map[string]string{"login": "alice", "password": password})
	code, _, b = request("POST", "/api/v1/auth/login", string(loginBody), bootstrap.CSRF, ts.URL)
	check(code, 200)
	json.Unmarshal(b, &result)
	// Storage failures stay generic and no credentials are reflected.
	p.Close()
	code, _, b = request("GET", "/api/v1/me", "", "", "")
	check(code, 503)
	if strings.Contains(string(b), "database") || strings.Contains(string(b), password) {
		t.Fatal("unsafe storage error")
	}
}
func TestPlainHTTPAndHostRejectedForAuth(t *testing.T) {
	p, e := store.OpenPortal(context.Background(), filepath.Join(t.TempDir(), "portal", "state.db"), false)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	s, e := auth.New(p, nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	h := New(Options{Host: "127.0.0.1:8443", Store: p, Auth: s})
	for _, host := range []string{"127.0.0.1:8443", "attacker.invalid"} {
		r := httptest.NewRequest("GET", "/api/v1/auth/bootstrap", nil)
		r.Host = host
		r.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("plaintext/host bypass")
		}
	}
}
