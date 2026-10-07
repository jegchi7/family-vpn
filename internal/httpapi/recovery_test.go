package httpapi

import (
	"context"
	"encoding/json"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/store"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecoveryHTTPBoundary(t *testing.T) {
	ctx := context.Background()
	p, e := store.OpenPortal(ctx, filepath.Join(t.TempDir(), "portal", "state.db"), false)
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
	invite, e := s.IssueInvite(ctx, "alice", "Alice", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	oldPassword := auth.RandomToken()
	old, e := s.Accept(ctx, "local-test", invite, oldPassword)
	if e != nil {
		t.Fatal(e)
	}
	recovery, e := s.IssueRecovery(ctx, "alice", auth.RecoveryTTL)
	if e != nil {
		t.Fatal(e)
	}
	ts := httptest.NewUnstartedServer(nil)
	host := ts.Listener.Addr().String()
	ts.Config.Handler = New(Options{Host: host, Store: p, Auth: s})
	ts.StartTLS()
	defer ts.Close()
	client := ts.Client()
	client.Jar, _ = cookiejar.New(nil)
	type result struct {
		code   int
		header http.Header
		body   []byte
	}
	request := func(method, path, body, csrf, origin, contentType string) result {
		t.Helper()
		r, e := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Origin", origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Content-Type", contentType)
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		b, e := io.ReadAll(response.Body)
		if e != nil {
			t.Fatal(e)
		}
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("recovery response cached")
		}
		for _, secret := range []string{recovery, oldPassword, old.Token} {
			if strings.Contains(string(b), secret) {
				t.Fatal("secret reflected")
			}
		}
		return result{response.StatusCode, response.Header, b}
	}
	check := func(r result, want int) {
		t.Helper()
		if r.code != want {
			t.Fatalf("HTTP %d wanted %d", r.code, want)
		}
	}
	bootstrap := func() string {
		t.Helper()
		r := request("GET", "/api/v1/auth/bootstrap", "", "", "", "")
		check(r, 200)
		var b struct {
			CSRF string `json:"csrf_token"`
		}
		if e = json.Unmarshal(r.body, &b); e != nil {
			t.Fatal(e)
		}
		return b.CSRF
	}
	csrf := bootstrap()
	newPassword := auth.RandomToken()
	body, _ := json.Marshal(map[string]string{"token": recovery, "new_password": newPassword})
	path := "/api/v1/auth/recovery/consume"
	check(request("POST", path, string(body), "", ts.URL, "application/json"), 403)
	check(request("POST", path, string(body), csrf, "https://attacker.invalid", "application/json"), 403)
	check(request("POST", path, string(body), csrf, ts.URL, "text/plain"), 415)
	check(request("POST", path, string(body)+"{}", csrf, ts.URL, "application/json"), 400)
	oversized, _ := json.Marshal(map[string]string{"token": recovery, "new_password": strings.Repeat("x", 65537)})
	check(request("POST", path, string(oversized), csrf, ts.URL, "application/json"), 400)
	check(request("POST", path+"?token=not-a-secret", string(body), csrf, ts.URL, "application/json"), 400)
	r := request("POST", path, string(body), csrf, ts.URL, "application/json")
	check(r, 204)
	if len(r.body) != 0 {
		t.Fatal("recovery returned session data")
	}
	for _, c := range (&http.Response{Header: r.header}).Cookies() {
		if c.Value != "" || c.MaxAge != -1 || !c.Secure || !c.HttpOnly {
			t.Fatal("recovery issued cookie instead of clearing it")
		}
	}
	check(request("GET", "/api/v1/me", "", "", "", ""), 401)
	csrf = bootstrap()
	check(request("POST", path, string(body), csrf, ts.URL, "application/json"), 401)
	loginBody, _ := json.Marshal(map[string]string{"login": "alice", "password": oldPassword})
	check(request("POST", "/api/v1/auth/login", string(loginBody), csrf, ts.URL, "application/json"), 401)
	loginBody, _ = json.Marshal(map[string]string{"login": "alice", "password": newPassword})
	check(request("POST", "/api/v1/auth/login", string(loginBody), csrf, ts.URL, "application/json"), 200)
	check(request("GET", "/api/v1/admin/overview", "", "", "", ""), 404)
	// There is no anonymous issuance endpoint and no public admin reset endpoint.
	check(request("GET", "/api/v1/auth/recovery/request", "", "", "", ""), 404)
}
