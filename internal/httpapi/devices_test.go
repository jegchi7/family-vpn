package httpapi

import (
	"context"
	"encoding/json"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/store"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeviceHTTPBoundary(t *testing.T) {
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
	makeUser := func(login string) auth.Result {
		t.Helper()
		token, e := s.IssueInvite(ctx, login, login, time.Hour)
		if e != nil {
			t.Fatal(e)
		}
		u, e := s.Accept(ctx, "ip", token, auth.RandomToken())
		if e != nil {
			t.Fatal(e)
		}
		return u
	}
	alice, bob := makeUser("alice"), makeUser("bob")
	h := New(Options{Host: "127.0.0.1:8443", Store: p, Auth: s, Devices: p})
	request := func(method, path string, in any, user auth.Result, origin, csrf string) *httptest.ResponseRecorder {
		t.Helper()
		b, _ := json.Marshal(in)
		r := httptest.NewRequest(method, "https://127.0.0.1:8443"+path, strings.NewReader(string(b)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		r.Header.Set("X-CSRF-Token", csrf)
		if user.Token != "" {
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: user.Token})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	origin := "https://127.0.0.1:8443"
	in := domain.DeviceRequest{RequestID: auth.RandomToken(), Name: "iPhone", OS: "ios"}
	check := func(w *httptest.ResponseRecorder, want int) {
		t.Helper()
		if w.Code != want {
			t.Fatalf("status %d want %d", w.Code, want)
		}
	}
	check(request("POST", "/api/v1/devices", in, auth.Result{}, origin, ""), 401)
	check(request("POST", "/api/v1/devices", in, alice, "https://other.invalid", alice.CSRF), 403)
	check(request("POST", "/api/v1/devices", in, alice, origin, ""), 403)
	check(request("POST", "/api/v1/devices", map[string]any{"owner_id": bob.ID, "request_id": in.RequestID, "name": in.Name, "os": in.OS}, alice, origin, alice.CSRF), 400)
	w := request("POST", "/api/v1/devices", in, alice, origin, alice.CSRF)
	check(w, 200)
	var d domain.Device
	if e = json.Unmarshal(w.Body.Bytes(), &d); e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{d.ID, "missing"} {
		check(request("POST", "/api/v1/devices/"+id+"/rename", map[string]any{"name": "new", "expected_revision": 1}, bob, origin, bob.CSRF), 404)
		check(request("POST", "/api/v1/devices/"+id+"/cancel", map[string]int{"expected_revision": 1}, bob, origin, bob.CSRF), 404)
	}
	check(request("GET", "/api/v1/profiles/"+d.Profiles[0].ID+"/download", nil, alice, "", ""), 409)
	check(request("GET", "/api/v1/profiles/"+d.Profiles[0].ID+"/download", nil, bob, "", ""), 404)
	check(request("POST", "/api/v1/devices/"+d.ID+"/rename", map[string]any{"name": "new", "expected_revision": 1}, alice, origin, alice.CSRF), 200)
	check(request("POST", "/api/v1/devices/"+d.ID+"/rename", map[string]any{"name": "stale", "expected_revision": 1}, alice, origin, alice.CSRF), 409)
	check(request("POST", "/api/v1/devices/"+d.ID+"/cancel", map[string]int{"expected_revision": 2}, alice, origin, alice.CSRF), 200)
	w = request("GET", "/api/v1/devices/quota", nil, alice, "", "")
	check(w, 200)
	var q domain.DeviceQuota
	json.Unmarshal(w.Body.Bytes(), &q)
	if q.Used != 0 {
		t.Fatal("quota stale")
	}
	// Demo remains read only even though the same binary can serve authenticated device requests.
	demo := New(Options{Host: "127.0.0.1:8080"})
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/v1/devices", nil)
	out := httptest.NewRecorder()
	demo.ServeHTTP(out, r)
	check(out, 405)
}
