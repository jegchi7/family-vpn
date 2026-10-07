package httpapi

import (
	"familyvpn.local/platform/internal/adapters/fake"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, host string
		admin                    bool
		want                     int
	}{
		{"list", "GET", "/api/v1/devices", "127.0.0.1:8080", false, 200},
		{"foreign device", "GET", "/api/v1/devices/dev-other", "127.0.0.1:8080", false, 404},
		{"foreign profile", "GET", "/api/v1/profiles/p-other/download", "127.0.0.1:8080", false, 404},
		{"unready profile", "GET", "/api/v1/profiles/p-laptop/download", "127.0.0.1:8080", false, 409},
		{"public admin", "GET", "/api/v1/admin/overview", "127.0.0.1:8080", false, 404},
		{"admin overview", "GET", "/api/v1/admin/overview", "127.0.0.1:8080", true, 200},
		{"mutation", "POST", "/api/v1/devices", "127.0.0.1:8080", false, 405},
		{"dns rebinding", "GET", "/api/v1/devices", "attacker.example", false, 403},
		{"format", "GET", "/api/v1/profiles/p-awg/download?format=conf", "127.0.0.1:8080", false, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := New(Options{Host: "127.0.0.1:8080", Admin: tc.admin})
			r := httptest.NewRequest(tc.method, tc.path, nil)
			r.Host = tc.host
			r.Header.Set("Cookie", "role=admin")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("cache enabled")
			}
			if tc.name == "list" && strings.Contains(w.Body.String(), "dev-other") {
				t.Fatal("ownership leak")
			}
		})
	}
}
func TestExpiryDoesNotRefreshOnRead(t *testing.T) {
	start := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	now := start
	h := New(Options{Host: "127.0.0.1:8080", Store: fake.New(start), Now: func() time.Time { return now }})
	now = start.Add(time.Minute)
	r := httptest.NewRequest("GET", "/api/v1/status", nil)
	r.Host = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), `"status":"healthy"`) {
		t.Fatal("expired fixture reported healthy")
	}
}
func TestDemoDownload(t *testing.T) {
	h := New(Options{Host: "127.0.0.1:8080"})
	r := httptest.NewRequest("GET", "/api/v1/profiles/p-awg/download", nil)
	r.Host = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "НЕ VPN-КОНФИГ") {
		t.Fatal("missing explicit demo marker")
	}
	if w.Header().Get("Content-Disposition") == "" {
		t.Fatal("not attachment")
	}
}
func TestListenRestrictions(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8080", "localhost:8080", "[::]:8080", "192.0.2.1:8080"} {
		if ValidateListen(addr) == nil {
			t.Fatalf("accepted %s", addr)
		}
	}
	if ValidateListen("127.0.0.1:8080") != nil {
		t.Fatal("rejected loopback")
	}
}
