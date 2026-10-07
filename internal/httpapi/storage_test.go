package httpapi

import (
	"context"
	"familyvpn.local/platform/internal/store"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSQLiteAPIAndUnavailable(t *testing.T) {
	p, e := store.OpenPortal(context.Background(), filepath.Join(t.TempDir(), "portal", "state.db"), false)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if e = p.SeedDemo(context.Background(), time.Now()); e != nil {
		t.Fatal(e)
	}
	h := New(Options{Host: "127.0.0.1:8080", Store: p})
	for _, tc := range []struct {
		path string
		want int
	}{{"/api/v1/devices", 200}, {"/api/v1/profiles/p-other/download", 404}, {"/api/v1/admin/overview", 404}, {"/readyz", 200}} {
		r := httptest.NewRequest("GET", tc.path, nil)
		r.Host = "127.0.0.1:8080"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body.String())
		}
	}
	p.Close()
	r := httptest.NewRequest("GET", "/api/v1/devices", nil)
	r.Host = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "STORAGE_UNAVAILABLE") || strings.Contains(w.Body.String(), "database is closed") {
		t.Fatal("unsafe storage failure", w.Code, w.Body.String())
	}
}
