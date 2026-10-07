package guides

import (
	"encoding/json"
	"familyvpn.local/platform/internal/domain"
	"strings"
	"testing"
)

func TestCatalogVerificationScopeAndIsolation(t *testing.T) {
	c, e := Load()
	if e != nil {
		t.Fatal(e)
	}
	items := c.List()
	if len(items) != 12 {
		t.Fatal("missing catalog entries")
	}
	for _, g := range items {
		if g.Kind == "vpn" && g.Verified {
			t.Fatal("untested client declared verified")
		}
		if g.Kind == "portal" && (!g.Verified || g.VerificationScope != "portal") {
			t.Fatal("portal scope missing")
		}
	}
	items[0].Steps[0] = "changed"
	again := c.List()
	if again[0].Steps[0] == "changed" {
		t.Fatal("catalog mutable through list")
	}
	got, _ := c.Get(items[0].ID)
	got.Steps[0] = "changed"
	again = c.List()
	if again[0].Steps[0] == "changed" {
		t.Fatal("catalog mutable through getter")
	}
	if _, ok := c.Get("../secret"); ok {
		t.Fatal("unknown ID accepted")
	}
}
func TestCatalogRejectsInvalidClaimsAndMetadata(t *testing.T) {
	for _, field := range []string{"id", "version", "future_schema", "duplicate_id", "bad_date", "scope", "client_claim", "control", "unknown"} {
		t.Run(field, func(t *testing.T) {
			c, _ := Load()
			g, _ := c.Get("portal-ios")
			items := []domain.Instruction{g}
			schema := 1
			switch field {
			case "id":
				g.ID = "../path"
			case "version":
				g.ContentVersion = 0
			case "future_schema":
				schema = 2
			case "duplicate_id":
				items = append(items, g)
			case "bad_date":
				g.VerifiedAt = "2026-02-30"
			case "scope":
				g.VerificationScope = "client"
			case "client_claim":
				g.Kind = "vpn"
				g.VerificationScope = "client"
			case "control":
				g.Steps = []string{"unsafe\x00text"}
			}
			items[0] = g
			data, _ := json.Marshal(map[string]any{"schema": schema, "items": items})
			if field == "unknown" {
				data = []byte(`{"schema":1,"items":[],"extra":true}`)
			}
			if _, e := parse(data); e == nil {
				t.Fatal("invalid catalog accepted")
			}
		})
	}
}
func TestOfflineIsSelfContainedAndEscapesHTML(t *testing.T) {
	c, _ := Load()
	g, _ := c.Get("portal-ios")
	g.Title = "<script>alert(1)</script>"
	g.Steps = []string{`<img src="https://tracker.invalid" onerror="alert(1)">`}
	b, e := Render(g)
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	if strings.Contains(s, "<script>") || strings.Contains(s, "<img ") || strings.Contains(s, "<link ") || strings.Contains(s, "<iframe") || strings.Contains(s, "src=\"https://") {
		t.Fatal("executable/external HTML")
	}
	if !strings.Contains(s, "&lt;script&gt;") || !strings.Contains(s, "default-src &#39;none&#39;") && !strings.Contains(s, "default-src 'none'") {
		t.Fatal("escaping or offline CSP missing")
	}
}
