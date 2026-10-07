// Package guides serves versioned, non-secret first-party instructions.
// Catalog verification metadata never grants access or changes profile state.
package guides

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/domain"
	"io"
	"regexp"
	"sort"
	"time"
	"unicode"
	"unicode/utf8"
)

//go:embed catalog.json
var embedded []byte
var ErrCatalog = errors.New("invalid instruction catalog")
var idPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

type Catalog struct{ items []domain.Instruction }

func safeText(s string, max int) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
func Load() (*Catalog, error) { return parse(embedded) }
func parse(data []byte) (*Catalog, error) {
	var file struct {
		Schema int                  `json:"schema"`
		Items  []domain.Instruction `json:"items"`
	}
	if len(data) > 128*1024 {
		return nil, ErrCatalog
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&file) != nil {
		return nil, ErrCatalog
	}
	if e := d.Decode(new(any)); !errors.Is(e, io.EOF) {
		return nil, ErrCatalog
	}
	if file.Schema != 1 || len(file.Items) == 0 || len(file.Items) > 100 {
		return nil, ErrCatalog
	}
	seen := map[string]bool{}
	for _, g := range file.Items {
		if !idPattern.MatchString(g.ID) || seen[g.ID] || g.ContentVersion < 1 || !safeText(g.Title, 128) || len(g.Steps) < 1 || len(g.Steps) > 20 || !g.OfflineAvailable {
			return nil, ErrCatalog
		}
		seen[g.ID] = true
		switch g.OS {
		case "ios", "android", "windows", "macos", "linux", "other":
		default:
			return nil, ErrCatalog
		}
		for _, step := range g.Steps {
			if !safeText(step, 1000) {
				return nil, ErrCatalog
			}
		}
		if g.Kind != "portal" && g.Kind != "vpn" {
			return nil, ErrCatalog
		}
		if g.Verified {
			if _, e := time.Parse("2006-01-02", g.VerifiedAt); e != nil {
				return nil, ErrCatalog
			}
			if g.Kind == "portal" {
				if g.VerificationScope != "portal" || g.Protocol != "" || g.AppID != "" || g.Format != "" {
					return nil, ErrCatalog
				}
			} else {
				if g.VerificationScope != "client" || g.AppID == "" || g.AppVersion == "" || g.Protocol == "" || g.Format == "" {
					return nil, ErrCatalog
				}
			}
		} else if g.VerifiedAt != "" || g.VerificationScope != "none" {
			return nil, ErrCatalog
		}
		if g.Protocol != "" && g.Protocol != "awg" && g.Protocol != "reality" {
			return nil, ErrCatalog
		}
		for _, v := range []string{g.AppID, g.AppVersion, g.Format} {
			if v != "" && !safeText(v, 64) {
				return nil, ErrCatalog
			}
		}
	}
	sort.Slice(file.Items, func(i, j int) bool {
		if file.Items[i].Kind != file.Items[j].Kind {
			return file.Items[i].Kind == "portal"
		}
		return file.Items[i].ID < file.Items[j].ID
	})
	return &Catalog{file.Items}, nil
}
func clone(g domain.Instruction) domain.Instruction {
	g.Steps = append([]string{}, g.Steps...)
	return g
}
func (c *Catalog) List() []domain.Instruction {
	out := make([]domain.Instruction, 0, len(c.items))
	for _, g := range c.items {
		out = append(out, clone(g))
	}
	return out
}
func (c *Catalog) Get(id string) (domain.Instruction, bool) {
	for _, g := range c.items {
		if g.ID == id {
			return clone(g), true
		}
	}
	return domain.Instruction{}, false
}
