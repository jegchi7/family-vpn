package store

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/profilevault"
	"net/url"
	"testing"
)

func TestPreflightReadOnlyBindingsAndPending(t *testing.T) {
	p, s, _, path := authStore(t)
	a, _ := enroll(t, s, "alice")
	b, _ := enroll(t, s, "bob")
	v := profileTestKey(t)
	p.InitializeProfileVault(ctx, v)
	d, _ := p.RequestDevice(ctx, a.ID, deviceInput())
	c := importContext(a.ID, d)
	payload := importPayload(t)
	u, _ := url.Parse(string(bytes.TrimSpace(payload)))
	pair, _ := ecdh.X25519().GenerateKey(rand.Reader)
	q := u.Query()
	q.Set("pbk", base64.RawURLEncoding.EncodeToString(pair.PublicKey().Bytes()))
	u.RawQuery = q.Encode()
	payload = []byte(u.String())
	defer clear(payload)
	_, e := p.ImportClientProfile(ctx, v, c, 1, payload, true)
	if e != nil {
		t.Fatal(e)
	}
	server, _ := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"tag": "clients", "protocol": "vless", "port": 443, "settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": u.User.Username(), "flow": "xtls-rprx-vision"}}}, "streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"target": "cover.example.invalid:443", "serverNames": []string{"cover.example.invalid"}, "shortIds": []string{""}, "privateKey": base64.RawURLEncoding.EncodeToString(pair.Bytes())}}}}})
	defer clear(server)
	sum := sha256.Sum256(server)
	pin := hex.EncodeToString(sum[:])
	ro, e := OpenPortal(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	var before, after int
	p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&before)
	fields, e := ro.PreflightClientProfile(ctx, v, c, 2, server, "clients", "edge.example.invalid:443", pin)
	if e != nil || len(fields) != 0 {
		t.Fatal("readonly comparison", e, fields)
	}
	p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&after)
	if before != after {
		t.Fatal("preview mutated audit")
	}
	var state string
	var installed *string
	var revision int
	p.db.QueryRow("SELECT p.state,p.installed_revision,d.revision FROM profiles p JOIN devices d ON d.id=p.device_id WHERE p.id=?", c.ProfileID).Scan(&state, &installed, &revision)
	if state != "pending" || installed != nil || revision != 2 {
		t.Fatal("preview published access")
	}
	wrong := c
	wrong.OwnerID = b.ID
	if _, e = ro.PreflightClientProfile(ctx, v, wrong, 2, server, "clients", "edge.example.invalid:443", pin); !errors.Is(e, ErrNotFound) {
		t.Fatal("foreign binding", e)
	}
	wrong = c
	wrong.Generation++
	if _, e = ro.PreflightClientProfile(ctx, v, wrong, 2, server, "clients", "edge.example.invalid:443", pin); !errors.Is(e, ErrNotFound) {
		t.Fatal("generation binding", e)
	}
	if _, e = ro.PreflightClientProfile(ctx, v, c, 1, server, "clients", "edge.example.invalid:443", pin); !errors.Is(e, ErrConflict) {
		t.Fatal("stale preview", e)
	}
	if _, e = ro.PreflightClientProfile(ctx, profileTestKey(t), c, 2, server, "clients", "edge.example.invalid:443", pin); !errors.Is(e, profilevault.ErrKey) {
		t.Fatal("wrong key", e)
	}
	p.db.Exec("UPDATE users SET state='disabled' WHERE id=?", a.ID)
	if _, e = ro.PreflightClientProfile(ctx, v, c, 2, server, "clients", "edge.example.invalid:443", pin); !errors.Is(e, ErrNotFound) {
		t.Fatal("inactive owner", e)
	}
}
