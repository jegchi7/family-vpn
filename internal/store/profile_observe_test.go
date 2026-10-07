package store

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/profileobserve"
	"strings"
	"testing"
)

func observationPayload(t *testing.T) ([]byte, []byte) {
	t.Helper()
	client := awgImportPayload(t)
	server, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	lines := strings.Split(string(client), "\r\n")
	clientPublic := ""
	for i, line := range lines {
		if strings.HasPrefix(line, "PrivateKey = ") {
			b, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "PrivateKey = "))
			key, _ := ecdh.X25519().NewPrivateKey(b)
			clear(b)
			clientPublic = base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
		}
		if strings.HasPrefix(line, "PublicKey = ") {
			lines[i] = "PublicKey = " + base64.StdEncoding.EncodeToString(server.PublicKey().Bytes())
		}
	}
	client = []byte(strings.Join(lines, "\r\n"))
	iface := strings.Split(string(client), "[Peer]")[0]
	serverLines := []string{}
	for _, line := range strings.Split(iface, "\r\n") {
		if strings.HasPrefix(line, "Address = ") || strings.HasPrefix(line, "DNS = ") {
			continue
		}
		if strings.HasPrefix(line, "PrivateKey = ") {
			line = "PrivateKey = " + base64.StdEncoding.EncodeToString(server.Bytes())
		}
		serverLines = append(serverLines, line)
	}
	snapshot := []byte(strings.Join(serverLines, "\r\n") + "ListenPort = 443\r\n[Peer]\r\nPublicKey = " + clientPublic + "\r\nAdvancedSecurity = on\r\nAllowedIPs = 10.77.0.2/32\r\n")
	t.Cleanup(func() { clear(client); clear(snapshot) })
	return client, snapshot
}

func TestProfileObservationAtomicScopedAndPending(t *testing.T) {
	p, s, _, path := authStore(t)
	a, _ := enroll(t, s, "alice")
	b, _ := enroll(t, s, "bob")
	v := profileTestKey(t)
	p.InitializeProfileVault(ctx, v)
	d, _ := p.RequestDevice(ctx, a.ID, deviceInput())
	c := awgImportContext(a.ID, d)
	client, snapshot := observationPayload(t)
	if _, e := p.ImportClientProfile(ctx, v, c, 1, client, true); e != nil {
		t.Fatal(e)
	}
	ro, e := OpenPortal(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	plain, e := ro.LoadPendingAWGObservation(ctx, v, c, 2)
	if e != nil || !bytes.Equal(plain, client) {
		t.Fatal("readonly scoped read", e)
	}
	clear(plain)
	result, e := profileobserve.Snapshot(c, 2, client, snapshot, "edge.example.invalid:443")
	if e != nil || !result.Summary().PeerMatches {
		t.Fatal(e)
	}
	if e = p.RecordProfileObservation(ctx, v, c, 2, profileobserve.Target{Endpoint: "edge.example.invalid:443"}, profileobserve.Result{}); !errors.Is(e, profileobserve.ErrStale) {
		t.Fatal("forged empty result accepted", e)
	}
	wrong := c
	wrong.OwnerID = b.ID
	if e = p.RecordProfileObservation(ctx, v, wrong, 2, profileobserve.Target{Endpoint: "edge.example.invalid:443"}, result); !errors.Is(e, ErrNotFound) {
		t.Fatal("foreign result accepted", e)
	}
	p.db.Exec("CREATE TRIGGER deny_observation BEFORE INSERT ON audit_events WHEN NEW.action='profile.observe' BEGIN SELECT RAISE(ABORT,'test'); END")
	if e = p.RecordProfileObservation(ctx, v, c, 2, profileobserve.Target{Endpoint: "edge.example.invalid:443"}, result); e == nil {
		t.Fatal("audit failure committed")
	}
	var n int
	p.db.QueryRow("SELECT count(*) FROM profile_observations").Scan(&n)
	if n != 0 {
		t.Fatal("partial observation survived")
	}
	p.db.Exec("DROP TRIGGER deny_observation")
	if e = p.RecordProfileObservation(ctx, v, c, 2, profileobserve.Target{Endpoint: "edge.example.invalid:443"}, result); e != nil {
		t.Fatal(e)
	}
	if e = p.RecordProfileObservation(ctx, v, c, 2, profileobserve.Target{Endpoint: "edge.example.invalid:443"}, result); e != nil {
		t.Fatal("replay", e)
	}
	p.db.QueryRow("SELECT count(*) FROM profile_observations").Scan(&n)
	if n != 1 {
		t.Fatal("duplicated observation")
	}
	var source, fields string
	p.db.QueryRow("SELECT source,mismatched_fields FROM profile_observations").Scan(&source, &fields)
	if source != "awg-snapshot" || fields != "[]" {
		t.Fatal("source or safe fields corrupted")
	}
	if _, e = p.ReadReadyProfileSecret(ctx, v, a.ID, c.ProfileID); !errors.Is(e, domain.ErrDeviceState) {
		t.Fatal("observation published config", e)
	}
	var revision int
	var state string
	var installed *string
	p.db.QueryRow("SELECT d.revision,p.state,p.installed_revision FROM devices d JOIN profiles p ON p.device_id=d.id WHERE p.id=?", c.ProfileID).Scan(&revision, &state, &installed)
	if revision != 2 || state != "pending" || installed != nil {
		t.Fatal("readback changed access")
	}
	if _, e = p.RenameDevice(ctx, a.ID, d.ID, "Renamed", 2); e != nil {
		t.Fatal(e)
	}
	if e = p.RecordProfileObservation(ctx, v, c, 2, profileobserve.Target{Endpoint: "edge.example.invalid:443"}, result); !errors.Is(e, ErrConflict) {
		t.Fatal("stale result after rename accepted", e)
	}
	if e = p.RecordProfileObservation(ctx, v, c, 3, profileobserve.Target{Endpoint: "edge.example.invalid:443"}, result); !errors.Is(e, profileobserve.ErrStale) {
		t.Fatal("rebound old observation", e)
	}
}

func TestPortalObservationMigrationPreservesProfiles(t *testing.T) {
	p, s, _, path := authStore(t)
	u, _ := enroll(t, s, "alice")
	v := profileTestKey(t)
	p.InitializeProfileVault(ctx, v)
	d, _ := p.RequestDevice(ctx, u.ID, deviceInput())
	c := awgImportContext(u.ID, d)
	client, _ := observationPayload(t)
	if _, e := p.ImportClientProfile(ctx, v, c, 1, client, true); e != nil {
		t.Fatal(e)
	}
	var before []byte
	p.db.QueryRow("SELECT ciphertext FROM profiles WHERE id=?", c.ProfileID).Scan(&before)
	if _, e := p.db.Exec("DROP TABLE profile_observations; DELETE FROM schema_migrations WHERE version=6; PRAGMA user_version=5"); e != nil {
		t.Fatal(e)
	}
	p.Close()
	if old, e := OpenPortal(ctx, path, true); !errors.Is(e, ErrSchema) {
		if old != nil {
			old.Close()
		}
		t.Fatal("runtime accepted old schema", e)
	}
	upgraded, e := OpenPortal(ctx, path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer upgraded.Close()
	var after []byte
	upgraded.db.QueryRow("SELECT ciphertext FROM profiles WHERE id=?", c.ProfileID).Scan(&after)
	if !bytes.Equal(before, after) {
		t.Fatal("migration changed ciphertext")
	}
	plain, e := upgraded.LoadPendingAWGObservation(ctx, v, c, 2)
	defer clear(plain)
	if e != nil || !bytes.Equal(plain, client) {
		t.Fatal("migration lost binding/profile", e)
	}
}
