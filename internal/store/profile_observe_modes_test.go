package store

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/profileobserve"
	"reflect"
	"strings"
	"testing"
)

func replaceObservationField(data []byte, name, value string) []byte {
	lines := strings.Split(string(data), "\r\n")
	for i, line := range lines {
		if strings.HasPrefix(line, name+" = ") {
			lines[i] = name + " = " + value
		}
	}
	return []byte(strings.Join(lines, "\r\n"))
}

func TestFullAWGConflictRoundTripsThroughLedgerAndReadiness(t *testing.T) {
	p, authStore, _, path := authStore(t)
	u, _ := enroll(t, authStore, "alice")
	v := profileTestKey(t)
	if e := p.InitializeProfileVault(ctx, v); e != nil {
		t.Fatal(e)
	}
	d, e := p.RequestDevice(ctx, u.ID, deviceInput())
	if e != nil {
		t.Fatal(e)
	}
	c := awgImportContext(u.ID, d)
	client, snapshot := observationPayload(t)
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	enc := base64.StdEncoding.EncodeToString
	// Use real comparison output, not a manufactured list of mismatch names.
	// All private material exists only in test memory and temporary encrypted DB.
	client = append(bytes.Clone(client), []byte("PresharedKey = "+enc(key.Bytes())+"\r\n")...)
	defer clear(client)
	for name, value := range map[string]string{"ListenPort": "444", "PrivateKey": enc(key.Bytes()), "HeaderProtectionKey": enc(key.Bytes()), "S1": "20", "S2": "20", "S3": "20", "S4": "20", "H1": "11", "H2": "12", "H3": "13", "H4": "14", "RandomTrailers": "off", "DisableCookies": "on", "AdvancedSecurity": "off", "AllowedIPs": "10.77.0.3/32"} {
		next := replaceObservationField(snapshot, name, value)
		clear(snapshot)
		snapshot = next
	}
	snapshot = append(snapshot, []byte("[Peer]\r\nPublicKey = "+enc(key.PublicKey().Bytes())+"\r\nAllowedIPs = 10.77.0.0/24\r\n")...)
	defer clear(snapshot)
	if _, e = p.ImportClientProfile(ctx, v, c, 1, client, true); e != nil {
		t.Fatal(e)
	}
	result, e := profileobserve.Snapshot(c, 2, client, snapshot, "edge.example.invalid:443")
	if e != nil {
		t.Fatal(e)
	}
	fields := result.Summary().MismatchedFields
	if len(fields) != 17 || !clientconfig.ValidAWGMismatchFields(fields) {
		t.Fatal("full comparison lost a conflict", len(fields))
	}
	if e = p.RecordProfileObservation(ctx, v, c, 2, profileobserve.Target{Endpoint: "edge.example.invalid:443"}, result); e != nil {
		t.Fatal(e)
	}
	ro, e := OpenPortal(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	r, e := ro.ProfileReadiness(ctx, ReadinessTarget{u.ID, d.ID, c.ProfileID, 1, 2})
	if e != nil || r.Observation == nil || r.Observation.Status != "conflict" || !reflect.DeepEqual(fields, r.Observation.MismatchedFields) || r.Ready || r.StoredRuntimeReadbackFresh || r.ClientsVerified || r.SecretVerified {
		t.Fatal("stored comparison lost full conflict or allowed access", e)
	}
	if _, e = p.ReadReadyProfileSecret(ctx, v, u.ID, c.ProfileID); !errors.Is(e, domain.ErrDeviceState) {
		t.Fatal("comparison published access", e)
	}
	out, _ := json.Marshal(r)
	for _, secret := range [][]byte{client, snapshot, []byte(enc(key.Bytes()))} {
		if bytes.Contains(out, secret) {
			t.Fatal("report leaked comparison input")
		}
	}
	var revision, audits int
	var state string
	var installed *string
	if e = p.db.QueryRow("SELECT d.revision,p.state,p.installed_revision FROM devices d JOIN profiles p ON p.device_id=d.id WHERE p.id=?", c.ProfileID).Scan(&revision, &state, &installed); e != nil || revision != 2 || state != "pending" || installed != nil {
		t.Fatal("conflict changed readiness state", e)
	}
	if e = p.db.QueryRow("SELECT count(*) FROM audit_events WHERE action='profile.observe'").Scan(&audits); e != nil || audits != 1 {
		t.Fatal("observation audit missing or diagnostic mutated audit", e)
	}
}

func TestAWGMismatchMetadataVocabularyAndRedaction(t *testing.T) {
	fields := []string{"endpoint", "server_key", "header_protection", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "randomtrailers", "disablecookies", "address_conflict", "peer_missing", "preshared_key", "peer_addresses", "advanced_security"}
	for _, valid := range [][]string{fields, {}, {"advanced_security"}} {
		raw, _ := json.Marshal(valid)
		out, e := observationFields(string(raw), len(valid) == 0)
		if e != nil || !reflect.DeepEqual(out, valid) {
			t.Fatal("safe bounded vocabulary rejected", e)
		}
	}
	for _, invalid := range [][]string{nil, {"advanced_security", "advanced_security"}, {"raw-sensitive-value"}, append(append([]string{}, fields...), "endpoint")} {
		raw, _ := json.Marshal(invalid)
		if _, e := observationFields(string(raw), false); !errors.Is(e, profileobserve.ErrObservation) || strings.Contains(e.Error(), "raw-sensitive-value") {
			t.Fatal("unsafe metadata accepted or echoed")
		}
	}
	if _, e := observationFields(`["advanced_security"]`, true); !errors.Is(e, profileobserve.ErrObservation) {
		t.Fatal("matched result accepted conflicting fields")
	}
}
