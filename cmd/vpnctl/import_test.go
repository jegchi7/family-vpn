package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/profilevault"
	"familyvpn.local/platform/internal/store"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestProfileImportCLISafeReportsAndDefaultDryRun(t *testing.T) {
	for _, format := range []string{clientconfig.VLESSRealityURI, clientconfig.AWG31Conf} {
		t.Run(format, func(t *testing.T) { testProfileImportCLI(t, format) })
	}
}
func testProfileImportCLI(t *testing.T, format string) {
	ctx := context.Background()
	base := t.TempDir()
	root := filepath.Join(base, "state")
	key := filepath.Join(base, "keys", "client.key")
	os.Mkdir(filepath.Dir(key), 0700)
	if e := profilevault.CreateKey(key); e != nil {
		t.Fatal(e)
	}
	v, e := profilevault.LoadKey(key)
	if e != nil {
		t.Fatal(e)
	}
	p, e := store.OpenPortal(ctx, filepath.Join(root, "portal", "state.db"), false)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	p.InitializeLocalAuth(ctx)
	p.InitializeProfileVault(ctx, v)
	s, e := auth.New(p, nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	token, e := s.IssueInvite(ctx, "alice", "Test", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	u, e := s.Accept(ctx, "ip", token, auth.RandomToken())
	if e != nil {
		t.Fatal(e)
	}
	d, e := p.RequestDevice(ctx, u.ID, domain.DeviceRequest{RequestID: auth.RandomToken(), Name: "Phone", OS: "ios"})
	if e != nil {
		t.Fatal(e)
	}
	var id string
	for _, profile := range d.Profiles {
		if (format == clientconfig.VLESSRealityURI && profile.Protocol == "reality") || (format == clientconfig.AWG31Conf && profile.Protocol == "awg") {
			id = profile.ID
		}
	}
	b := make([]byte, 16)
	rand.Read(b)
	h := hex.EncodeToString(b)
	clear(b)
	uuid := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	pair, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	pbk := base64.RawURLEncoding.EncodeToString(pair.PublicKey().Bytes())
	uri := []byte("vless://" + uuid + "@edge.example.invalid:443?type=tcp&security=reality&fp=chrome&flow=xtls-rprx-vision&sni=cover.example.invalid&pbk=" + pbk + "&sid=00#Test\n")
	if format == clientconfig.AWG31Conf {
		uuid = base64.StdEncoding.EncodeToString(pair.Bytes())
		pbk = base64.StdEncoding.EncodeToString(pair.PublicKey().Bytes())
		uri = []byte("[Interface]\nPrivateKey = " + uuid + "\nAddress = 10.77.0.2/32\nDNS = 10.77.0.1\nJc = 3\nJmin = 40\nJmax = 70\nS1 = 16\nS2 = 16\nS3 = 16\nS4 = 16\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nHeaderProtectionKey = " + pbk + "\n[Peer]\nPublicKey = " + pbk + "\nEndpoint = edge.example.invalid:443\nAllowedIPs = 0.0.0.0/0\n")
	}
	defer clear(uri)
	args := []string{"--root", root, "--profile-key", key, "--owner-id", u.ID, "--device-id", d.ID, "--profile-id", id, "--generation", "1", "--expected-revision", strconv.Itoa(d.Revision), "--format", format}
	invoke := func(extra []string, input []byte, want string) {
		t.Helper()
		out := new(bytes.Buffer)
		e := runProfileImport(append(append([]string{}, args...), extra...), bytes.NewReader(input), out)
		var report map[string]any
		if json.Unmarshal(out.Bytes(), &report) != nil {
			t.Fatal("missing JSON report")
		}
		if bytes.Contains(out.Bytes(), uri) || bytes.Contains(out.Bytes(), []byte(uuid)) || bytes.Contains(out.Bytes(), []byte(pbk)) {
			t.Fatal("report echoed secrets")
		}
		if e != nil && (bytes.Contains([]byte(e.Error()), []byte(uuid)) || bytes.Contains([]byte(e.Error()), []byte(pbk))) {
			t.Fatal("error echoed secrets")
		}
		if report["ready"] != false || report["peers_verified"] != false {
			t.Fatal("false readiness")
		}
		if report["outcome"] != want && report["code"] != want {
			t.Fatal("unexpected report code")
		}
		if (report["status"] == "error") != (e != nil) {
			t.Fatal("exit/report mismatch")
		}
	}
	invoke(nil, uri, "would-import")
	invoke([]string{"--dry-run"}, uri, "would-import")
	if n, e := p.CheckProfileVault(ctx, v); e != nil || n != 0 {
		t.Fatal("default mutated DB", e)
	}
	invoke([]string{"--apply"}, uri, "imported-pending")
	invoke([]string{"--apply"}, uri, "already-stored")
	invoke([]string{"--apply", "--dry-run"}, uri, "INVALID_TARGET")
	invoke(nil, []byte("ssh://root:password@host.invalid"), "INVALID_EXPORT")
	invoke([]string{"--format", "awg-conf"}, uri, "UNSUPPORTED_FORMAT")
	invoke([]string{"--profile-id", "missing"}, uri, "TARGET_NOT_FOUND")
	invoke([]string{"--unexpected", string(uri)}, uri, "INVALID_TARGET")
	targets := new(bytes.Buffer)
	if e = runProfileTargets([]string{"--root", root, "--login", "alice", "--device-id", d.ID}, targets); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(targets.Bytes(), []byte(uuid)) || bytes.Contains(targets.Bytes(), []byte(pbk)) {
		t.Fatal("targets leaked secret")
	}
	private := filepath.Join(base, "input")
	os.Mkdir(private, 0700)
	file := filepath.Join(private, "client.txt")
	os.WriteFile(file, uri, 0600)
	invoke([]string{"--input", file}, nil, "already-stored")
	os.Chmod(file, 0644)
	invoke([]string{"--input", file}, nil, "INPUT_SOURCE")
}
