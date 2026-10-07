package store

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/profilevault"
	"strings"
	"sync"
	"testing"
)

func awgImportPayload(t *testing.T) []byte {
	t.Helper()
	client, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	server, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	header := make([]byte, 32)
	rand.Read(header)
	defer clear(header)
	b := []byte("# Synthetic; never a live client\r\n[Interface]\r\nPrivateKey = " + base64.StdEncoding.EncodeToString(client.Bytes()) + "\r\nAddress = 10.77.0.2/32\r\nDNS = 10.77.0.1\r\nJc = 3\r\nJmin = 40\r\nJmax = 70\r\nS1 = 16\r\nS2 = 16\r\nS3 = 16\r\nS4 = 16\r\nH1 = 1\r\nH2 = 2\r\nH3 = 3\r\nH4 = 4\r\nHeaderProtectionKey = " + base64.StdEncoding.EncodeToString(header) + "\r\nRandomTrailers = on\r\nDisableCookies = off\r\nContentPaddingAddition = 0-64\r\nI1 = <r 20><t>\r\n[Peer]\r\nPublicKey = " + base64.StdEncoding.EncodeToString(server.PublicKey().Bytes()) + "\r\nEndpoint = edge.example.invalid:443\r\nAllowedIPs = 0.0.0.0/0\r\nPersistentKeepalive = 20-30\r\n")
	t.Cleanup(func() { clear(b) })
	return b
}
func awgImportContext(owner string, d domain.Device) profilevault.Context {
	for _, p := range d.Profiles {
		if p.Protocol == "awg" {
			return profilevault.Context{ProfileID: p.ID, DeviceID: d.ID, OwnerID: owner, Protocol: "awg", Generation: 1, Format: clientconfig.AWG31Conf}
		}
	}
	panic("no AWG slot")
}

func TestAWGImportRoundTripRotationAndPendingGate(t *testing.T) {
	p, s, _, path := authStore(t)
	u, _ := enroll(t, s, "alice")
	b, _ := enroll(t, s, "bob")
	v := profileTestKey(t)
	if e := p.InitializeProfileVault(ctx, v); e != nil {
		t.Fatal(e)
	}
	d, _ := p.RequestDevice(ctx, u.ID, deviceInput())
	c, data := awgImportContext(u.ID, d), awgImportPayload(t)
	ro, e := OpenPortal(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	if _, e = ro.ImportClientProfile(ctx, v, c, 1, data, false); e != nil {
		t.Fatal("read-only AWG dry run", e)
	}
	if n, e := p.CheckProfileVault(ctx, v); n != 0 || e != nil {
		t.Fatal("dry run wrote secret", e)
	}
	wrong := c
	wrong.OwnerID = b.ID
	if _, e = p.ImportClientProfile(ctx, v, wrong, 1, data, true); !errors.Is(e, ErrNotFound) {
		t.Fatal("foreign owner accepted", e)
	}
	wrong = c
	wrong.Protocol = "reality"
	if _, e = p.ImportClientProfile(ctx, v, wrong, 1, data, true); !errors.Is(e, profilevault.ErrInput) {
		t.Fatal("protocol mismatch accepted", e)
	}
	p.db.Exec("CREATE TRIGGER fail_awg_import BEFORE INSERT ON audit_events WHEN NEW.action='profile.stage' BEGIN SELECT RAISE(ABORT,'test'); END")
	if _, e = p.ImportClientProfile(ctx, v, c, 1, data, true); e == nil {
		t.Fatal("audit failure committed")
	}
	p.db.Exec("DROP TRIGGER fail_awg_import")
	if n, e := p.CheckProfileVault(ctx, v); n != 0 || e != nil {
		t.Fatal("rollback left ciphertext", e)
	}
	if _, e = p.ImportClientProfile(ctx, v, c, 1, data, true); e != nil {
		t.Fatal(e)
	}
	if replay, e := p.ImportClientProfile(ctx, v, c, 1, data, true); e != nil || !replay.AlreadyStored {
		t.Fatal("AWG replay", e)
	}
	if _, e = p.ImportClientProfile(ctx, v, c, 2, bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")), true); !errors.Is(e, ErrConflict) {
		t.Fatal("byte-different repeat overwrote export", e)
	}
	newKey := profileTestKey(t)
	if _, e = p.RotateProfileVault(ctx, v, newKey); e != nil {
		t.Fatal(e)
	}
	tx, _ := p.db.BeginTx(ctx, nil)
	actual, envelope, e := secretFromTx(ctx, tx, c.ProfileID)
	tx.Rollback()
	if e != nil {
		t.Fatal(e)
	}
	plain, e := newKey.Open(actual, envelope)
	defer clear(plain)
	if e != nil || !bytes.Equal(plain, data) {
		t.Fatal("rotation changed AWG fields/comments/line endings", e)
	}
	if _, e = v.Open(actual, envelope); !errors.Is(e, profilevault.ErrKey) {
		t.Fatal("old key still opens export")
	}
	if _, e = p.ReadReadyProfileSecret(ctx, newKey, u.ID, c.ProfileID); !errors.Is(e, domain.ErrDeviceState) {
		t.Fatal("AWG import falsely ready", e)
	}
}

func TestAWGPublicIdentityConflictAcrossHandles(t *testing.T) {
	p, s, _, path := authStore(t)
	a, _ := enroll(t, s, "alice")
	b, _ := enroll(t, s, "bob")
	v := profileTestKey(t)
	p.InitializeProfileVault(ctx, v)
	da, _ := p.RequestDevice(ctx, a.ID, deviceInput())
	db, _ := p.RequestDevice(ctx, b.ID, deviceInput())
	data := awgImportPayload(t)
	lines := strings.Split(string(data), "\r\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "PrivateKey = ") {
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "PrivateKey = "))
			raw[0] ^= 7
			raw[31] ^= 128
			lines[i] = "PrivateKey = " + base64.StdEncoding.EncodeToString(raw)
			clear(raw)
		}
	}
	equivalent := []byte(strings.Join(lines, "\r\n"))
	defer clear(equivalent)
	other, e := OpenExistingPortal(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 2)
	for i, target := range []profilevault.Context{awgImportContext(a.ID, da), awgImportContext(b.ID, db)} {
		wg.Add(1)
		go func(index int, c profilevault.Context) {
			defer wg.Done()
			<-start
			store, payload := p, data
			if index == 1 {
				store, payload = other, equivalent
			}
			_, e := store.ImportClientProfile(ctx, v, c, 1, payload, true)
			errs <- e
		}(i, target)
	}
	close(start)
	wg.Wait()
	close(errs)
	success, conflict := 0, 0
	for e := range errs {
		if e == nil {
			success++
		} else if errors.Is(e, ErrClientCredentialConflict) {
			conflict++
		} else {
			t.Fatal("unexpected writer result", e)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("equivalent AWG identity assigned twice")
	}
}
