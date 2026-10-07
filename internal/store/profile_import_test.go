package store

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/profilevault"
	"sync"
	"testing"
)

func importPayload(t *testing.T) []byte {
	t.Helper()
	id := make([]byte, 16)
	rand.Read(id)
	h := hex.EncodeToString(id)
	clear(id)
	uuid := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	b := []byte("vless://" + uuid + "@edge.example.invalid:443?fp=chrome&security=reality&type=tcp&flow=xtls-rprx-vision&sni=cover.example.invalid&pbk=" + base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()) + "&sid=&spx=%2Fa%3Fb%3D1#Test\r\n")
	t.Cleanup(func() { clear(b) })
	return b
}
func importContext(owner string, d domain.Device) profilevault.Context {
	for _, p := range d.Profiles {
		if p.Protocol == "reality" {
			return profilevault.Context{ProfileID: p.ID, DeviceID: d.ID, OwnerID: owner, Protocol: "reality", Generation: 1, Format: clientconfig.VLESSRealityURI}
		}
	}
	panic("no REALITY slot")
}
func TestImportDryRunReadOnlyAtomicApplyAndRepeat(t *testing.T) {
	p, s, _, path := authStore(t)
	u, _ := enroll(t, s, "alice")
	v := profileTestKey(t)
	p.InitializeProfileVault(ctx, v)
	d, _ := p.RequestDevice(ctx, u.ID, deviceInput())
	c := importContext(u.ID, d)
	data := importPayload(t)
	var before int
	p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&before)
	ro, e := OpenPortal(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	result, e := ro.ImportClientProfile(ctx, v, c, 1, data, false)
	if e != nil || result.DeviceRevision != 1 || result.AlreadyStored {
		t.Fatal("dry run", e)
	}
	var n int
	p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&n)
	if n != before {
		t.Fatal("dry run wrote audit")
	}
	p.db.QueryRow("SELECT count(*) FROM profiles WHERE ciphertext IS NOT NULL").Scan(&n)
	if n != 0 {
		t.Fatal("dry run wrote secret")
	}
	if _, e = p.RenameDevice(ctx, u.ID, d.ID, "Renamed", 1); e != nil {
		t.Fatal(e)
	}
	if _, e = p.ImportClientProfile(ctx, v, c, 1, data, true); !errors.Is(e, ErrConflict) {
		t.Fatal("dry run reserved stale revision", e)
	}
	result, e = p.ImportClientProfile(ctx, v, c, 2, data, true)
	if e != nil || result.DeviceRevision != 3 || result.AlreadyStored {
		t.Fatal("apply", e)
	}
	replay, e := p.ImportClientProfile(ctx, v, c, 2, data, true)
	if e != nil || !replay.AlreadyStored || replay.DeviceRevision != 3 {
		t.Fatal("retry", e)
	}
	dry, e := ro.ImportClientProfile(ctx, v, c, 2, data, false)
	if e != nil || !dry.AlreadyStored {
		t.Fatal("dry existing", e)
	}
	if _, e = p.ImportClientProfile(ctx, v, c, 3, importPayload(t), true); !errors.Is(e, ErrConflict) {
		t.Fatal("overwrite", e)
	}
	tx, _ := p.db.BeginTx(ctx, nil)
	actual, envelope, e := secretFromTx(ctx, tx, c.ProfileID)
	tx.Rollback()
	if e != nil {
		t.Fatal(e)
	}
	plain, e := v.Open(actual, envelope)
	if e != nil || !bytes.Equal(plain, data) {
		t.Fatal("URI bytes changed", e)
	}
	clear(plain)
	if _, e = p.ReadReadyProfileSecret(ctx, v, u.ID, c.ProfileID); !errors.Is(e, domain.ErrDeviceState) {
		t.Fatal("import published access", e)
	}
	if _, e = p.CancelDeviceRequest(ctx, u.ID, d.ID, 3); !errors.Is(e, domain.ErrDeviceState) {
		t.Fatal("import cancelled")
	}
	targets, e := p.ProfileImportTargets(ctx, "alice", d.ID)
	if e != nil || len(targets) != 2 {
		t.Fatal("targets", e)
	}
	for _, target := range targets {
		if target.Generation != 1 || target.DeviceRevision != 3 || target.ProfileState != "pending" {
			t.Fatal("target metadata wrong")
		}
	}
}
func TestImportCredentialsOwnerMismatchAndRollback(t *testing.T) {
	p, s, _, _ := authStore(t)
	a, _ := enroll(t, s, "alice")
	b, _ := enroll(t, s, "bob")
	v := profileTestKey(t)
	p.InitializeProfileVault(ctx, v)
	d, _ := p.RequestDevice(ctx, a.ID, deviceInput())
	other, _ := p.RequestDevice(ctx, b.ID, deviceInput())
	c := importContext(a.ID, d)
	data := importPayload(t)
	wrong := c
	wrong.OwnerID = b.ID
	if _, e := p.ImportClientProfile(ctx, v, wrong, 1, data, false); !errors.Is(e, ErrNotFound) {
		t.Fatal("foreign target", e)
	}
	wrong = c
	wrong.Protocol = "awg"
	if _, e := p.ImportClientProfile(ctx, v, wrong, 1, data, true); !errors.Is(e, profilevault.ErrInput) {
		t.Fatal("wrong protocol", e)
	}
	if _, e := p.ImportClientProfile(ctx, v, c, 1, []byte(`{"root_password":"not-an-export"}`), true); !errors.Is(e, clientconfig.ErrInvalid) {
		t.Fatal("management input accepted", e)
	}
	p.db.Exec("CREATE TRIGGER fail_import BEFORE INSERT ON audit_events WHEN NEW.action='profile.stage' BEGIN SELECT RAISE(ABORT,'test'); END")
	if _, e := p.ImportClientProfile(ctx, v, c, 1, data, true); e == nil {
		t.Fatal("audit failure committed")
	}
	var revision int
	p.db.QueryRow("SELECT revision FROM devices WHERE id=?", d.ID).Scan(&revision)
	if revision != 1 {
		t.Fatal("failed import changed revision")
	}
	p.db.Exec("DROP TRIGGER fail_import")
	if _, e := p.ImportClientProfile(ctx, v, c, 1, data, true); e != nil {
		t.Fatal(e)
	}
	for _, apply := range []bool{false, true} {
		if _, e := p.ImportClientProfile(ctx, v, importContext(b.ID, other), 1, data, apply); !errors.Is(e, ErrClientCredentialConflict) {
			t.Fatal("shared credential", e)
		}
	}
	replacement := profileTestKey(t)
	if _, e := p.RotateProfileVault(ctx, v, replacement); e != nil {
		t.Fatal(e)
	}
	if _, e := p.ImportClientProfile(ctx, replacement, importContext(b.ID, other), 1, data, false); !errors.Is(e, ErrClientCredentialConflict) {
		t.Fatal("rotation lost credential conflict", e)
	}
	if _, e := p.ProfileImportTargets(ctx, "alice", other.ID); !errors.Is(e, ErrNotFound) {
		t.Fatal("foreign targets listed", e)
	}
}
func TestImportSameCredentialRaceAcrossDBHandles(t *testing.T) {
	p, s, _, path := authStore(t)
	u, _ := enroll(t, s, "alice")
	v := profileTestKey(t)
	p.InitializeProfileVault(ctx, v)
	a, _ := p.RequestDevice(ctx, u.ID, deviceInput())
	b, _ := p.RequestDevice(ctx, u.ID, deviceInput())
	second, e := OpenExistingPortal(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	start := make(chan struct{})
	errorsOut := make(chan error, 2)
	data := importPayload(t)
	var wg sync.WaitGroup
	for i, target := range []profilevault.Context{importContext(u.ID, a), importContext(u.ID, b)} {
		writer := p
		if i == 1 {
			writer = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, e := writer.ImportClientProfile(ctx, v, target, 1, data, true)
			errorsOut <- e
		}()
	}
	close(start)
	wg.Wait()
	close(errorsOut)
	success, conflict := 0, 0
	for e := range errorsOut {
		if e == nil {
			success++
		} else if errors.Is(e, ErrClientCredentialConflict) {
			conflict++
		} else {
			t.Fatal("unexpected race failure", e)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("credential assigned twice")
	}
}
