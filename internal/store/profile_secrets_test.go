package store

import (
	"bytes"
	"crypto/rand"
	"errors"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/profilevault"
	"os"
	"sync"
	"testing"
)

func profileTestKey(t *testing.T) *profilevault.Vault {
	t.Helper()
	k := make([]byte, 32)
	rand.Read(k)
	defer clear(k)
	v, e := profilevault.New(k)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func profilePayload(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 256)
	if _, e := rand.Read(b); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { clear(b) })
	return b
}
func targetForDevice(owner string, d domain.Device, index int) profilevault.Context {
	p := d.Profiles[index]
	return profilevault.Context{ProfileID: p.ID, DeviceID: d.ID, OwnerID: owner, Protocol: p.Protocol, Generation: 1, Format: "client-only-opaque"}
}
func TestProfileStagingOwnerReadyAndDiskBoundary(t *testing.T) {
	p, s, _, path := authStore(t)
	a, _ := enroll(t, s, "alice")
	b, _ := enroll(t, s, "bob")
	v := profileTestKey(t)
	if _, e := p.CheckProfileVault(ctx, v); !errors.Is(e, profilevault.ErrKey) {
		t.Fatal("uninitialized accepted", e)
	}
	if e := p.InitializeProfileVault(ctx, v); e != nil {
		t.Fatal(e)
	}
	if e := p.InitializeProfileVault(ctx, profileTestKey(t)); !errors.Is(e, profilevault.ErrKey) {
		t.Fatal("wrong key adopted", e)
	}
	d, e := p.RequestDevice(ctx, a.ID, deviceInput())
	if e != nil {
		t.Fatal(e)
	}
	c := targetForDevice(a.ID, d, 0)
	plain := profilePayload(t)
	wrong := c
	wrong.OwnerID = b.ID
	if _, e = p.StageProfileSecret(ctx, v, wrong, 1, plain); !errors.Is(e, ErrNotFound) {
		t.Fatal("foreign stage", e)
	}
	wrong = c
	wrong.Generation = 2
	if _, e = p.StageProfileSecret(ctx, v, wrong, 1, plain); !errors.Is(e, ErrConflict) {
		t.Fatal("wrong generation", e)
	}
	if _, e = p.StageProfileSecret(ctx, v, c, 9, plain); !errors.Is(e, ErrConflict) {
		t.Fatal("stale revision", e)
	}
	first, e := p.StageProfileSecret(ctx, v, c, 1, plain)
	if e != nil || first.DeviceRevision != 2 || first.AlreadyStored {
		t.Fatal("stage failed", e)
	}
	repeated, e := p.StageProfileSecret(ctx, v, c, 1, plain)
	if e != nil || !repeated.AlreadyStored || repeated.DeviceRevision != 2 {
		t.Fatal("retry failed", e)
	}
	if _, e = p.StageProfileSecret(ctx, v, c, 2, profilePayload(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("overwrote secret", e)
	}
	if _, e = p.ReadReadyProfileSecret(ctx, v, a.ID, c.ProfileID); !errors.Is(e, domain.ErrDeviceState) {
		t.Fatal("pending published", e)
	}
	if _, e = p.ReadReadyProfileSecret(ctx, v, b.ID, c.ProfileID); !errors.Is(e, ErrNotFound) {
		t.Fatal("foreign read", e)
	}
	if _, e = p.CancelDeviceRequest(ctx, a.ID, d.ID, 2); !errors.Is(e, domain.ErrDeviceState) {
		t.Fatal("staged cancelled", e)
	}
	var ip, installed *string
	var state string
	p.db.QueryRow("SELECT allocated_ip,installed_revision,state FROM profiles WHERE id=?", c.ProfileID).Scan(&ip, &installed, &state)
	if ip != nil || installed != nil || state != "pending" {
		t.Fatal("staging provisioned or published")
	}
	// Simulate future install verification only inside this isolated test, never a CLI command.
	p.db.Exec("UPDATE devices SET state='partial' WHERE id=?", d.ID)
	p.db.Exec("UPDATE profiles SET state='ready',installed_revision='verified-test' WHERE id=?", c.ProfileID)
	got, e := p.ReadReadyProfileSecret(ctx, v, a.ID, c.ProfileID)
	if e != nil || !bytes.Equal(got, plain) {
		t.Fatal("ready read failed", e)
	}
	clear(got)
	p.db.Exec("UPDATE users SET state='disabled' WHERE id=?", a.ID)
	if _, e = p.ReadReadyProfileSecret(ctx, v, a.ID, c.ProfileID); !errors.Is(e, ErrNotFound) {
		t.Fatal("disabled user read", e)
	}
	for _, file := range []string{path, path + "-wal"} {
		data, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(data, plain) {
			t.Fatal("plaintext in persisted state")
		}
	}
}
func TestProfileRotationAtomicRetryAndAllStates(t *testing.T) {
	p, s, _, _ := authStore(t)
	a, _ := enroll(t, s, "alice")
	old, new := profileTestKey(t), profileTestKey(t)
	p.InitializeProfileVault(ctx, old)
	d, e := p.RequestDevice(ctx, a.ID, deviceInput())
	if e != nil {
		t.Fatal(e)
	}
	payload := profilePayload(t)
	for i := range d.Profiles {
		if _, e = p.StageProfileSecret(ctx, old, targetForDevice(a.ID, d, i), i+1, payload); e != nil {
			t.Fatal(e)
		}
	}
	// Rotate revoked history too; rekeying must not change access state or generation.
	p.db.Exec("UPDATE profiles SET state='revoked' WHERE id=?", d.Profiles[0].ID)
	p.db.Exec("CREATE TRIGGER fail_rotate BEFORE INSERT ON audit_events WHEN NEW.action='profile-vault.rotate' BEGIN SELECT RAISE(ABORT,'test'); END")
	if _, e = p.RotateProfileVault(ctx, old, new); e == nil {
		t.Fatal("audit failure committed")
	}
	if n, e := p.CheckProfileVault(ctx, old); e != nil || n != 2 {
		t.Fatal("rollback lost profiles", e)
	}
	p.db.Exec("DROP TRIGGER fail_rotate")
	if n, e := p.RotateProfileVault(ctx, old, new); e != nil || n != 2 {
		t.Fatal("rotation failed", e)
	}
	if n, e := p.CheckProfileVault(ctx, new); e != nil || n != 2 {
		t.Fatal("new key cannot read", e)
	}
	if _, e = p.CheckProfileVault(ctx, old); !errors.Is(e, profilevault.ErrKey) {
		t.Fatal("stale key accepted", e)
	}
	if n, e := p.RotateProfileVault(ctx, old, new); e != nil || n != 0 {
		t.Fatal("rotation retry failed", e)
	}
	var state string
	var generation int
	p.db.QueryRow("SELECT state,generation FROM profiles WHERE id=?", d.Profiles[0].ID).Scan(&state, &generation)
	if state != "revoked" || generation != 1 {
		t.Fatal("rotation changed VPN lifecycle")
	}
	for _, id := range []string{d.Profiles[0].ID, d.Profiles[1].ID} {
		tx, e := p.db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		c, envelope, e := secretFromTx(ctx, tx, id)
		tx.Rollback()
		if e != nil {
			t.Fatal(e)
		}
		got, e := new.Open(c, envelope)
		if e != nil || !bytes.Equal(got, payload) {
			t.Fatal("secret lost", e)
		}
		clear(got)
	}
}
func TestProfileCorruptionRollsBackRekeyAndStageAudit(t *testing.T) {
	p, s, _, _ := authStore(t)
	a, _ := enroll(t, s, "alice")
	old, new := profileTestKey(t), profileTestKey(t)
	p.InitializeProfileVault(ctx, old)
	d, _ := p.RequestDevice(ctx, a.ID, deviceInput())
	c := targetForDevice(a.ID, d, 0)
	plain := profilePayload(t)
	p.db.Exec("CREATE TRIGGER fail_stage BEFORE INSERT ON audit_events WHEN NEW.action='profile.stage' BEGIN SELECT RAISE(ABORT,'test'); END")
	if _, e := p.StageProfileSecret(ctx, old, c, 1, plain); e == nil {
		t.Fatal("stage audit committed")
	}
	var n int
	p.db.QueryRow("SELECT count(*) FROM profiles WHERE ciphertext IS NOT NULL").Scan(&n)
	if n != 0 {
		t.Fatal("secret survived rollback")
	}
	p.db.Exec("DROP TRIGGER fail_stage")
	for i := range d.Profiles {
		if _, e := p.StageProfileSecret(ctx, old, targetForDevice(a.ID, d, i), i+1, plain); e != nil {
			t.Fatal(e)
		}
	}
	// Corrupt the last ID, so rekey attempts at least one update before the failure.
	rows, e := p.db.Query("SELECT id FROM profiles ORDER BY id")
	if e != nil {
		t.Fatal(e)
	}
	ids := []string{}
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	p.db.Exec("UPDATE profiles SET ciphertext=x'00' WHERE id=?", ids[len(ids)-1])
	if _, e = p.RotateProfileVault(ctx, old, new); !errors.Is(e, profilevault.ErrEnvelope) {
		t.Fatal("corruption accepted", e)
	}
	p.db.QueryRow("SELECT count(*) FROM profiles WHERE key_id=?", old.ID()).Scan(&n)
	if n != 2 {
		t.Fatal("partial rekey committed")
	}
	if e = p.InitializeProfileVault(ctx, old); !errors.Is(e, profilevault.ErrEnvelope) {
		t.Fatal("corrupt existing vault accepted", e)
	}
}
func TestStaleProfileWriterRacingKeyRotation(t *testing.T) {
	p, s, _, path := authStore(t)
	a, _ := enroll(t, s, "alice")
	old, new := profileTestKey(t), profileTestKey(t)
	p.InitializeProfileVault(ctx, old)
	d, _ := p.RequestDevice(ctx, a.ID, deviceInput())
	plain := profilePayload(t)
	if _, e := p.StageProfileSecret(ctx, old, targetForDevice(a.ID, d, 0), 1, plain); e != nil {
		t.Fatal(e)
	}
	second, e := OpenExistingPortal(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	start := make(chan struct{})
	var wg sync.WaitGroup
	var stageErr, rotateErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, stageErr = second.StageProfileSecret(ctx, old, targetForDevice(a.ID, d, 1), 2, plain)
	}()
	go func() { defer wg.Done(); <-start; _, rotateErr = p.RotateProfileVault(ctx, old, new) }()
	close(start)
	wg.Wait()
	if rotateErr != nil {
		t.Fatal("rotation race failed", rotateErr)
	}
	if stageErr != nil && !errors.Is(stageErr, profilevault.ErrKey) {
		t.Fatal("unexpected stage race failure", stageErr)
	}
	n, e := p.CheckProfileVault(ctx, new)
	if e != nil || n < 1 || n > 2 {
		t.Fatal("mixed key state", e)
	}
	if _, e = p.StageProfileSecret(ctx, old, targetForDevice(a.ID, d, 1), 2, plain); !errors.Is(e, profilevault.ErrKey) {
		t.Fatal("stale writer restored old key", e)
	}
}

func TestNonceCollisionAndAdditionalGenerationCancelGuard(t *testing.T) {
	p, s, _, _ := authStore(t)
	a, _ := enroll(t, s, "alice")
	v := profileTestKey(t)
	p.InitializeProfileVault(ctx, v)
	d, _ := p.RequestDevice(ctx, a.ID, deviceInput())
	plain := profilePayload(t)
	if _, e := p.StageProfileSecret(ctx, v, targetForDevice(a.ID, d, 0), 1, plain); e != nil {
		t.Fatal(e)
	}
	if _, e := p.db.Exec("UPDATE profiles SET key_id=(SELECT key_id FROM profiles WHERE id=?),nonce=(SELECT nonce FROM profiles WHERE id=?),ciphertext=(SELECT ciphertext FROM profiles WHERE id=?) WHERE id=?", d.Profiles[0].ID, d.Profiles[0].ID, d.Profiles[0].ID, d.Profiles[1].ID); e == nil {
		t.Fatal("nonce collision accepted")
	}
	fresh, e := p.RequestDevice(ctx, a.ID, deviceInput())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.db.Exec("INSERT INTO profiles(id,device_id,protocol,generation,state,format,installed_revision) VALUES('older-protected',?,'awg',2,'ready','client-only-opaque','installed-test')", fresh.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = p.CancelDeviceRequest(ctx, a.ID, fresh.ID, 1); !errors.Is(e, domain.ErrDeviceState) {
		t.Fatal("other generation bypass", e)
	}
	another, e := p.RequestDevice(ctx, a.ID, deviceInput())
	if e != nil {
		t.Fatal(e)
	}
	hash := make([]byte, 32)
	rand.Read(hash)
	if _, e = p.db.Exec("INSERT INTO subscription_tokens(id,device_id,token_hash,format) VALUES('test-subscription',?,?,'test')", another.ID, hash); e != nil {
		t.Fatal(e)
	}
	if _, e = p.CancelDeviceRequest(ctx, a.ID, another.ID, 1); !errors.Is(e, domain.ErrDeviceState) {
		t.Fatal("subscription bypass", e)
	}
}
