package profilevault

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func testVault(t *testing.T) *Vault {
	t.Helper()
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	v, e := New(key)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestEnvelopeAuthenticatesEveryBinding(t *testing.T) {
	v := testVault(t)
	c := Context{"profile-a", "device-a", "owner-a", "awg", 1, "client-conf"}
	plain := make([]byte, 128)
	rand.Read(plain)
	defer clear(plain)
	envelope, e := v.Seal(c, plain)
	if e != nil {
		t.Fatal(e)
	}
	another, e := v.Seal(c, plain)
	if e != nil || bytes.Equal(envelope.Nonce, another.Nonce) {
		t.Fatal("nonce reused", e)
	}
	got, e := v.Open(c, envelope)
	if e != nil || !bytes.Equal(got, plain) {
		t.Fatal("round trip failed", e)
	}
	clear(got)
	for _, change := range []func(*Context){func(c *Context) { c.ProfileID = "profile-b" }, func(c *Context) { c.DeviceID = "device-b" }, func(c *Context) { c.OwnerID = "owner-b" }, func(c *Context) { c.Protocol = "reality" }, func(c *Context) { c.Generation = 2 }, func(c *Context) { c.Format = "other-format" }} {
		modified := c
		change(&modified)
		if _, e = v.Open(modified, envelope); !errors.Is(e, ErrEnvelope) {
			t.Fatal("binding substitution accepted", e)
		}
	}
	tampered := Envelope{envelope.KeyID, bytes.Clone(envelope.Nonce), bytes.Clone(envelope.Ciphertext)}
	tampered.Ciphertext[0] ^= 1
	if _, e = v.Open(c, tampered); !errors.Is(e, ErrEnvelope) {
		t.Fatal("ciphertext accepted", e)
	}
	tampered = Envelope{envelope.KeyID, bytes.Clone(envelope.Nonce), bytes.Clone(envelope.Ciphertext)}
	tampered.Nonce[0] ^= 1
	if _, e = v.Open(c, tampered); !errors.Is(e, ErrEnvelope) {
		t.Fatal("nonce accepted", e)
	}
	if _, e = testVault(t).Open(c, envelope); !errors.Is(e, ErrKey) {
		t.Fatal("wrong key", e)
	}
	if _, e = (*Vault)(nil).Open(c, envelope); !errors.Is(e, ErrKey) {
		t.Fatal("nil key", e)
	}
	for _, bad := range []Envelope{{v.ID(), nil, envelope.Ciphertext}, {v.ID(), envelope.Nonce, []byte{1}}, {v.ID(), envelope.Nonce, make([]byte, MaxSize+17)}} {
		if _, e = v.Open(c, bad); !errors.Is(e, ErrEnvelope) {
			t.Fatal("invalid envelope", e)
		}
	}
	if _, e = v.Seal(c, nil); !errors.Is(e, ErrInput) {
		t.Fatal(e)
	}
	if _, e = v.Seal(c, make([]byte, MaxSize+1)); !errors.Is(e, ErrInput) {
		t.Fatal(e)
	}
	c.ProfileID = "bad\x00binding"
	if _, e = v.Seal(c, plain); !errors.Is(e, ErrInput) {
		t.Fatal(e)
	}
}
func TestPurposeTaggedKeyFileAndExternalLocation(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "secrets")
	os.Mkdir(dir, 0700)
	key := filepath.Join(dir, "client.key")
	if _, e := LoadKey(key); !errors.Is(e, ErrKey) {
		t.Fatal("missing key", e)
	}
	if e := CreateKey(key); e != nil {
		t.Fatal(e)
	}
	v, e := LoadKey(key)
	if e != nil {
		t.Fatal(e)
	}
	if e = CreateKey(key); !errors.Is(e, ErrKey) {
		t.Fatal("overwrite", e)
	}
	other, e := LoadKey(key)
	if e != nil || other.ID() != v.ID() {
		t.Fatal("key changed", e)
	}
	state := filepath.Join(root, "state")
	if e = CheckLocation(state, key); e != nil {
		t.Fatal(e)
	}
	if e = CheckLocation(root, key); !errors.Is(e, ErrKey) {
		t.Fatal("key in backup root", e)
	}
	alias := filepath.Join(root, "alias")
	if e = os.Symlink(dir, alias); e != nil {
		t.Fatal(e)
	}
	if e = CheckLocation(filepath.Join(alias, "new-state"), key); !errors.Is(e, ErrKey) {
		t.Fatal("aliased root", e)
	}
	if _, e = LoadKey(filepath.Join(alias, "client.key")); !errors.Is(e, ErrKey) {
		t.Fatal("aliased ancestor", e)
	}
	link := filepath.Join(dir, "alias.key")
	os.Symlink(key, link)
	if _, e = LoadKey(link); !errors.Is(e, ErrKey) {
		t.Fatal("symlink key", e)
	}
	os.Chmod(key, 0644)
	if _, e = LoadKey(key); !errors.Is(e, ErrKey) {
		t.Fatal("public key", e)
	}
	os.Chmod(key, 0600)
	os.Chmod(dir, 0755)
	if _, e = LoadKey(key); !errors.Is(e, ErrKey) {
		t.Fatal("public parent", e)
	}
	os.Chmod(dir, 0700)
	raw := make([]byte, 32)
	rand.Read(raw)
	os.WriteFile(key, raw, 0600)
	clear(raw)
	if _, e = LoadKey(key); !errors.Is(e, ErrKey) {
		t.Fatal("raw admin key accepted", e)
	}
	for _, bad := range []string{`{"version":1,"purpose":"admin-totp","key":""}`, `{"version":2}`, `{}`, `{} {}`, `{"version":1,"extra":1}`} {
		os.WriteFile(key, []byte(bad), 0600)
		if _, e = LoadKey(key); !errors.Is(e, ErrKey) {
			t.Fatal("malformed key accepted", e)
		}
	}
}
