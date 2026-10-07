package adminauth

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestVaultAuthenticatesSecretAndContext(t *testing.T) {
	k := make([]byte, 32)
	rand.Read(k)
	v, e := NewVault(k)
	if e != nil {
		t.Fatal(e)
	}
	secret := make([]byte, 20)
	rand.Read(secret)
	data := v.Seal("account-a", string(secret))
	another := v.Seal("account-a", string(secret))
	if string(data) == string(another) {
		t.Fatal("nonce reuse")
	}
	got, e := v.Open("account-a", v.ID, data)
	if e != nil || got != string(secret) {
		t.Fatal(e)
	}
	if _, e = v.Open("account-b", v.ID, data); e == nil {
		t.Fatal("AAD substitution")
	}
	data[len(data)-1] ^= 1
	if _, e = v.Open("account-a", v.ID, data); e == nil {
		t.Fatal("tampering accepted")
	}
}
func TestMasterKeyFailsClosed(t *testing.T) {
	d := filepath.Join(t.TempDir(), "private")
	os.Mkdir(d, 0700)
	p := filepath.Join(d, "master.key")
	if _, e := LoadKey(p); e == nil {
		t.Fatal("missing key")
	}
	if e := CreateKey(p); e != nil {
		t.Fatal(e)
	}
	v, e := LoadKey(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = CreateKey(p); e == nil {
		t.Fatal("overwrote key")
	}
	again, e := LoadKey(p)
	if e != nil || again.ID != v.ID {
		t.Fatal("key changed")
	}
	alias := filepath.Join(d, "alias.key")
	if e = os.Symlink(p, alias); e != nil {
		t.Fatal(e)
	}
	if _, e = LoadKey(alias); e == nil {
		t.Fatal("symlink key")
	}
	os.Chmod(p, 0644)
	if _, e = LoadKey(p); e == nil {
		t.Fatal("public key permissions")
	}
	os.Chmod(p, 0600)
	os.Chmod(d, 0755)
	if _, e = LoadKey(p); e == nil {
		t.Fatal("public parent permissions")
	}
}
