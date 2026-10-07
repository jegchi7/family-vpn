package main

import (
	"context"
	"errors"
	"familyvpn.local/platform/internal/profilevault"
	"familyvpn.local/platform/internal/store"
	"os"
	"path/filepath"
	"testing"
)

func TestProfileCLIKeyLifecycleAndFailClosed(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "state")
	key := filepath.Join(base, "keys", "old.key")
	next := filepath.Join(base, "keys", "new.key")
	args := []string{"--root", root, "--profile-key", key}
	if e := runProfiles("profile-key-create", args); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(key)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(before)
	if e = runProfiles("profile-key-create", args); !errors.Is(e, profilevault.ErrKey) {
		t.Fatal("CLI overwrite", e)
	}
	if e = runProfiles("profile-vault-init", args); e == nil {
		t.Fatal("CLI created missing DB")
	}
	ctx := context.Background()
	p, e := store.OpenPortal(ctx, filepath.Join(root, "portal", "state.db"), false)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.InitializeLocalAuth(ctx); e != nil {
		t.Fatal(e)
	}
	p.Close()
	if e = runProfiles("profile-vault-check", args); !errors.Is(e, profilevault.ErrKey) {
		t.Fatal("uninitialized check", e)
	}
	if e = runProfiles("profile-vault-init", args); e != nil {
		t.Fatal(e)
	}
	if e = runProfiles("profile-vault-check", args); e != nil {
		t.Fatal(e)
	}
	if e = runProfiles("profile-key-create", []string{"--root", root, "--profile-key", next}); e != nil {
		t.Fatal(e)
	}
	rotate := append(append([]string{}, args...), "--new-key", next)
	if e = runProfiles("profile-key-rotate", rotate); e != nil {
		t.Fatal(e)
	}
	if e = runProfiles("profile-key-rotate", rotate); e != nil {
		t.Fatal("retry", e)
	}
	if e = runProfiles("profile-vault-check", args); !errors.Is(e, profilevault.ErrKey) {
		t.Fatal("old key", e)
	}
	if e = runProfiles("profile-vault-check", []string{"--root", root, "--profile-key", next}); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(key); e != nil {
		t.Fatal("old key deleted", e)
	}
	if e = runProfiles("profile-key-create", []string{"--root", root, "--profile-key", filepath.Join(root, "nested", "bad.key")}); !errors.Is(e, profilevault.ErrKey) {
		t.Fatal("key in state root", e)
	}
	if _, e = os.Stat(filepath.Join(root, "nested")); !os.IsNotExist(e) {
		t.Fatal("invalid key path mutated state")
	}
}
