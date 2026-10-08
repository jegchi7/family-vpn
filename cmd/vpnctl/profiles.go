package main

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/profilevault"
	"familyvpn.local/platform/internal/store"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func runProfiles(command string, args []string) error {
	if command == "profile-observe-awg-session" {
		return runProfileObserveAWGSession(args, os.Stdout)
	}
	if command == "profile-observe-xray-users" {
		return runProfileObserveXrayUsers(args, os.Stdout)
	}
	if command == "profile-readiness" {
		return runProfileReadiness(args, os.Stdout)
	}
	if command == "profile-observe-awg" {
		return runProfileObserve(args, os.Stdout)
	}
	if command == "profile-preflight" {
		return runProfilePreflight(args, os.Stdin, os.Stdout)
	}
	if command == "profile-import" {
		return runProfileImport(args, os.Stdin, os.Stdout)
	}
	if command == "profile-targets" {
		return runProfileTargets(args, os.Stdout)
	}
	switch command {
	case "profile-key-create", "profile-vault-init", "profile-vault-check", "profile-key-rotate":
	default:
		return errors.New("unsupported profile command")
	}
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	root := f.String("root", "var/auth", "Local user state root")
	key := f.String("profile-key", "var/profile-secrets/current.key", "External purpose-tagged client profile key")
	next := f.String("new-key", "", "Existing new external client profile key (rotation only)")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if command != "profile-key-rotate" && *next != "" {
		return errors.New("new-key is only valid for rotation")
	}
	if e := profilevault.CheckLocation(*root, *key); e != nil {
		return e
	}
	if command == "profile-key-create" {
		if e := os.MkdirAll(filepath.Dir(*key), 0700); e != nil {
			return profilevault.ErrKey
		}
		if e := profilevault.CreateKey(*key); e != nil {
			return e
		}
		fmt.Println("Client profile key created exclusively. Keep a separate private backup; no key bytes printed.")
		return nil
	}
	v, e := profilevault.LoadKey(*key)
	if e != nil {
		return e
	}
	var replacement *profilevault.Vault
	if command == "profile-key-rotate" {
		if *next == "" {
			return errors.New("rotation requires new-key created separately")
		}
		if e = profilevault.CheckLocation(*root, *next); e != nil {
			return e
		}
		replacement, e = profilevault.LoadKey(*next)
		if e != nil {
			return e
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// No migration or accidental new DB creation; use auth-init to upgrade first.
	p, e := store.OpenExistingPortal(ctx, filepath.Join(*root, "portal", "state.db"))
	if e != nil {
		return e
	}
	defer p.Close()
	if command == "profile-vault-init" {
		if e = p.InitializeProfileVault(ctx, v); e != nil {
			return e
		}
		fmt.Println("Client profile vault initialized. No configs imported or VPN access created.")
		return nil
	}
	count := 0
	if command == "profile-key-rotate" {
		count, e = p.RotateProfileVault(ctx, v, replacement)
	} else {
		count, e = p.CheckProfileVault(ctx, v)
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"operation": command, "profiles": count, "status": "ok", "note": "No plaintext output; key files retained. Rotation does not revoke VPN access."})
}
