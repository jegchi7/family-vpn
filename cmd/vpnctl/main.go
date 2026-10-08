package main

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/app"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/store"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: vpnctl stand-check|demo-init|db-status|demo-rename|auth-init|auth-invite|auth-recovery|auth-reissue-invite|admin-*|profile-*|core-*|foreign-*|ru-*|network-* [flags]")
	}
	command := os.Args[1]
	if strings.HasPrefix(command, "core-") {
		return runCores(command, os.Args[2:])
	}
	if strings.HasPrefix(command, "foreign-") {
		return runForeign(command, os.Args[2:])
	}
	if strings.HasPrefix(command, "ru-") {
		return runRU(command, os.Args[2:])
	}
	if strings.HasPrefix(command, "network-") {
		return runNetwork(command, os.Args[2:])
	}
	if command == "stand-check" {
		return runStandCheck(os.Args[2:], os.Stdout)
	}
	if strings.HasPrefix(command, "profile-") {
		return runProfiles(command, os.Args[2:])
	}
	if strings.HasPrefix(command, "admin-") {
		return runAdmin(command, os.Args[2:])
	}
	if command != "demo-init" && command != "db-status" && command != "demo-rename" && command != "auth-init" && command != "auth-invite" && command != "auth-recovery" && command != "auth-reissue-invite" {
		return errors.New("unsupported command")
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	defaultRoot := "var/demo"
	if command == "auth-init" || command == "auth-invite" || command == "auth-recovery" || command == "auth-reissue-invite" {
		defaultRoot = "var/auth"
	}
	root := flags.String("root", defaultRoot, "Local state root")
	login := flags.String("login", "", "New user login (3-64 ASCII characters)")
	recoveryTTL := flags.Duration("recovery-ttl", auth.RecoveryTTL, "Recovery lifetime, maximum 1 hour; issuance disables old password and all portal sessions")
	inviteTTL := flags.Duration("invite-ttl", 24*time.Hour, "Invitation lifetime, maximum 24 hours")
	id := flags.String("id", "", "Device ID")
	name := flags.String("name", "", "New name")
	expected := flags.Int("expected-revision", 1, "Expected device revision")
	if e := flags.Parse(os.Args[2:]); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	portalPath := filepath.Join(*root, "portal", "state.db")
	controlPath := filepath.Join(*root, "control", "state.db")
	p, e := store.OpenPortal(ctx, portalPath, command == "db-status")
	if e != nil {
		return e
	}
	defer p.Close()
	if command == "auth-init" {
		if e = p.InitializeLocalAuth(ctx); e != nil {
			return e
		}
		certPath := filepath.Join(*root, "tls", "local-cert.pem")
		keyPath := filepath.Join(*root, "tls", "local-key.pem")
		_, ce := os.Stat(certPath)
		_, ke := os.Stat(keyPath)
		if os.IsNotExist(ce) && os.IsNotExist(ke) {
			if e = app.CreateLocalCertificate(*root); e != nil {
				return e
			}
		} else if ce != nil || ke != nil {
			return errors.New("incomplete local certificate pair; choose a new state root")
		}
		fmt.Println("Local auth store and TLS certificate ready. No accounts or VPN access created.")
		return nil
	}
	if command == "auth-recovery" || command == "auth-reissue-invite" {
		if e = p.AssertLocalAuth(ctx); e != nil {
			return e
		}
		s, e := auth.New(p, nil, 0, 0)
		if e != nil {
			return e
		}
		var token string
		var ttl time.Duration
		var purpose, note string
		if command == "auth-recovery" {
			ttl = *recoveryTTL
			purpose = "recovery"
			note = "Old password disabled and all portal sessions revoked immediately. VPN profiles unchanged. Paste code into recovery form; no automatic login."
			token, e = s.IssueRecovery(ctx, *login, ttl)
		} else {
			ttl = *inviteTTL
			purpose = "invite"
			note = "Previous invitation revoked. Paste replacement code into invitation form."
			token, e = s.ReissueInvite(ctx, *login, ttl)
		}
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"token": token, "login": *login, "purpose": purpose, "ttl_seconds": int(ttl.Seconds()), "note": note})
	}
	if command == "auth-invite" {
		if e = p.AssertLocalAuth(ctx); e != nil {
			return e
		}
		s, e := auth.New(p, nil, 0, 0)
		if e != nil {
			return e
		}
		token, e := s.IssueInvite(ctx, *login, *name, *inviteTTL)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"token": token, "login": *login, "note": "One-use local invitation. Paste into HTTPS form. Do not log or commit."})
	}
	if command == "demo-rename" {
		if e = p.RenameDemo(ctx, *id, *name, *expected); e != nil {
			return e
		}
		fmt.Println("Demo device renamed; persisted. No VPN changes.")
		return nil
	}
	c, e := store.OpenControl(ctx, controlPath, command == "db-status")
	if e != nil {
		return e
	}
	defer c.Close()
	if command == "demo-init" {
		if e = c.SeedDemo(ctx); e != nil {
			return e
		}
		if e = p.SeedDemo(ctx, time.Now()); e != nil {
			return e
		}
	}
	ps, e := p.Status(ctx)
	if e != nil {
		return e
	}
	cs, e := c.Status(ctx)
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"portal": ps, "control": cs})
}
