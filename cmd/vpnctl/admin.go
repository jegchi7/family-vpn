package main

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/adminauth"
	"familyvpn.local/platform/internal/app"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/store"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Credentials come only from stdin, never command arguments or environment variables.
func runAdmin(command string, args []string) error {
	switch command {
	case "admin-key-create", "admin-init", "admin-enroll", "admin-confirm", "admin-reset", "admin-disable":
	default:
		return errors.New("unsupported admin command")
	}
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	root := f.String("root", "var/admin", "Separate local admin state root")
	key := f.String("master-key", "var/admin-secrets/master.key", "Master key outside the admin DB state root")
	login := f.String("login", "", "Administrator login")
	name := f.String("name", "Администратор", "Display name")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	abs, e := filepath.Abs(*root)
	if e != nil {
		return e
	}
	k, e := filepath.Abs(*key)
	if e != nil {
		return e
	}
	rel, e := filepath.Rel(abs, k)
	if e != nil || rel == "." || !(rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("master key must be outside admin state root")
	}
	if command == "admin-key-create" {
		if e = os.MkdirAll(filepath.Dir(k), 0700); e != nil {
			return e
		}
		if e = adminauth.CreateKey(k); e != nil {
			return e
		}
		fmt.Println("Admin master key created. Keep a separate private backup; never copy it into a DB backup.")
		return nil
	}
	var in struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if command == "admin-enroll" || command == "admin-reset" || command == "admin-confirm" {
		d := json.NewDecoder(io.LimitReader(os.Stdin, 8192))
		d.DisallowUnknownFields()
		if e = d.Decode(&in); e != nil {
			return errors.New("expected one JSON object on stdin (password or code)")
		}
		var extra any
		if e = d.Decode(&extra); e != io.EOF {
			return errors.New("unexpected stdin data")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	a, e := store.OpenAdmin(ctx, filepath.Join(abs, "auth", "state.db"), command == "admin-init")
	if e != nil {
		return e
	}
	defer a.Close()
	if command == "admin-disable" {
		normalized, e := auth.NormalizeLogin(*login)
		if e != nil {
			return e
		}
		if e = a.AdminDisable(ctx, normalized, time.Now()); e != nil {
			return e
		}
		fmt.Println("Admin disabled; sessions and challenges revoked.")
		return nil
	}
	v, e := adminauth.LoadKey(k)
	if e != nil {
		return e
	}
	s, e := adminauth.New(a, v, nil)
	if e != nil {
		return e
	}
	if command == "admin-init" {
		cp, kp := filepath.Join(abs, "tls", "local-cert.pem"), filepath.Join(abs, "tls", "local-key.pem")
		_, ce := os.Stat(cp)
		_, ke := os.Stat(kp)
		if os.IsNotExist(ce) && os.IsNotExist(ke) {
			if e = app.CreateLocalCertificate(abs); e != nil {
				return e
			}
		} else if ce != nil || ke != nil {
			return errors.New("incomplete TLS certificate pair")
		}
		fmt.Println("Separate admin store and local TLS ready. Enroll and confirm TOTP before login.")
		return nil
	}
	if command == "admin-confirm" {
		if e = s.Confirm(ctx, *login, in.Code); e != nil {
			return e
		}
		fmt.Println("TOTP confirmed. Wait for the next authenticator code before browser login.")
		return nil
	}
	secret, e := s.Enroll(ctx, *login, *name, in.Password, command == "admin-reset")
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"secret": secret, "issuer": "Family VPN Admin", "account": *login, "algorithm": "SHA1", "digits": 6, "period_seconds": 30, "expires_in_seconds": 600, "note": "Add this secret manually to your authenticator, then admin-confirm. Do not log or share. Reset immediately revokes previous credentials, sessions and challenges."})
}
