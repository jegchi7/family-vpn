package main

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/adminauth"
	"familyvpn.local/platform/internal/app"
	"familyvpn.local/platform/internal/store"
	"flag"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Explicit trusted read-only diagnostics. Never open control DB or profile
// key, issue credentials, migrate state, or allow profile publication.
func runStandCheck(args []string, output io.Writer) error {
	f := flag.NewFlagSet("stand-check", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	portal := f.String("portal-root", "var/auth", "Existing local-auth state")
	admin := f.String("admin-root", "var/admin", "Existing separate admin state")
	key := f.String("master-key", "var/admin-secrets/master.key", "Existing external admin key")
	web := f.String("web-dir", "web/dist", "Built local frontend")
	requireAdmin := f.Bool("require-admin", false, "Also check Linux admin DB, key and TLS")
	codes := []string{}
	report := func() error {
		status := "ok"
		if len(codes) != 0 {
			status = "blocked"
		}
		e := json.NewEncoder(output).Encode(map[string]any{"status": status, "blockers": codes, "read_only": true, "sqlite_sidecars_possible": true, "network_changed": false, "vpn_ready": false, "profile_delivery_available": false})
		if e != nil || len(codes) != 0 {
			return errors.New("stand checks incomplete; see sanitized report")
		}
		return nil
	}
	if e := f.Parse(args); e != nil || f.NArg() != 0 {
		codes = append(codes, "INVALID_ARGUMENTS")
		return report()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if app.CheckStandAssets(*web) != nil {
		codes = append(codes, "WEB_ASSETS_UNAVAILABLE")
	}
	if app.CheckStandTLS(filepath.Join(*portal, "tls", "local-cert.pem"), filepath.Join(*portal, "tls", "local-key.pem"), "127.0.0.1", time.Now()) != nil {
		codes = append(codes, "PORTAL_TLS_UNAVAILABLE_OR_EXPIRED")
	}
	p, e := store.OpenPortal(ctx, filepath.Join(*portal, "portal", "state.db"), true)
	if e != nil {
		codes = append(codes, "PORTAL_DB_UNAVAILABLE")
	} else {
		if p.AssertLocalAuth(ctx) != nil {
			codes = append(codes, "PORTAL_DATASET_INVALID")
		}
		p.Close()
	}
	if *requireAdmin {
		if runtime.GOOS != "linux" {
			codes = append(codes, "ADMIN_STAND_REQUIRES_LINUX")
			return report()
		}
		adminAbs, ae := filepath.Abs(*admin)
		portalAbs, pe := filepath.Abs(*portal)
		keyAbs, ke := filepath.Abs(*key)
		outside := func(root, path string) bool {
			rel, err := filepath.Rel(root, path)
			return err == nil && (rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)))
		}
		if ae != nil || pe != nil || ke != nil || !outside(adminAbs, portalAbs) || !outside(portalAbs, adminAbs) || !outside(adminAbs, keyAbs) || !outside(portalAbs, keyAbs) {
			codes = append(codes, "ADMIN_STATE_OR_KEY_LOCATION_INVALID")
			return report()
		}
		if app.CheckStandTLS(filepath.Join(*admin, "tls", "local-cert.pem"), filepath.Join(*admin, "tls", "local-key.pem"), "127.0.0.1", time.Now()) != nil {
			codes = append(codes, "ADMIN_TLS_UNAVAILABLE_OR_EXPIRED")
		}
		a, e := store.OpenAdminReadOnly(ctx, filepath.Join(*admin, "auth", "state.db"))
		if e != nil {
			codes = append(codes, "ADMIN_DB_UNAVAILABLE")
		} else {
			v, e := adminauth.LoadKey(*key)
			if e != nil || a.CheckAdminKey(ctx, v) != nil {
				codes = append(codes, "ADMIN_KEY_UNAVAILABLE_OR_MISMATCHED")
			}
			if active, e := a.HasActiveAdmin(ctx); e != nil || !active {
				codes = append(codes, "ADMIN_MFA_ENROLLMENT_REQUIRED")
			}
			a.Close()
		}
	}
	return report()
}
