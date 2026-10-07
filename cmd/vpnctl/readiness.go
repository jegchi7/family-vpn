package main

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/profileobserve"
	"familyvpn.local/platform/internal/store"
	"flag"
	"io"
	"path/filepath"
	"time"
)

func runProfileReadiness(args []string, output io.Writer) error {
	f := flag.NewFlagSet("profile-readiness", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	root := f.String("root", "var/auth", "Existing user state")
	owner := f.String("owner-id", "", "Current owner")
	device := f.String("device-id", "", "Current device")
	profile := f.String("profile-id", "", "Current profile")
	generation := f.Int("generation", 0, "Current generation")
	revision := f.Int("expected-revision", 0, "Expected device revision")
	fail := func(e error) error {
		code := "REPORT_UNAVAILABLE"
		switch {
		case errors.Is(e, auth.ErrInput):
			code = "INVALID_TARGET"
		case errors.Is(e, store.ErrNotFound):
			code = "TARGET_NOT_FOUND"
		case errors.Is(e, store.ErrConflict):
			code = "REVISION_OR_GENERATION_CONFLICT"
		case errors.Is(e, store.ErrSchema):
			code = "SCHEMA_UNAVAILABLE"
		case errors.Is(e, profileobserve.ErrObservation):
			code = "INVALID_OBSERVATION"
		}
		_ = json.NewEncoder(output).Encode(map[string]any{"status": "error", "code": code, "ready": false, "clients_verified": false, "secret_verified": false, "read_only": true, "network_changed": false})
		return errors.New("profile readiness report unavailable; see sanitized report")
	}
	if e := f.Parse(args); e != nil || f.NArg() != 0 {
		return fail(auth.ErrInput)
	}
	t := store.ReadinessTarget{OwnerID: *owner, DeviceID: *device, ProfileID: *profile, Generation: *generation, ExpectedRevision: *revision}
	if !t.Valid() {
		return fail(auth.ErrInput)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, e := store.OpenPortal(ctx, filepath.Join(*root, "portal", "state.db"), true)
	if e != nil {
		return fail(e)
	}
	defer p.Close()
	r, e := p.ProfileReadiness(ctx, t)
	if e != nil {
		return fail(e)
	}
	if e = json.NewEncoder(output).Encode(map[string]any{"status": "blocked", "report": r, "ready": false, "read_only": true, "network_changed": false}); e != nil {
		return errors.New("profile readiness report unavailable")
	}
	return errors.New("profile remains blocked; see sanitized report")
}
