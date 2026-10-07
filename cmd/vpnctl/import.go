package main

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/profilevault"
	"familyvpn.local/platform/internal/store"
	"flag"
	"io"
	"path/filepath"
	"time"
)

func importCode(e error) string {
	switch {
	case errors.Is(e, store.ErrClientCredentialConflict):
		return "CREDENTIAL_CONFLICT"
	case errors.Is(e, store.ErrConflict):
		return "REVISION_OR_CONTENT_CONFLICT"
	case errors.Is(e, store.ErrNotFound):
		return "TARGET_NOT_FOUND"
	case errors.Is(e, domain.ErrDeviceState):
		return "TARGET_NOT_PENDING"
	case errors.Is(e, auth.ErrDenied):
		return "OWNER_INACTIVE"
	case errors.Is(e, profilevault.ErrKey):
		return "PROFILE_KEY_UNAVAILABLE"
	case errors.Is(e, profilevault.ErrEnvelope):
		return "PROFILE_AUTHENTICATION_FAILED"
	case errors.Is(e, profilevault.ErrInput):
		return "INVALID_TARGET"
	default:
		return clientconfig.ErrorCode(e)
	}
}
func runProfileImport(args []string, input io.Reader, output io.Writer) error {
	f := flag.NewFlagSet("profile-import", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	root := f.String("root", "var/auth", "Existing user state root")
	key := f.String("profile-key", "var/profile-secrets/current.key", "External profile key")
	owner := f.String("owner-id", "", "Owner ID from profile-targets")
	device := f.String("device-id", "", "Device ID from profile-targets")
	profile := f.String("profile-id", "", "Profile ID from profile-targets")
	generation := f.Int("generation", 0, "Expected current profile generation")
	revision := f.Int("expected-revision", 0, "Expected device revision")
	format := f.String("format", "", "Explicit supported client-only format")
	source := f.String("input", "-", "Private input file or stdin (-); no config in arguments")
	apply := f.Bool("apply", false, "Commit validated encrypted staging; no server changes")
	dry := f.Bool("dry-run", false, "Read-only preview (default)")
	fail := func(e error) error {
		_ = json.NewEncoder(output).Encode(map[string]any{"status": "error", "code": importCode(e), "ready": false, "peers_verified": false})
		return errors.New("profile import failed; see sanitized report")
	}
	if e := f.Parse(args); e != nil || f.NArg() != 0 || (*apply && *dry) {
		return fail(profilevault.ErrInput)
	}
	protocol := "reality"
	if *format == clientconfig.AWG31Conf {
		protocol = "awg"
	}
	c := profilevault.Context{OwnerID: *owner, DeviceID: *device, ProfileID: *profile, Generation: *generation, Protocol: protocol, Format: *format}
	if !c.Valid() || *revision < 1 {
		return fail(profilevault.ErrInput)
	}
	data, e := clientconfig.ReadInput(*source, input)
	if e != nil {
		return fail(e)
	}
	defer clear(data)
	if _, e = clientconfig.Validate(*format, data); e != nil {
		return fail(e)
	}
	if e = profilevault.CheckLocation(*root, *key); e != nil {
		return fail(e)
	}
	v, e := profilevault.LoadKey(*key)
	if e != nil {
		return fail(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var p *store.PortalStore
	if *apply {
		p, e = store.OpenExistingPortal(ctx, filepath.Join(*root, "portal", "state.db"))
	} else {
		p, e = store.OpenPortal(ctx, filepath.Join(*root, "portal", "state.db"), true)
	}
	if e != nil {
		return fail(e)
	}
	defer p.Close()
	result, e := p.ImportClientProfile(ctx, v, c, *revision, data, *apply)
	if e != nil {
		return fail(e)
	}
	outcome := "would-import"
	if result.AlreadyStored {
		outcome = "already-stored"
	} else if *apply {
		outcome = "imported-pending"
	}
	return json.NewEncoder(output).Encode(map[string]any{"status": "ok", "outcome": outcome, "dry_run": !*apply, "device_revision": result.DeviceRevision, "ready": false, "peers_verified": false})
}
func runProfileTargets(args []string, output io.Writer) error {
	f := flag.NewFlagSet("profile-targets", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	root := f.String("root", "var/auth", "Existing user state root")
	login := f.String("login", "", "Active ordinary user login")
	device := f.String("device-id", "", "Optional owner device filter")
	if e := f.Parse(args); e != nil || f.NArg() != 0 {
		return errors.New("invalid profile-targets arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	p, e := store.OpenPortal(ctx, filepath.Join(*root, "portal", "state.db"), true)
	if e != nil {
		return errors.New("profile targets unavailable")
	}
	defer p.Close()
	targets, e := p.ProfileImportTargets(ctx, *login, *device)
	if e != nil {
		return errors.New("profile targets unavailable or owner/device not found")
	}
	return json.NewEncoder(output).Encode(map[string]any{"targets": targets})
}
