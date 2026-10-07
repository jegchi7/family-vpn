package main

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/profilevault"
	"familyvpn.local/platform/internal/store"
	"flag"
	"io"
	"path/filepath"
	"time"
)

func runProfilePreflight(args []string, input io.Reader, output io.Writer) error {
	f := flag.NewFlagSet("profile-preflight", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	root := f.String("root", "var/auth", "Existing user state root")
	key := f.String("profile-key", "var/profile-secrets/current.key", "External profile key")
	owner := f.String("owner-id", "", "Owner binding")
	device := f.String("device-id", "", "Device binding")
	profile := f.String("profile-id", "", "Profile binding")
	generation := f.Int("generation", 0, "Current generation")
	revision := f.Int("expected-revision", 0, "Device revision")
	source := f.String("server-config", "-", "Private Xray JSON file or stdin")
	tag := f.String("inbound-tag", "", "Explicit server inbound tag")
	endpoint := f.String("expected-endpoint", "", "RU client endpoint from trusted inventory")
	pin := f.String("expected-config-sha256", "", "Independent expected digest of server snapshot")
	fail := func(e error) error {
		code := importCode(e)
		if errors.Is(e, clientconfig.ErrSnapshot) {
			code = "INVALID_SERVER_SNAPSHOT"
		}
		if errors.Is(e, clientconfig.ErrSnapshotRevision) {
			code = "SNAPSHOT_REVISION_CONFLICT"
		}
		_ = json.NewEncoder(output).Encode(map[string]any{"status": "error", "code": code, "ready": false, "runtime_verified": false, "clients_verified": false})
		return errors.New("profile preflight failed; see sanitized report")
	}
	if e := f.Parse(args); e != nil || f.NArg() != 0 {
		return fail(profilevault.ErrInput)
	}
	c := profilevault.Context{OwnerID: *owner, DeviceID: *device, ProfileID: *profile, Generation: *generation, Protocol: "reality", Format: clientconfig.VLESSRealityURI}
	if !c.Valid() || *revision < 1 || *tag == "" || *endpoint == "" || *pin == "" {
		return fail(profilevault.ErrInput)
	}
	data, e := clientconfig.ReadInput(*source, input)
	if e != nil {
		return fail(e)
	}
	defer clear(data)
	if e = profilevault.CheckLocation(*root, *key); e != nil {
		return fail(e)
	}
	v, e := profilevault.LoadKey(*key)
	if e != nil {
		return fail(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, e := store.OpenPortal(ctx, filepath.Join(*root, "portal", "state.db"), true)
	if e != nil {
		return fail(e)
	}
	defer p.Close()
	mismatches, e := p.PreflightClientProfile(ctx, v, c, *revision, data, *tag, *endpoint, *pin)
	if e != nil {
		return fail(e)
	}
	matched := len(mismatches) == 0
	status := "ok"
	if !matched {
		status = "conflict"
	}
	e = json.NewEncoder(output).Encode(map[string]any{"status": status, "configuration_matches": matched, "mismatched_fields": mismatches, "ready": false, "runtime_verified": false, "clients_verified": false, "network_changed": false})
	if e != nil {
		return errors.New("profile preflight report unavailable")
	}
	if !matched {
		return errors.New("profile preflight conflict; see sanitized report")
	}
	return nil
}
