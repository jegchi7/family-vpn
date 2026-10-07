package main

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/profilevault"
	"familyvpn.local/platform/internal/runtimeenv"
	"familyvpn.local/platform/internal/store"
	"familyvpn.local/platform/internal/xrayinventory"
	"familyvpn.local/platform/internal/xrayobserve"
	"flag"
	"io"
	"path/filepath"
	"time"
)

func runProfileObserveXrayUsers(args []string, output io.Writer) error {
	f := flag.NewFlagSet("profile-observe-xray-users", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	root := f.String("root", "var/auth", "Existing user state")
	key := f.String("profile-key", "var/profile-secrets/current.key", "External profile vault key")
	owner := f.String("owner-id", "", "Owner binding")
	device := f.String("device-id", "", "Device binding")
	profile := f.String("profile-id", "", "Profile binding")
	generation := f.Int("generation", 0, "Current generation")
	revision := f.Int("expected-revision", 0, "Current device revision")
	server := f.String("api-server", "", "Existing numeric loopback Xray API")
	tag := f.String("inbound-tag", "", "Inbound tag from independent inventory")
	pin := f.String("expected-tool-sha256", "", "Independent pin for /usr/bin/xray")
	inventoryPin := f.String("expected-inventory-sha256", "", "Independent exact-byte pin for fixed protected Xray inventory")
	boot := f.String("expected-boot-id", "", "Independent current boot ID")
	nsDev := f.Uint64("expected-netns-device", 0, "Independent network namespace device")
	nsIno := f.Uint64("expected-netns-inode", 0, "Independent network namespace inode")
	fail := func(e error) error {
		code := importCode(e)
		switch {
		case errors.Is(e, xrayinventory.ErrInventory):
			code = "INVENTORY_UNAVAILABLE_OR_CHANGED"
		case errors.Is(e, xrayobserve.ErrTarget):
			code = "RUNTIME_ENVIRONMENT_CHANGED"
		case errors.Is(e, xrayobserve.ErrInput):
			code = "INVALID_RUNTIME_TARGET"
		case errors.Is(e, xrayobserve.ErrRuntime):
			code = "RUNTIME_UNAVAILABLE"
		case errors.Is(e, xrayobserve.ErrDrift):
			code = "RUNTIME_CHANGED"
		case errors.Is(e, xrayobserve.ErrStale):
			code = "OBSERVATION_STALE"
		case errors.Is(e, clientconfig.ErrXrayUsers):
			code = "INVALID_USERS_READBACK"
		}
		_ = json.NewEncoder(output).Encode(map[string]any{"status": "error", "code": code, "ready": false, "clients_verified": false, "read_only": true, "network_changed": false})
		return errors.New("Xray users observation failed; see sanitized report")
	}
	if e := f.Parse(args); e != nil || f.NArg() != 0 || !xrayobserve.ValidTarget(*server, *tag, *pin) {
		return fail(xrayobserve.ErrInput)
	}
	target := xrayobserve.Target{Server: *server, Tag: *tag, ToolSHA256: *pin, InventorySHA256: *inventoryPin, Scope: runtimeenv.Scope{BootID: *boot, NetNSDevice: *nsDev, NetNSInode: *nsIno}}
	if !target.Valid() {
		return fail(xrayobserve.ErrInput)
	}
	c := profilevault.Context{OwnerID: *owner, DeviceID: *device, ProfileID: *profile, Generation: *generation, Protocol: "reality", Format: clientconfig.VLESSRealityURI}
	if !c.Valid() || *revision < 1 {
		return fail(profilevault.ErrInput)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if e := xrayinventory.Require(ctx, target.InventorySHA256, xrayinventory.Expected{Server: target.Server, Tag: target.Tag, ToolSHA256: target.ToolSHA256, Scope: target.Scope}); e != nil {
		return fail(e)
	}
	if e := profilevault.CheckLocation(*root, *key); e != nil {
		return fail(e)
	}
	v, e := profilevault.LoadKey(*key)
	if e != nil {
		return fail(e)
	}
	p, e := store.OpenPortal(ctx, filepath.Join(*root, "portal", "state.db"), true)
	if e != nil {
		return fail(e)
	}
	defer p.Close()
	plain, e := p.LoadPendingXrayUsersObservation(ctx, v, c, *revision)
	if e != nil {
		return fail(e)
	}
	defer clear(plain)
	r, e := xrayobserve.Observe(ctx, c, *revision, plain, target)
	if e != nil {
		return fail(e)
	}
	s, e := p.RecheckXrayUsersObservation(ctx, v, c, *revision, target, r)
	if e != nil {
		return fail(e)
	}
	if e = json.NewEncoder(output).Encode(map[string]any{"status": "blocked", "observation": s, "blockers": []string{"runtime_users_partial", "core_identity_unverified", "runtime_revision_unverified", "transport_verification_required", "client_acceptance_missing", "readiness_transition_unavailable"}, "stored": false, "ready": false, "read_only": true, "network_changed": false}); e != nil {
		return errors.New("Xray users report unavailable")
	}
	return errors.New("profile remains blocked after partial users observation")
}
