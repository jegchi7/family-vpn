package main

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/profileobserve"
	"familyvpn.local/platform/internal/profilevault"
	"familyvpn.local/platform/internal/store"
	"flag"
	"io"
	"path/filepath"
	"time"
)

func runProfileObserveAWGSession(args []string, output io.Writer) error {
	f := flag.NewFlagSet("profile-observe-awg-session", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	root := f.String("root", "var/auth", "Existing user state")
	key := f.String("profile-key", "var/profile-secrets/current.key", "External profile vault key")
	owner := f.String("owner-id", "", "Owner binding")
	device := f.String("device-id", "", "Device binding")
	profile := f.String("profile-id", "", "Profile binding")
	generation := f.Int("generation", 0, "Current generation")
	revision := f.Int("expected-revision", 0, "Current device revision")
	iface := f.String("interface", "", "Existing AWG interface in this process network namespace")
	endpoint := f.String("expected-endpoint", "", "RU endpoint from independent inventory")
	pin := f.String("expected-tool-sha256", "", "Independent pin for /usr/bin/awg")
	boot := f.String("expected-boot-id", "", "Independent current boot ID")
	nsDev := f.Uint64("expected-netns-device", 0, "Independent network namespace device")
	nsIno := f.Uint64("expected-netns-inode", 0, "Independent network namespace inode")
	fail := func(e error) error {
		code := importCode(e)
		switch {
		case errors.Is(e, profileobserve.ErrTarget):
			code = "INVALID_RUNTIME_TARGET"
		case errors.Is(e, profileobserve.ErrRuntime):
			code = "RUNTIME_UNAVAILABLE"
		case errors.Is(e, profileobserve.ErrDrift):
			code = "RUNTIME_CHANGED"
		case errors.Is(e, profileobserve.ErrStale):
			code = "OBSERVATION_STALE"
		case errors.Is(e, profileobserve.ErrObservation):
			code = "INVALID_OBSERVATION"
		}
		_ = json.NewEncoder(output).Encode(map[string]any{"status": "error", "code": code, "stored": false, "read_only": true, "ready": false, "clients_verified": false, "network_changed": false})
		return errors.New("AWG session observation failed; see sanitized report")
	}
	if e := f.Parse(args); e != nil || f.NArg() != 0 {
		return fail(profilevault.ErrInput)
	}
	target := profileobserve.Target{Interface: *iface, Endpoint: *endpoint, ToolSHA256: *pin, BootID: *boot, NetNSDevice: *nsDev, NetNSInode: *nsIno}
	if !target.Valid() {
		return fail(profileobserve.ErrTarget)
	}
	c := profilevault.Context{OwnerID: *owner, DeviceID: *device, ProfileID: *profile, Generation: *generation, Protocol: "awg", Format: clientconfig.AWG31Conf}
	if !c.Valid() || *revision < 1 {
		return fail(profilevault.ErrInput)
	}
	if e := profilevault.CheckLocation(*root, *key); e != nil {
		return fail(e)
	}
	v, e := profilevault.LoadKey(*key)
	if e != nil {
		return fail(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	p, e := store.OpenPortal(ctx, filepath.Join(*root, "portal", "state.db"), true)
	if e != nil {
		return fail(e)
	}
	defer p.Close()
	client, e := p.LoadPendingAWGObservation(ctx, v, c, *revision)
	if e != nil {
		return fail(e)
	}
	defer clear(client)
	result, e := profileobserve.ObserveSession(ctx, c, *revision, client, target)
	if e != nil {
		return fail(e)
	}
	summary, e := p.CheckPendingAWGSession(ctx, v, c, *revision, target, result)
	if e != nil {
		return fail(e)
	}
	if e = json.NewEncoder(output).Encode(map[string]any{"status": "blocked", "observation": summary, "blockers": []string{"core_identity_unverified", "runtime_revision_unverified", "client_acceptance_missing", "dns_routing_verification_required", "readiness_transition_unavailable"}, "stored": false, "read_only": true, "network_changed": false, "ready": false, "clients_verified": false}); e != nil {
		return errors.New("AWG session report unavailable")
	}
	return errors.New("profile remains blocked after AWG session observation")
}
