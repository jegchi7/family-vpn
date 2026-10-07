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

func runProfileObserve(args []string, output io.Writer) error {
	f := flag.NewFlagSet("profile-observe-awg", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	root := f.String("root", "var/auth", "Existing user state")
	key := f.String("profile-key", "var/profile-secrets/current.key", "External profile vault key")
	owner := f.String("owner-id", "", "Owner binding")
	device := f.String("device-id", "", "Device binding")
	profile := f.String("profile-id", "", "Profile binding")
	generation := f.Int("generation", 0, "Current generation")
	revision := f.Int("expected-revision", 0, "Device revision")
	iface := f.String("interface", "", "Existing AWG interface in this process network namespace")
	endpoint := f.String("expected-endpoint", "", "RU endpoint from independent inventory")
	pin := f.String("expected-tool-sha256", "", "Independent pin for /usr/bin/awg")
	boot := f.String("expected-boot-id", "", "Independent current boot ID")
	nsDev := f.Uint64("expected-netns-device", 0, "Independent network namespace device")
	nsIno := f.Uint64("expected-netns-inode", 0, "Independent network namespace inode")
	apply := f.Bool("apply", false, "Save readback metadata only; never publish access")
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
		case errors.Is(e, clientconfig.ErrSnapshot):
			code = "INVALID_RUNTIME_READBACK"
		case errors.Is(e, profileobserve.ErrObservation):
			code = "INVALID_OBSERVATION"
		}
		_ = json.NewEncoder(output).Encode(map[string]any{"status": "error", "code": code, "ready": false, "clients_verified": false, "network_changed": false})
		return errors.New("AWG observation failed; see sanitized report")
	}
	if e := f.Parse(args); e != nil || f.NArg() != 0 || *iface == "" || *endpoint == "" || len(*pin) != 64 {
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
	client, e := p.LoadPendingAWGObservation(ctx, v, c, *revision)
	if e != nil {
		return fail(e)
	}
	defer clear(client)
	result, e := profileobserve.Observe(ctx, c, *revision, client, target)
	if e != nil {
		return fail(e)
	}
	if *apply {
		if e = p.RecordProfileObservation(ctx, v, c, *revision, target, result); e != nil {
			return fail(e)
		}
	}
	summary := result.Summary()
	status := "ok"
	if !summary.PeerMatches {
		status = "conflict"
	}
	if e = json.NewEncoder(output).Encode(map[string]any{"status": status, "observation": summary, "stored": *apply, "ready": false, "clients_verified": false, "network_changed": false}); e != nil {
		return errors.New("AWG observation report unavailable")
	}
	if !summary.PeerMatches {
		return errors.New("AWG observation conflict; see sanitized report")
	}
	return nil
}
