package main

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/coreinstall"
	"flag"
	"io"
	"os"
	"runtime"
	"time"
)

func runCores(command string, args []string) error { return runCoresOutput(command, args, os.Stdout) }

func runCoresOutput(command string, args []string, output io.Writer) error {
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	report := map[string]any{"command": command, "vpn_ready": false, "network_changed": false, "services_started": false, "profile_delivery_available": false, "native_acceptance": false}
	finish := func(code string) error {
		if code != "" {
			report["status"] = "blocked"
			report["blockers"] = []string{code}
		}
		e := json.NewEncoder(output).Encode(report)
		if e != nil {
			return errors.New("core report unavailable")
		}
		if code != "" {
			return errors.New("core operation incomplete; see sanitized report")
		}
		return nil
	}
	switch command {
	case "core-plan":
		role := f.String("role", "", "ru or foreign")
		if e := f.Parse(args); e != nil || f.NArg() != 0 || (*role != "ru" && *role != "foreign") {
			return finish("INVALID_ARGUMENTS")
		}
		cores := []string{"xray", "sing-box"}
		if *role == "foreign" {
			cores = []string{"xray", "hysteria"}
		}
		artifacts := []coreinstall.Artifact{}
		compatibility := []coreinstall.Compatibility{}
		for _, core := range cores {
			a, e := coreinstall.Lookup(core, runtime.GOARCH)
			if e != nil {
				return finish("UNSUPPORTED_ARCHITECTURE")
			}
			artifacts = append(artifacts, a)
			contract, _ := coreinstall.ConfigurationCompatibility(core)
			compatibility = append(compatibility, contract)
		}
		report["status"] = "planned"
		report["role"] = *role
		report["artifacts"] = artifacts
		report["compatibility"] = compatibility
		report["read_only"] = true
		report["downloads_performed"] = false
		report["can_apply"] = coreinstall.CanApply()
		report["awg_status"] = "blocked"
		report["awg_blockers"] = []string{"NO_ACCEPTED_UBUNTU20_BINARY", "ADVANCED_SECURITY_READBACK_UNAVAILABLE"}
		return finish("")
	case "core-install":
		core := f.String("core", "", "xray, sing-box or hysteria")
		apply := f.Bool("apply", false, "Install the fixed pinned Linux binary")
		if e := f.Parse(args); e != nil || f.NArg() != 0 {
			return finish("INVALID_ARGUMENTS")
		}
		a, e := coreinstall.Lookup(*core, runtime.GOARCH)
		if e != nil {
			return finish("INVALID_CORE_OR_ARCHITECTURE")
		}
		report["artifact"] = a
		contract, _ := coreinstall.ConfigurationCompatibility(*core)
		report["compatibility"] = contract
		report["read_only"] = !*apply
		report["can_apply"] = coreinstall.CanApply()
		report["downloads_performed"] = false
		report["changed"] = false
		if !*apply {
			report["status"] = "planned"
			return finish("")
		}
		if !coreinstall.CanApply() {
			return finish("LINUX_ROOT_REQUIRED")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()
		delete(report, "downloads_performed")
		report["download_may_be_attempted"] = true
		_, changed, e := coreinstall.Install(ctx, *core)
		report["changed"] = changed
		if e != nil {
			return finish(coreErrorCode(e))
		}
		report["changed"] = changed
		report["status"] = "installed"
		report["binary_integrity_verified"] = true
		return finish("")
	case "core-status":
		core := f.String("core", "", "Optional single core")
		if e := f.Parse(args); e != nil || f.NArg() != 0 {
			return finish("INVALID_ARGUMENTS")
		}
		cores := []string{"xray", "sing-box", "hysteria"}
		if *core != "" {
			if _, e := coreinstall.Lookup(*core, runtime.GOARCH); e != nil {
				return finish("INVALID_CORE_OR_ARCHITECTURE")
			}
			cores = []string{*core}
		}
		items := []map[string]any{}
		blocked := false
		for _, c := range cores {
			a, e := coreinstall.VerifyInstalled(c)
			item := map[string]any{"core": c, "binary_integrity_verified": e == nil}
			contract, _ := coreinstall.ConfigurationCompatibility(c)
			item["compatibility"] = contract
			if e != nil {
				item["blocker"] = coreErrorCode(e)
				blocked = true
			} else {
				item["artifact"] = a
			}
			items = append(items, item)
		}
		report["read_only"] = true
		report["artifacts"] = items
		report["status"] = "ok"
		if blocked {
			return finish("PINNED_CORE_UNAVAILABLE")
		}
		return finish("")
	default:
		return finish("INVALID_COMMAND")
	}
}

func coreErrorCode(e error) string {
	switch {
	case errors.Is(e, coreinstall.ErrPlatform):
		return "LINUX_ROOT_REQUIRED"
	case errors.Is(e, coreinstall.ErrArguments):
		return "INVALID_CORE_OR_ARCHITECTURE"
	case errors.Is(e, coreinstall.ErrDownload):
		return "DOWNLOAD_FAILED"
	case errors.Is(e, coreinstall.ErrIntegrity):
		return "CORE_INTEGRITY_FAILED"
	case errors.Is(e, coreinstall.ErrProtected):
		return "PROTECTED_CORE_LOCATION_INVALID"
	case errors.Is(e, coreinstall.ErrConflict):
		return "EXISTING_CORE_CONFLICT"
	default:
		return "PINNED_CORE_UNAVAILABLE"
	}
}
