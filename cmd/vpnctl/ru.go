package main

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/coreinstall"
	"familyvpn.local/platform/internal/rusetup"
	"flag"
	"io"
	"os"
	"time"
)

func runRU(command string, args []string) error { return runRUTo(command, args, os.Stdout) }
func runRUTo(command string, args []string, output io.Writer) error {
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var i rusetup.Inputs
	var apply, native bool
	switch command {
	case "ru-init":
		f.StringVar(&i.Endpoint, "endpoint", "", "Independently selected public RU IPv4:443")
		f.StringVar(&i.ForeignEndpoint, "foreign-endpoint", "", "Independently selected public Foreign IPv4:443")
		f.StringVar(&i.RealityTarget, "reality-target", "", "Independently selected public camouflage IPv4:443")
		f.StringVar(&i.ServerName, "server-name", "", "Camouflage TLS hostname")
		f.BoolVar(&apply, "apply", false, "Create private closed RU stage; no network or service activation")
	case "ru-check":
		f.BoolVar(&native, "native-check", false, "Syntax-test protected config using pinned installed cores")
	case "ru-status":
	default:
		return errors.New("unsupported RU command")
	}
	s := rusetup.Summary{XrayVersion: coreinstall.XrayVersion, SingBoxVersion: coreinstall.SingBoxVersion}
	status, blocker, readOnly := "blocked", "", true
	var cause error
	if e := f.Parse(args); e != nil || f.NArg() != 0 {
		blocker = "INVALID_ARGUMENTS"
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		switch command {
		case "ru-init":
			cause = rusetup.ValidateInputs(i)
			if cause == nil {
				status = "planned"
				if apply {
					readOnly = false
					s, cause = rusetup.Stage(ctx, i)
					if cause == nil {
						status = "staged"
					}
				}
			}
		case "ru-check", "ru-status":
			s, _, cause = rusetup.Check(ctx, native)
			if cause == nil {
				status = "configuration_validated"
			}
		}
		if cause != nil {
			status = "blocked"
			switch {
			case errors.Is(cause, rusetup.ErrInput):
				blocker = "INVALID_INPUT"
			case errors.Is(cause, rusetup.ErrPlatform):
				blocker = "LINUX_ROOT_REQUIRED"
			case errors.Is(cause, rusetup.ErrNative):
				blocker = "NATIVE_SYNTAX_CHECK_UNAVAILABLE_OR_REJECTED"
			case errors.Is(cause, rusetup.ErrConfig):
				blocker = "STAGED_CONFIGURATION_REJECTED"
			default:
				blocker = "PRIVATE_HOP_OR_STAGE_UNAVAILABLE_OR_EXISTS"
			}
		}
	}
	report := struct {
		rusetup.Summary
		Status            string   `json:"status"`
		Blocker           string   `json:"blocker,omitempty"`
		ReadOnly          bool     `json:"read_only"`
		NetworkChanged    bool     `json:"network_changed"`
		ServicesStarted   bool     `json:"services_started"`
		RemainingRequired []string `json:"remaining_required"`
	}{s, status, blocker, readOnly, false, false, []string{"kernel_namespace_guard", "trusted_client_profile_binding", "actual_dns_and_routing", "real_client"}}
	if e := json.NewEncoder(output).Encode(report); e != nil {
		return errors.New("RU report could not be written")
	}
	if blocker != "" {
		return errors.New("RU preparation incomplete; see sanitized report")
	}
	return nil
}
