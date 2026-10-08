package main

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/foreignsetup"
	"flag"
	"io"
	"os"
	"time"
)

func runForeign(command string, args []string) error {
	return runForeignTo(command, args, os.Stdout)
}

func runForeignTo(command string, args []string, output io.Writer) error {
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var i foreignsetup.Inputs
	var apply, native bool
	switch command {
	case "foreign-init":
		f.StringVar(&i.Endpoint, "endpoint", "", "Explicit public Foreign IP:443")
		f.StringVar(&i.RUSource, "ru-source", "", "Explicit public RU source IP")
		f.StringVar(&i.RealityTarget, "reality-target", "", "Explicit public camouflage IP:443")
		f.StringVar(&i.ServerName, "server-name", "", "Explicit camouflage TLS hostname")
		f.BoolVar(&apply, "apply", false, "Create private stage only; never start networking")
	case "foreign-check":
		f.BoolVar(&native, "native-check", false, "Syntax-test protected stage using pinned installed Xray")
	case "foreign-status":
	default:
		return errors.New("unsupported Foreign command")
	}
	s := foreignsetup.Summary{XrayVersion: foreignsetup.XrayVersion, RUHopCoreVersion: foreignsetup.SingBoxVersion}
	status, blocker := "blocked", ""
	readOnly := true
	var cause error
	if e := f.Parse(args); e != nil || f.NArg() != 0 {
		blocker = "INVALID_ARGUMENTS"
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		switch command {
		case "foreign-init":
			cause = foreignsetup.ValidateInputs(i)
			if cause == nil {
				status = "planned"
				if apply {
					readOnly = false
					s, cause = foreignsetup.Stage(ctx, i)
					if cause == nil {
						status = "staged"
					}
				}
			}
		case "foreign-check", "foreign-status":
			s, cause = foreignsetup.Check(ctx, native)
			if cause == nil {
				status = "configuration_validated"
			}
		}
		if cause != nil {
			status = "blocked"
			switch {
			case errors.Is(cause, foreignsetup.ErrInput):
				blocker = "INVALID_INPUT"
			case errors.Is(cause, foreignsetup.ErrPlatform):
				blocker = "LINUX_ROOT_REQUIRED"
			case errors.Is(cause, foreignsetup.ErrNative):
				blocker = "NATIVE_SYNTAX_CHECK_UNAVAILABLE_OR_REJECTED"
			case errors.Is(cause, foreignsetup.ErrConfig):
				blocker = "STAGED_CONFIGURATION_REJECTED"
			default:
				blocker = "PRIVATE_STAGE_UNAVAILABLE_OR_EXISTS"
			}
		}
	}
	report := struct {
		foreignsetup.Summary
		Status            string   `json:"status"`
		Blocker           string   `json:"blocker,omitempty"`
		ReadOnly          bool     `json:"read_only"`
		NetworkChanged    bool     `json:"network_changed"`
		ServicesStarted   bool     `json:"services_started"`
		RemainingRequired []string `json:"remaining_required"`
	}{s, status, blocker, readOnly, false, false, []string{"kernel_egress_guard", "ru_isolated_hop", "actual_dns_and_routing", "real_client", "backup_tls_setup"}}
	if e := json.NewEncoder(output).Encode(report); e != nil {
		return errors.New("Foreign report could not be written")
	}
	if blocker != "" {
		return errors.New("Foreign preparation incomplete; see sanitized report")
	}
	return nil
}
