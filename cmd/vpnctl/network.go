package main

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/netguard"
	"familyvpn.local/platform/internal/netstand"
	"familyvpn.local/platform/internal/runtimeenv"
	"flag"
	"io"
	"net/netip"
	"os"
	"time"
)

func runNetwork(command string, args []string) error { return runNetworkTo(command, args, os.Stdout) }
func runNetworkTo(command string, args []string, out io.Writer) error {
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var role, ru, foreign, host, transit, uplink, boot, ip, nft, sysctl, tc, xtLegacy string
	var device, inode uint64
	var apply, native bool
	switch command {
	case "network-plan", "network-prepare", "network-apply", "network-check":
	default:
		return errors.New("unsupported network command")
	}
	f.StringVar(&role, "role", "", "Explicit ru or foreign role")
	f.StringVar(&ru, "ru-ipv4", "", "Explicit public RU IPv4")
	f.StringVar(&foreign, "foreign-ipv4", "", "Explicit public Foreign IPv4")
	f.StringVar(&host, "host-ipv4", "", "Independent public IPv4 on selected uplink")
	f.StringVar(&transit, "transit", "", "Independent non-overlapping private IPv4 /30")
	f.StringVar(&uplink, "uplink", "", "Independent selected default-route interface")
	f.StringVar(&boot, "boot-id", "", "Independent expected current boot")
	f.Uint64Var(&device, "netns-device", 0, "Independent expected host network namespace device")
	f.Uint64Var(&inode, "netns-inode", 0, "Independent expected host network namespace inode")
	f.StringVar(&ip, "ip-sha256", "", "Independent protected fixed ip helper pin")
	f.StringVar(&nft, "nft-sha256", "", "Independent protected fixed nft helper pin")
	f.StringVar(&sysctl, "sysctl-sha256", "", "Independent protected fixed sysctl helper pin")
	f.StringVar(&tc, "tc-sha256", "", "Independent protected fixed tc helper pin")
	f.StringVar(&xtLegacy, "xtables-legacy-sha256", "", "Foreign-only independent fixed legacy multicall helper pin")
	if command == "network-prepare" || command == "network-apply" {
		f.BoolVar(&apply, "apply", false, "Apply requested operator-only operation")
	}
	if command == "network-check" {
		f.BoolVar(&native, "native-check", false, "Fresh native kernel guard/topology readback")
	}
	s := netstand.Summary{}
	status, blocker := "blocked", ""
	readOnly := !apply
	var cause error
	if f.Parse(args) != nil || f.NArg() != 0 {
		blocker = "INVALID_ARGUMENTS"
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if command == "network-check" && !native {
			if f.NFlag() != 0 {
				cause = netstand.ErrInput
			} else {
				s, cause = netstand.Check(ctx)
				if cause == nil {
					status = "configuration_validated"
				}
			}
		} else {
			ruIP, e1 := netip.ParseAddr(ru)
			foreignIP, e2 := netip.ParseAddr(foreign)
			hostIP, e3 := netip.ParseAddr(host)
			prefix, e4 := netip.ParsePrefix(transit)
			i := netguard.Inputs{Role: role, RUIPv4: ruIP, ForeignIPv4: foreignIP, HostPublicIPv4: hostIP, Transit: prefix, Uplink: uplink}
			t := netstand.Target{Scope: runtimeenv.Scope{BootID: boot, NetNSDevice: device, NetNSInode: inode}, IP_SHA256: ip, NFT_SHA256: nft, SysctlSHA256: sysctl, TCSHA256: tc, XTLegacySHA256: xtLegacy}
			if e1 != nil || e2 != nil || e3 != nil || e4 != nil || netguard.ValidateInputs(i) != nil {
				cause = netstand.ErrInput
			} else if !apply && !native {
				status = "planned"
				s.Role = i.Role
			} else if netstand.Validate(i, t) != nil {
				cause = netstand.ErrInput
			} else {
				switch command {
				case "network-prepare":
					s, cause = netstand.Prepare(ctx, i, t)
					if cause == nil {
						status = "staged"
					}
				case "network-apply":
					s, cause = netstand.Apply(ctx, i, t)
					if cause == nil {
						status = "kernel_configuration_observed"
					}
				case "network-check":
					var proof netstand.Proof
					proof, s, cause = netstand.Verify(ctx, i, t)
					proof.Close()
					if cause == nil {
						status = "kernel_configuration_observed"
					}
				default:
					cause = netstand.ErrInput
				}
			}
		}
	}
	if cause != nil {
		status = "blocked"
		switch {
		case errors.Is(cause, netstand.ErrInput):
			blocker = "INVALID_INPUT"
		case errors.Is(cause, netstand.ErrPlatform):
			blocker = "LINUX_ROOT_REQUIRED"
		case errors.Is(cause, netstand.ErrInventory):
			blocker = "CURRENT_INVENTORY_OR_SCOPE_CONFLICT"
		case errors.Is(cause, netstand.ErrForwarding):
			blocker = "HOST_FORWARDING_ZERO_PRESERVATION_REQUIRED"
		case errors.Is(cause, netstand.ErrRecovery):
			blocker = "OWNED_NETWORK_RECOVERY_REQUIRED"
		case errors.Is(cause, netstand.ErrGuardProof):
			blocker = "NATIVE_KERNEL_GUARD_READBACK_REJECTED"
		case errors.Is(cause, netstand.ErrExecution):
			blocker = "BOUNDED_NETWORK_STEP_FAILED"
		default:
			blocker = "PROTECTED_STAGE_OR_HELPER_UNAVAILABLE_OR_CHANGED"
		}
	}
	report := struct {
		netstand.Summary
		Status            string   `json:"status"`
		Blocker           string   `json:"blocker,omitempty"`
		ReadOnly          bool     `json:"read_only"`
		RemainingRequired []string `json:"remaining_required"`
	}{s, status, blocker, readOnly, []string{"native_linux_acceptance", "unprivileged_core_runtime", "real_client_and_fail_closed_test", "audited_profile_readiness_transition"}}
	if json.NewEncoder(out).Encode(report) != nil {
		return errors.New("network report could not be written")
	}
	if blocker != "" {
		return errors.New("network preparation incomplete; see sanitized report")
	}
	return nil
}
