package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestObserveCLIRejectsInvalidArgumentsWithoutEcho(t *testing.T) {
	for _, args := range [][]string{nil, {"--input", "sensitive-config"}, {"--unexpected", "sensitive-config"}, {"--interface", "awg0", "--expected-endpoint", "host.invalid:443", "--expected-tool-sha256", strings.Repeat("0", 64)}} {
		out := new(bytes.Buffer)
		e := runProfileObserve(args, out)
		var report map[string]any
		if e == nil || json.Unmarshal(out.Bytes(), &report) != nil || report["status"] != "error" || report["ready"] != false || report["network_changed"] != false || report["clients_verified"] != false {
			t.Fatal("unsafe error/report")
		}
		if strings.Contains(out.String(), "sensitive-config") || strings.Contains(e.Error(), "sensitive-config") {
			t.Fatal("echoed rejected arguments")
		}
	}
}

func TestObserveCLIRequiresIndependentRuntimeInventory(t *testing.T) {
	base := []string{"--interface", "inventory_awg", "--expected-endpoint", "edge.example.invalid:443", "--expected-tool-sha256", strings.Repeat("a", 64)}
	scope := []string{"--expected-boot-id", "11111111-2222-3333-4444-555555555555", "--expected-netns-device", "4", "--expected-netns-inode", "12345"}
	cases := [][]string{base, append(append([]string{}, base...), scope[:2]...), append(append([]string{}, base...), scope[:4]...)}
	for _, field := range []string{"--expected-boot-id", "--expected-netns-device", "--expected-netns-inode", "--expected-tool-sha256", "--interface", "--expected-endpoint"} {
		args := append(append([]string{}, base...), scope...)
		for i := 0; i < len(args); i += 2 {
			if args[i] == field {
				args[i+1] = "private-invalid-inventory"
			}
		}
		cases = append(cases, args)
	}
	for _, args := range cases {
		// No owner/key/state/tool reads are needed to reject missing/malformed scope.
		out := new(bytes.Buffer)
		e := runProfileObserve(args, out)
		var report map[string]any
		if e == nil || json.Unmarshal(out.Bytes(), &report) != nil || report["status"] != "error" || report["ready"] != false || report["network_changed"] != false {
			t.Fatal("invalid inventory accepted")
		}
		code := report["code"]
		if code != "INVALID_RUNTIME_TARGET" && code != "INVALID_TARGET" {
			t.Fatal("reached secret/database access before inventory rejection", code)
		}
		for _, bad := range []string{"private-invalid-inventory", "inventory_awg", "edge.example.invalid", "11111111-2222-3333-4444-555555555555"} {
			if strings.Contains(out.String(), bad) || strings.Contains(e.Error(), bad) {
				t.Fatal("inventory echoed")
			}
		}
	}
}
