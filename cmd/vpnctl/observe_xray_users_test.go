package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestXrayUsersCLIRejectsBypassAndExternalTargetWithoutEcho(t *testing.T) {
	for _, args := range [][]string{nil, {"--apply"}, {"--input", "sensitive-input"}, {"--tool", "sensitive-input"}, {"--ready"}, {"--api-server", "remote.example.invalid:443", "--inbound-tag", "clients", "--expected-tool-sha256", strings.Repeat("a", 64)}} {
		out := new(bytes.Buffer)
		e := runProfileObserveXrayUsers(args, out)
		var r map[string]any
		if e == nil || json.Unmarshal(out.Bytes(), &r) != nil || r["status"] != "error" || r["ready"] != false || r["clients_verified"] != false || r["read_only"] != true || r["network_changed"] != false {
			t.Fatal("unsafe CLI result", e)
		}
		if strings.Contains(out.String(), "sensitive-input") || strings.Contains(out.String(), "remote.example.invalid") || strings.Contains(e.Error(), "sensitive-input") {
			t.Fatal("raw target/argument escaped")
		}
	}
}

func TestXrayCLIRequiresInventoryPinBeforeOpeningSecrets(t *testing.T) {
	base := []string{"--api-server", "127.0.0.1:10085", "--inbound-tag", "inventory", "--expected-tool-sha256", strings.Repeat("a", 64), "--expected-boot-id", "11111111-2222-3333-4444-555555555555", "--expected-netns-device", "4", "--expected-netns-inode", "12345"}
	for _, args := range [][]string{nil, {"--expected-inventory-sha256", "invalid-private-pin"}, {"--expected-inventory-sha256", strings.Repeat("A", 64)}, {"--inventory", "private-file-path"}} {
		out := new(bytes.Buffer)
		e := runProfileObserveXrayUsers(append(append([]string{}, base...), args...), out)
		var report map[string]any
		if e == nil || json.Unmarshal(out.Bytes(), &report) != nil || report["code"] != "INVALID_RUNTIME_TARGET" || report["ready"] != false {
			t.Fatal("pin/path bypass", e)
		}
		if strings.Contains(out.String(), "private") || strings.Contains(e.Error(), "private") || strings.Contains(out.String(), "12345") {
			t.Fatal("raw inventory escaped")
		}
	}
	// Valid lexical inventory pin still cannot authorize a missing/mismatched
	// fixed-file manifest; reject it before trying the nonexistent profile key.
	args := append(append([]string{}, base...), "--expected-inventory-sha256", strings.Repeat("c", 64), "--owner-id", "owner", "--device-id", "device", "--profile-id", "profile", "--generation", "1", "--expected-revision", "2", "--profile-key", "nonexistent-private-key")
	out := new(bytes.Buffer)
	e := runProfileObserveXrayUsers(args, out)
	var report map[string]any
	if e == nil || json.Unmarshal(out.Bytes(), &report) != nil || report["code"] != "INVENTORY_UNAVAILABLE_OR_CHANGED" || strings.Contains(out.String(), "nonexistent") {
		t.Fatal("inventory was not checked before secrets", e)
	}
}

func TestXrayUsersCLIRejectsIncompleteScopeBeforeOpeningState(t *testing.T) {
	base := []string{"--api-server", "127.0.0.1:10085", "--inbound-tag", "inventory", "--expected-tool-sha256", strings.Repeat("a", 64), "--expected-inventory-sha256", strings.Repeat("c", 64)}
	boot := "11111111-1111-1111-1111-111111111111"
	for _, scope := range [][]string{
		nil,
		{"--expected-boot-id", boot},
		{"--expected-netns-device", "4", "--expected-netns-inode", "12345"},
		{"--expected-boot-id", "malformed-inventory", "--expected-netns-device", "4", "--expected-netns-inode", "12345"},
		{"--expected-boot-id", boot, "--expected-netns-device", "0", "--expected-netns-inode", "12345"},
		{"--expected-boot-id", boot, "--expected-netns-device", "4", "--expected-netns-inode", "0"},
		{"--expected-boot-id", boot, "--expected-netns-device", "-1", "--expected-netns-inode", "12345"},
	} {
		out := new(bytes.Buffer)
		e := runProfileObserveXrayUsers(append(append([]string{}, base...), scope...), out)
		var r map[string]any
		if e == nil || json.Unmarshal(out.Bytes(), &r) != nil || r["code"] != "INVALID_RUNTIME_TARGET" || r["ready"] != false || r["read_only"] != true || r["network_changed"] != false {
			t.Fatal("scope was not rejected before owner/key/state validation", e)
		}
		for _, private := range []string{boot, "malformed-inventory", "127.0.0.1", strings.Repeat("a", 64), "12345"} {
			if strings.Contains(out.String(), private) || strings.Contains(e.Error(), private) {
				t.Fatal("inventory escaped safe report")
			}
		}
	}
}
