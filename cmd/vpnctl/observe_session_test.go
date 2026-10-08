package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func awgSessionCLIArgs() []string {
	return []string{"--interface", "inventory_awg", "--expected-endpoint", "edge.example.invalid:443", "--expected-tool-sha256", strings.Repeat("a", 64), "--expected-boot-id", "11111111-2222-3333-4444-555555555555", "--expected-netns-device", "4", "--expected-netns-inode", "12345", "--owner-id", "owner", "--device-id", "device", "--profile-id", "profile", "--generation", "1", "--expected-revision", "2"}
}

func assertAWGSessionCLIRefusal(t *testing.T, args []string, codes ...string) {
	t.Helper()
	out := new(bytes.Buffer)
	e := runProfileObserveAWGSession(args, out)
	var report map[string]any
	if e == nil || json.Unmarshal(out.Bytes(), &report) != nil || report["status"] != "error" || report["ready"] != false || report["clients_verified"] != false || report["stored"] != false || report["read_only"] != true || report["network_changed"] != false {
		t.Fatal("unsafe AWG session CLI refusal")
	}
	allowed := false
	for _, code := range codes {
		allowed = allowed || report["code"] == code
	}
	if !allowed {
		t.Fatal("CLI reached secret/database/runtime access before argument rejection", report["code"])
	}
	for _, private := range []string{"private-marker", "inventory_awg", "edge.example.invalid", strings.Repeat("a", 64), "11111111-2222-3333-4444-555555555555", "12345"} {
		if strings.Contains(out.String(), private) || strings.Contains(e.Error(), private) {
			t.Fatal("raw argument/target escaped sanitized session error")
		}
	}
}

func TestAWGSessionCLIRejectsMutationInputAndToolFlags(t *testing.T) {
	for _, extra := range [][]string{{"--apply"}, {"--apply=false"}, {"--input", "private-marker"}, {"--snapshot", "private-marker"}, {"--tool", "private-marker"}, {"--client-checked"}, {"--client-verified"}, {"--ready"}, {"--format", "private-marker"}, {"--unknown", "private-marker"}, {"private-marker"}} {
		args := append(awgSessionCLIArgs(), extra...)
		assertAWGSessionCLIRefusal(t, args, "INVALID_TARGET")
	}
}

func TestAWGSessionCLIValidatesScopeAndBindingBeforeKeyOrDB(t *testing.T) {
	base := awgSessionCLIArgs()
	root := filepath.Join(t.TempDir(), "private-marker-state")
	key := filepath.Join(t.TempDir(), "private-marker-key")
	base = append(base, "--root", root, "--profile-key", key)
	for _, tc := range []struct {
		flag, value, code string
	}{
		{"--interface", "", "INVALID_RUNTIME_TARGET"},
		{"--interface", "private-marker/interface", "INVALID_RUNTIME_TARGET"},
		{"--expected-endpoint", "private-marker", "INVALID_RUNTIME_TARGET"},
		{"--expected-tool-sha256", strings.Repeat("A", 64), "INVALID_RUNTIME_TARGET"},
		{"--expected-boot-id", "private-marker", "INVALID_RUNTIME_TARGET"},
		{"--expected-netns-device", "0", "INVALID_RUNTIME_TARGET"},
		{"--expected-netns-inode", "0", "INVALID_RUNTIME_TARGET"},
		{"--expected-netns-inode", "-1", "INVALID_TARGET"},
		{"--owner-id", "", "INVALID_TARGET"},
		{"--device-id", "private-marker/device", "INVALID_TARGET"},
		{"--profile-id", "private-marker/profile", "INVALID_TARGET"},
		{"--generation", "0", "INVALID_TARGET"},
		{"--expected-revision", "0", "INVALID_TARGET"},
	} {
		t.Run(tc.flag+tc.value, func(t *testing.T) {
			args := append([]string{}, base...)
			for i := 0; i < len(args); i += 2 {
				if args[i] == tc.flag {
					args[i+1] = tc.value
				}
			}
			assertAWGSessionCLIRefusal(t, args, tc.code)
		})
	}
	for _, path := range []string{root, key} {
		if _, e := os.Stat(path); !os.IsNotExist(e) {
			t.Fatal("invalid arguments created state or key")
		}
	}
	assertAWGSessionCLIRefusal(t, nil, "INVALID_RUNTIME_TARGET")
}
