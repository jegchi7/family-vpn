package main

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func networkInputs() []string {
	return []string{"--role", "ru", "--ru-ipv4", "8.8.4.4", "--foreign-ipv4", "1.1.1.1", "--host-ipv4", "8.8.4.4", "--transit", "10.222.0.0/30", "--uplink", "eth0"}
}
func TestNetworkCommandsDefaultPureReadOnlyWithoutScopeOrHelperPins(t *testing.T) {
	for _, command := range []string{"network-plan", "network-prepare", "network-apply"} {
		var out bytes.Buffer
		if e := runNetworkTo(command, networkInputs(), &out); e != nil {
			t.Fatal(command, e)
		}
		var report map[string]any
		if json.Unmarshal(out.Bytes(), &report) != nil {
			t.Fatal("invalid report")
		}
		if report["status"] != "planned" || report["read_only"] != true {
			t.Fatal("default command performed native work")
		}
		for _, key := range []string{"configuration_validated", "inventory_checked", "execution_scope_bound", "kernel_guard_verified", "network_changed", "services_started", "native_acceptance", "client_verified", "ready"} {
			if report[key] != false {
				t.Fatalf("default command acquired %s", key)
			}
		}
	}
}
func TestNetworkFlagsNeverEchoPrivateValuesOrAcceptArbitraryHelper(t *testing.T) {
	for _, extra := range [][]string{{"--ip-path", "SECRET-HOST-PATH"}, {"--input", "SECRET-CONFIG"}, {"--role", "invalid-secret-role"}, {"--transit", "SECRET-TRANSIT"}, {"--apply"}} {
		var out bytes.Buffer
		if e := runNetworkTo("network-apply", append(networkInputs(), extra...), &out); e == nil {
			t.Fatal("invalid command accepted")
		}
		for _, private := range []string{"SECRET-HOST-PATH", "SECRET-CONFIG", "invalid-secret-role", "SECRET-TRANSIT"} {
			if strings.Contains(out.String(), private) {
				t.Fatal("input echoed")
			}
		}
		if strings.Contains(out.String(), `"ready":true`) || strings.Contains(out.String(), `"network_changed":true`) {
			t.Fatal("rejected input changed acceptance")
		}
	}
}
func TestNetworkNativeRequiresAllPinsAndCannotRunOnWindows(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("no native tool invocation in CLI tests")
	}
	args := append(networkInputs(), "--apply", "--boot-id", "12345678-1234-1234-1234-123456789abc", "--netns-device", "4", "--netns-inode", "5", "--ip-sha256", strings.Repeat("a", 64), "--nft-sha256", strings.Repeat("b", 64), "--sysctl-sha256", strings.Repeat("c", 64), "--tc-sha256", strings.Repeat("d", 64))
	var out bytes.Buffer
	if runNetworkTo("network-apply", args, &out) == nil || !strings.Contains(out.String(), "LINUX_ROOT_REQUIRED") {
		t.Fatal("unsupported platform started native work")
	}
}
