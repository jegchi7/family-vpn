package main

import (
	"bytes"
	"encoding/json"
	"familyvpn.local/platform/internal/coreinstall"
	"runtime"
	"strings"
	"testing"
)

func TestCoreCLIDryRunAndClosedPlan(t *testing.T) {
	for _, c := range []struct {
		command string
		args    []string
	}{{"core-plan", []string{"--role", "ru"}}, {"core-plan", []string{"--role", "foreign"}}, {"core-install", []string{"--core", "xray"}}, {"core-install", []string{"--core", "sing-box"}}, {"core-install", []string{"--core", "hysteria"}}} {
		var out bytes.Buffer
		if e := runCoresOutput(c.command, c.args, &out); e != nil {
			t.Fatal(e)
		}
		var r map[string]any
		if json.Unmarshal(out.Bytes(), &r) != nil || r["status"] != "planned" || r["network_changed"] != false || r["services_started"] != false || r["vpn_ready"] != false || r["read_only"] != true || r["downloads_performed"] != false {
			t.Fatal("unsafe dry run report")
		}
	}
}

func TestCoreCLICompatibilityCannotBecomeRuntimeReadiness(t *testing.T) {
	for _, role := range []string{"ru", "foreign"} {
		var out bytes.Buffer
		if e := runCoresOutput("core-plan", []string{"--role", role}, &out); e != nil {
			t.Fatal(e)
		}
		var r struct {
			Artifacts     []coreinstall.Artifact      `json:"artifacts"`
			Compatibility []coreinstall.Compatibility `json:"compatibility"`
			AWGBlockers   []string                    `json:"awg_blockers"`
		}
		if json.Unmarshal(out.Bytes(), &r) != nil || len(r.Compatibility) != 2 || len(r.AWGBlockers) != 2 {
			t.Fatal("missing role contract or AWG blocker")
		}
		for i, c := range r.Compatibility {
			if c.Core != r.Artifacts[i].Core || c.Version != r.Artifacts[i].Version || c.NativeAcceptance || c.ClientAcceptance || c.Ready || len(c.Blockers) == 0 {
				t.Fatal("installer incorrectly implies protocol readiness")
			}
		}
	}
}

func TestCoreCLIRejectsArbitraryArgumentsWithoutEcho(t *testing.T) {
	marker := "private-argument-marker"
	for _, c := range []struct {
		command string
		args    []string
	}{{"core-install", []string{"--core", marker}}, {"core-install", []string{"--core", "xray", "--url", marker}}, {"core-install", []string{"--core", "xray", "--destination", marker}}, {"core-plan", []string{"--role", marker}}, {"core-plan", []string{"--role", "foreign", "--apply"}}, {"core-status", []string{"--core", "xray", marker}}} {
		var out bytes.Buffer
		e := runCoresOutput(c.command, c.args, &out)
		if e == nil || strings.Contains(e.Error(), marker) || strings.Contains(out.String(), marker) || !strings.Contains(out.String(), "\"vpn_ready\":false") {
			t.Fatal("argument boundary or secret echo")
		}
	}
	if runtime.GOOS != "linux" {
		var out bytes.Buffer
		if runCoresOutput("core-install", []string{"--core", "xray", "--apply"}, &out) == nil || !strings.Contains(out.String(), "LINUX_ROOT_REQUIRED") {
			t.Fatal("cross-platform apply")
		}
	}
}
