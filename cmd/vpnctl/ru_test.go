package main

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func ruArguments() []string {
	return []string{"--endpoint", "8.8.4.4:443", "--foreign-endpoint", "8.8.8.8:443", "--reality-target", "1.0.0.1:443", "--server-name", "www.cloudflare.com"}
}
func TestRUCLIPureDryRunAndNoReadiness(t *testing.T) {
	var out bytes.Buffer
	if e := runRUTo("ru-init", ruArguments(), &out); e != nil {
		t.Fatal(e)
	}
	var r map[string]any
	if json.Unmarshal(out.Bytes(), &r) != nil || r["status"] != "planned" || r["read_only"] != true || r["configuration_validated"] != false || r["client_binding_configured"] != false || r["ready"] != false || r["network_changed"] != false || r["services_started"] != false {
		t.Fatal("dry-run invented private config or readiness")
	}
	for _, value := range []string{"8.8.4.4", "8.8.8.8", "www.cloudflare.com", "privateKey", "uuid"} {
		if strings.Contains(out.String(), value) {
			t.Fatal("private inputs echoed")
		}
	}
	if runtime.GOOS != "linux" {
		out.Reset()
		if runRUTo("ru-init", append(ruArguments(), "--apply"), &out) == nil || !strings.Contains(out.String(), "LINUX_ROOT_REQUIRED") {
			t.Fatal("unsupported staging accepted")
		}
	}
}
func TestRUCLIRejectsArbitraryInputsWithoutEcho(t *testing.T) {
	marker := "private-argument-marker"
	for _, args := range [][]string{{"--endpoint", marker}, append(ruArguments(), "--input", marker), append(ruArguments(), "--client", marker), append(ruArguments(), "--tool", marker), append(ruArguments(), "--ready"), append(ruArguments(), marker)} {
		var out bytes.Buffer
		e := runRUTo("ru-init", args, &out)
		if e == nil || strings.Contains(e.Error(), marker) || strings.Contains(out.String(), marker) || !strings.Contains(out.String(), `"ready":false`) {
			t.Fatal("argument boundary or secret echo")
		}
	}
	for _, command := range []string{"ru-check", "ru-status"} {
		var out bytes.Buffer
		if runRUTo(command, []string{"--apply"}, &out) == nil {
			t.Fatal("read command accepted mutation")
		}
	}
}
