package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestForeignDryRunAndArgumentsRedacted(t *testing.T) {
	valid := []string{"--endpoint", "8.8.8.8:443", "--ru-source", "8.8.4.4", "--reality-target", "1.0.0.1:443", "--server-name", "www.cloudflare.com"}
	var b bytes.Buffer
	if e := runForeignTo("foreign-init", valid, &b); e != nil {
		t.Fatal("dry-run failed")
	}
	var r map[string]any
	if json.Unmarshal(b.Bytes(), &r) != nil || r["status"] != "planned" || r["read_only"] != true || r["configuration_validated"] != false || r["native_syntax_validated"] != false || r["runtime_installed"] != false || r["ready"] != false || r["network_changed"] != false {
		t.Fatal("dry-run creates evidence")
	}
	if strings.Contains(b.String(), "8.8.8.8") || strings.Contains(b.String(), "www.cloudflare.com") {
		t.Fatal("dry-run exposes operator inputs")
	}
	for _, tc := range []struct {
		command string
		args    []string
	}{
		{"foreign-init", []string{"--unknown", "sensitive-input-marker"}},
		{"foreign-init", []string{"--endpoint", "sensitive-input-marker"}},
		{"foreign-init", append(append([]string{}, valid...), "--native-check")},
		{"foreign-check", []string{"--input", "sensitive-input-marker"}},
		{"foreign-check", []string{"--tool", "sensitive-input-marker"}},
		{"foreign-status", []string{"--apply"}},
		{"foreign-status", []string{"sensitive-input-marker"}},
	} {
		b.Reset()
		e := runForeignTo(tc.command, tc.args, &b)
		if e == nil || strings.Contains(e.Error(), "sensitive-input-marker") || strings.Contains(b.String(), "sensitive-input-marker") || strings.Contains(b.String(), "8.8.8.8") {
			t.Fatal("invalid argument accepted or exposed")
		}
		if json.Unmarshal(b.Bytes(), &r) != nil || r["status"] != "blocked" || r["ready"] != false {
			t.Fatal("bad argument report")
		}
	}
}
