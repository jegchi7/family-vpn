package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPreflightCLIRejectsUnsupportedFlagsWithoutEcho(t *testing.T) {
	secret := strings.Repeat("sensitive", 4)
	out := new(bytes.Buffer)
	if e := runProfilePreflight([]string{"--apply", secret}, strings.NewReader(secret), out); e == nil || strings.Contains(e.Error(), secret) {
		t.Fatal("invalid argument leakage")
	}
	if !strings.Contains(out.String(), "INVALID_TARGET") || strings.Contains(out.String(), secret) {
		t.Fatal("unsafe JSON report")
	}
	out.Reset()
	if e := runProfilePreflight(nil, strings.NewReader(secret), out); e == nil {
		t.Fatal("missing binding accepted")
	}
}
