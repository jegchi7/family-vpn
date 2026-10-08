package coreinstall

import (
	"errors"
	"strings"
	"testing"
)

func TestCompatibilityVersionsFollowArtifactPins(t *testing.T) {
	for _, core := range []string{"xray", "sing-box", "hysteria"} {
		c, e := ConfigurationCompatibility(core)
		if e != nil || c.Core != core || c.NativeAcceptance || c.ClientAcceptance || c.Ready || len(c.Blockers) == 0 {
			t.Fatal("format contract incorrectly certifies runtime or client")
		}
		for _, arch := range []string{"amd64", "arm64"} {
			a, e := Lookup(core, arch)
			if e != nil || a.Version != c.Version || !strings.Contains(a.URL, "/v"+c.Version+"/") {
				t.Fatal("configuration and installer versions disagree")
			}
		}
		c.Blockers[0] = "changed"
		fresh, _ := ConfigurationCompatibility(core)
		if fresh.Blockers[0] == "changed" {
			t.Fatal("mutable shared contract")
		}
	}
	for _, core := range []string{"awg", "XRAY", "direct", ""} {
		if _, e := ConfigurationCompatibility(core); !errors.Is(e, ErrArguments) {
			t.Fatal("unsupported configuration contract accepted")
		}
	}
}
