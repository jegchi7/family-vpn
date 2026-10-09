package netstand

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"familyvpn.local/platform/internal/netguard"
)

func TestNetworkEnvironmentMetadataCannotSupplyWriteAuthority(t *testing.T) {
	i, target, v, p := syntheticPlan(t)
	a, _ := buildArtifacts(i, target, v, p)
	if _, e := validateArtifacts(a); e != nil {
		t.Fatal(e)
	}
	var m manifest
	_ = json.Unmarshal(a.Manifest, &m)
	for _, mutate := range []func(*manifest){
		func(m *manifest) { m.Coexistence.LegacyForward = true },
		func(m *manifest) { m.Coexistence.NFTSHA256 = strings.Repeat("a", 64) },
		func(m *manifest) { m.ForwardingExpectedSHA256 = strings.Repeat("b", 64) },
		func(m *manifest) { m.Target.XTLegacySHA256 = strings.Repeat("d", 64) },
		func(m *manifest) { m.Format = 1 },
	} {
		changed := m
		mutate(&changed)
		bad := a
		bad.Manifest, _ = json.Marshal(changed)
		if _, e := validateArtifacts(bad); e == nil {
			t.Fatal("unsupported metadata accepted")
		}
	}
	v.IPv4Forwarding = false
	p, _ = netguard.Build(i, v)
	a, _ = buildArtifacts(i, target, v, p)
	if _, e := validateArtifacts(a); e == nil {
		t.Fatal("zero forwarding accepted without preservation binding")
	}
	a, m, p, e := bindEnvironment(a, coexistence{}, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if e != nil {
		t.Fatal(e)
	}
	if _, e := validateArtifacts(a); e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(p.HostFirewall, []byte("\n  drop\n }\n")) {
		t.Fatal("zero baseline lost unrelated forwarding guard")
	}
	s := summary(m)
	if s.KernelGuardVerified || s.Ready || s.ClientVerified || s.NativeAcceptance || s.ServicesStarted || s.NetworkChanged {
		t.Fatal("stored fingerprint became runtime proof")
	}
}

func TestForeignSupplementsRemainBeforeActivationAndAfterOwnedGuard(t *testing.T) {
	i, target, v, p := syntheticPlan(t)
	i.Role, i.HostPublicIPv4 = "foreign", i.ForeignIPv4
	v.Addresses[1].Prefix = netip.MustParsePrefix("1.1.1.1/24")
	target.XTLegacySHA256 = strings.Repeat("e", 64)
	p, e := netguard.Build(i, v)
	if e != nil {
		t.Fatal(e)
	}
	a, _ := buildArtifacts(i, target, v, p)
	c := coexistence{NFTSHA256: strings.Repeat("a", 64), LegacySHA256: strings.Repeat("b", 64), LegacyIPv6SHA256: strings.Repeat("c", 64), LegacyForward: true, NFTForward: true}
	a, m, augmented, e := bindEnvironment(a, c, "", "")
	if e != nil {
		t.Fatal(e)
	}
	// This non-secret placeholder exercises only protected artifact mechanics;
	// it is never a native core configuration or an acceptance fixture.
	a.ForeignXray = []byte("{}")
	m.ForeignSHA256 = hash(a.ForeignXray)
	a.Manifest, _ = json.Marshal(m)
	if _, e := validateArtifacts(a); e != nil {
		t.Fatal(e)
	}
	if len(augmented.Steps) != len(p.Steps)+4 || m.Steps != len(augmented.Steps) {
		t.Fatal("supplement journal boundaries missing")
	}
	if !bytes.Equal(augmented.Steps[0].Stdin, p.HostFirewall) {
		t.Fatal("supplement precedes independent owned guard")
	}
	firstUp := -1
	for n, step := range augmented.Steps {
		if activationStep(step) {
			firstUp = n
			break
		}
	}
	if firstUp < 4 {
		t.Fatal("activation boundary missing")
	}
	for _, backend := range []string{"legacy", "nft"} {
		steps, _ := netguard.DockerForwardInsertions(backend)
		for _, want := range steps {
			found := false
			for n, actual := range augmented.Steps {
				if actual.Executable == want.Executable && equalStrings(actual.Args, want.Args) && bytes.Equal(actual.Stdin, want.Stdin) {
					found = n < firstUp
				}
			}
			if !found {
				t.Fatal("supplement escaped closed pre-activation plan")
			}
		}
	}
	m.Coexistence.NFTForward = false
	a.Manifest, _ = json.Marshal(m)
	if _, e := validateArtifacts(a); e == nil {
		t.Fatal("changed supplemental steps accepted")
	}
}

func TestForwardingSysctlObservationHasExplicitPhase(t *testing.T) {
	zero := []byte("0\n1\n1\n0\n0\n0\n1\n")
	one := []byte("1\n1\n1\n0\n0\n0\n1\n")
	if validateKernelSysctlsPhase("host", zero, false, false) != nil || validateKernelSysctlsPhase("host", one, true, false) != nil {
		t.Fatal("expected phase rejected")
	}
	if validateKernelSysctlsPhase("host", one, false, false) == nil || validateKernelSysctlsPhase("host", zero, true, false) == nil {
		t.Fatal("unexpected global forwarding accepted")
	}
	for _, data := range [][]byte{zero, one} {
		if validateKernelSysctlsPhase("host", data, false, true) != nil {
			t.Fatal("grouped transition phase rejected")
		}
		bad := bytes.Clone(data)
		bad[len(bad)-2] = '0'
		if validateKernelSysctlsPhase("host", bad, false, true) == nil {
			t.Fatal("transition bypassed owned interface setting")
		}
	}
}
