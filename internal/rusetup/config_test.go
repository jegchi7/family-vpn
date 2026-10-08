package rusetup

import (
	"bytes"
	"encoding/json"
	"familyvpn.local/platform/internal/foreignsetup"
	"fmt"
	"strings"
	"testing"
)

func inputs() Inputs {
	return Inputs{"8.8.4.4:443", "8.8.8.8:443", "1.0.0.1:443", "www.cloudflare.com"}
}
func hopForTest(t *testing.T) []byte {
	t.Helper()
	b, e := foreignsetup.Generate(foreignsetup.Inputs{Endpoint: "8.8.8.8:443", RUSource: "8.8.4.4", RealityTarget: "1.1.1.1:443", ServerName: "www.cloudflare.com"})
	if e != nil {
		t.Fatal("Foreign fixture generation")
	}
	t.Cleanup(b.Clear)
	return b.RUHop
}
func bundleForTest(t *testing.T) Bundle {
	t.Helper()
	b, e := Generate(inputs(), hopForTest(t))
	if e != nil {
		t.Fatal("RU fixture generation", e)
	}
	t.Cleanup(b.Clear)
	return b
}
func TestRUPrimaryTopologyClosedAndClientPending(t *testing.T) {
	hop := hopForTest(t)
	b, err := Generate(inputs(), hop)
	if err != nil {
		t.Fatal("RU generation")
	}
	defer b.Clear()
	s, binding, e := ValidateBundle(b)
	if e != nil || !s.ConfigurationValidated || s.ClientBindingConfigured || s.NativeSyntaxValidated || s.RuntimeInstalled || s.KernelGuardVerified || s.RoutingVerified || s.DNSVerified || s.ClientVerified || s.Ready {
		t.Fatal("unexpected RU evidence")
	}
	if binding.RUIPv4 != "8.8.4.4" || binding.ForeignIPv4 != "8.8.8.8" || binding.RealityTargetIPv4 != "1.0.0.1" {
		t.Fatal("wrong independent network binding")
	}
	var x xConfig
	var sing singConfig
	if decode(b.Xray, &x) != nil || decode(b.SingBox, &sing) != nil {
		t.Fatal("private config decode")
	}
	if len(x.Inbounds) != 1 || x.Inbounds[0].Listen != "0.0.0.0" || x.Inbounds[0].Port != 443 || len(x.Inbounds[0].Settings.Clients) != 0 || x.Inbounds[0].Stream.Reality.Target != "127.0.0.1:10443" || x.Outbounds[0].Protocol != "blackhole" || x.Outbounds[1].Protocol != "socks" || !bytes.Contains(x.Outbounds[1].Settings, []byte("127.0.0.1")) || x.Routing.DomainStrategy != "AsIs" {
		t.Fatal("Xray ingress bypass or unowned peer")
	}
	if len(sing.Inbounds) != 2 || sing.Inbounds[0].Type != "socks" || sing.Inbounds[0].Listen != "127.0.0.1" || sing.Inbounds[0].ListenPort != 1080 || sing.Inbounds[1].Type != "direct" || sing.Inbounds[1].Listen != "127.0.0.1" || sing.Inbounds[1].ListenPort != 10443 || sing.Inbounds[1].OverrideAddress != "1.0.0.1" || sing.Inbounds[1].OverridePort != 443 || sing.Inbounds[1].Network != "tcp" || sing.Route.Final != "foreign-primary" || len(sing.Outbounds) != 1 || !bytes.Contains(sing.Outbounds[0], []byte(`"type": "vless"`)) {
		t.Fatal("camouflage relay or Foreign-only route mismatch")
	}
	if !bytes.Equal(b.Hop, hop) {
		t.Fatal("hop original bytes altered")
	}
}
func TestRUInputsAndIndependentHopRejectBoundaries(t *testing.T) {
	hop := hopForTest(t)
	for _, change := range []func(*Inputs){func(i *Inputs) { i.Endpoint = "127.0.0.1:443" }, func(i *Inputs) { i.ForeignEndpoint = i.Endpoint }, func(i *Inputs) { i.ForeignEndpoint = "[2606:4700:4700::1111]:443" }, func(i *Inputs) { i.RealityTarget = "10.1.2.3:443" }, func(i *Inputs) { i.RealityTarget = i.ForeignEndpoint }, func(i *Inputs) { i.RealityTarget = "1.0.0.1:8443" }, func(i *Inputs) { i.ServerName = "localhost" }} {
		i := inputs()
		change(&i)
		if ValidateInputs(i) == nil {
			t.Fatal("invalid RU input accepted")
		}
		if _, e := Generate(i, hop); e == nil {
			t.Fatal("invalid input generated secrets")
		}
	}
	i := inputs()
	i.ForeignEndpoint = "9.9.9.9:443"
	if ValidateInputs(i) != nil {
		t.Fatal("valid independent alternate endpoint rejected")
	}
	if _, e := Generate(i, hop); e == nil {
		t.Fatal("hop endpoint autopicked")
	}
	for _, h := range [][]byte{nil, []byte(`{}`), append(bytes.Clone(hop), ' '), bytes.Replace(hop, []byte(`"type": "vless"`), []byte(`"type": "direct"`), 1), bytes.Replace(hop, []byte(`"tls":`), []byte(`"detour":"direct","tls":`), 1)} {
		if _, e := Generate(inputs(), h); e == nil {
			t.Fatal("expanded hop accepted")
		}
	}
}
func TestRURejectsConfigExpansionRelayLeakAndSecretFormatting(t *testing.T) {
	b := bundleForTest(t)
	for _, bad := range [][]byte{bytes.Replace(b.Xray, []byte(`"127.0.0.1:10443"`), []byte(`"1.0.0.1:443"`), 1), bytes.Replace(b.Xray, []byte(`"blackhole"`), []byte(`"freedom"`), 1), bytes.Replace(b.Xray, []byte(`"clients": []`), []byte(`"clients": [],"Clients": []`), 1)} {
		copy := b
		copy.Xray = bad
		if _, _, e := ValidateBundle(copy); e == nil {
			t.Fatal("Xray bypass accepted")
		}
	}
	for _, bad := range [][]byte{bytes.Replace(b.SingBox, []byte(`"listen": "127.0.0.1"`), []byte(`"listen": "0.0.0.0"`), 1), bytes.Replace(b.SingBox, []byte(`"final": "foreign-primary"`), []byte(`"final": "direct"`), 1), bytes.Replace(b.SingBox, []byte(`"override_address": "1.0.0.1"`), []byte(`"override_address": "127.0.0.1"`), 1)} {
		copy := b
		copy.SingBox = bad
		if _, _, e := ValidateBundle(copy); e == nil {
			t.Fatal("relay escape accepted")
		}
	}
	if _, e := json.Marshal(b); e == nil {
		t.Fatal("private bundle serialized")
	}
	for _, formatted := range []string{fmt.Sprint(b), fmt.Sprintf("%#v", b)} {
		if strings.Contains(formatted, "privateKey") || strings.Contains(formatted, "uuid") || strings.Contains(formatted, "8.8.8.8") {
			t.Fatal("private bundle leaked")
		}
	}
	b.Clear()
	if len(b.Xray) != 0 || len(b.SingBox) != 0 || len(b.Hop) != 0 || len(b.Plan) != 0 {
		t.Fatal("private bundle not cleared")
	}
}

func FuzzRUClosedNegative(f *testing.F) {
	f.Add([]byte(`{}`), []byte(`{}`), []byte(`{}`), []byte(`{}`))
	f.Fuzz(func(t *testing.T, x, s, h, p []byte) {
		out, _, e := ValidateBundle(Bundle{x, s, h, p})
		if e == nil && (out.Ready || out.ClientVerified || out.RuntimeInstalled || out.NativeSyntaxValidated) {
			t.Fatal("parser created readiness")
		}
	})
}
