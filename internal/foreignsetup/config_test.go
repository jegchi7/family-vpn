package foreignsetup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func inputs() Inputs {
	return Inputs{"8.8.8.8:443", "8.8.4.4", "1.0.0.1:443", "www.cloudflare.com"}
}
func generated(t *testing.T) Bundle {
	t.Helper()
	b, e := Generate(inputs())
	if e != nil {
		t.Fatal("generation failed", e)
	}
	t.Cleanup(b.Clear)
	return b
}

func TestGenerateClosedPrimaryAndMatchingPair(t *testing.T) {
	b := generated(t)
	s, e := ValidatePair(b.Xray, b.RUHop)
	if e != nil || !s.ConfigurationValidated || s.NativeSyntaxValidated || s.RuntimeInstalled || s.KernelGuardVerified || s.RoutingVerified || s.DNSVerified || s.ClientVerified || s.Ready || s.BackupConfigured {
		t.Fatal("unexpected evidence state")
	}
	var x xrayConfig
	var h ruHop
	if decode(b.Xray, &x) != nil || decode(b.RUHop, &h) != nil {
		t.Fatal("decode generated pair")
	}
	if x.Outbounds[0].Protocol != "blackhole" || x.Outbounds[1].Settings.DomainStrategy != "ForceIP" || len(x.Inbounds) != 1 || len(x.Inbounds[0].Settings.Clients) != 1 || x.Routing.DomainStrategy != "IPOnDemand" || x.Routing.Rules[1].Source[0] != "8.8.4.4/32" || x.Routing.Rules[1].InboundTag[0] != "foreign-primary" {
		t.Fatal("primary boundary")
	}
	for _, deny := range []string{"10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "168.63.129.16/32", "8.8.8.8/32", "8.8.4.4/32"} {
		found := false
		for _, d := range x.Routing.Rules[0].IP {
			found = found || d == deny
		}
		if !found {
			t.Fatal("missing policy destination class")
		}
	}
	if h.Type != "vless" || h.Flow != "xtls-rprx-vision" || h.PacketEncoding != "xudp" || !h.TLS.Enabled || !h.TLS.Reality.Enabled || h.TLS.Insecure || !h.TLS.UTLS.Enabled || h.TLS.Reality.ShortID != x.Inbounds[0].Stream.Reality.ShortIDs[0] || h.UUID != x.Inbounds[0].Settings.Clients[0].ID || bytes.Contains(b.RUHop, []byte(x.Inbounds[0].Stream.Reality.PrivateKey)) {
		t.Fatal("hop secrecy or transport mismatch")
	}
}

func TestGenerateFreshCredentialsAndMixRejected(t *testing.T) {
	ids, keys, shorts := map[string]bool{}, map[string]bool{}, map[string]bool{}
	previous := generated(t)
	for range 8 {
		b := generated(t)
		var h ruHop
		decode(b.RUHop, &h)
		if ids[h.UUID] || keys[h.TLS.Reality.PublicKey] || shorts[h.TLS.Reality.ShortID] {
			t.Fatal("generated credential reused")
		}
		ids[h.UUID], keys[h.TLS.Reality.PublicKey], shorts[h.TLS.Reality.ShortID] = true, true, true
		if _, e := ValidatePair(previous.Xray, b.RUHop); !errors.Is(e, ErrConfig) {
			t.Fatal("unrelated pair accepted")
		}
	}
}

func TestPreparationInputBoundaries(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.2.3.4", "100.100.100.200", "169.254.169.254", "168.63.129.16", "192.0.2.1", "198.18.1.1", "224.0.0.1", "255.255.255.255", "::1", "::ffff:8.8.8.8", "fc00::1", "fe80::1", "fe80::1%eth0", "64:ff9b::808:808", "2001:db8::1", "2002:808:808::1", "3fff::1", "2001:20::1", "8.008.8.8", "private-name.example"} {
		i := inputs()
		i.RUSource = ip
		if !errors.Is(ValidateInputs(i), ErrInput) {
			t.Fatal("special-use or nonliteral source accepted")
		}
	}
	for _, mutate := range []func(*Inputs){
		func(i *Inputs) { i.Endpoint = "8.8.8.8:8443" },
		func(i *Inputs) { i.Endpoint = "edge.example:443" },
		func(i *Inputs) { i.RealityTarget = i.Endpoint },
		func(i *Inputs) { i.RealityTarget = "8.8.4.4:443" },
		func(i *Inputs) { i.RUSource = "8.8.8.8" },
		func(i *Inputs) { i.RUSource = "2001:4860:4860::8888" },
		func(i *Inputs) { i.ServerName = "localhost" },
		func(i *Inputs) { i.ServerName = "host.home.arpa" },
		func(i *Inputs) { i.ServerName = "UPPER.example.com" },
		func(i *Inputs) { i.ServerName = "8.8.8.8" },
		func(i *Inputs) { i.ServerName = "evil.com\nvalue" },
		func(i *Inputs) { i.ServerName = "xn--.com" },
		func(i *Inputs) { i.ServerName = "www.cloudflare.com." },
	} {
		i := inputs()
		mutate(&i)
		if !errors.Is(ValidateInputs(i), ErrInput) {
			t.Fatal("invalid preparation accepted")
		}
		if b, e := Generate(i); !errors.Is(e, ErrInput) || len(b.Xray) != 0 || len(b.RUHop) != 0 {
			t.Fatal("invalid preparation generated secret material")
		}
	}
	i := Inputs{"[2606:4700:4700::1111]:443", "2001:4860:4860::8888", "[2606:4700:4700::1001]:443", "www.cloudflare.com"}
	b, e := Generate(i)
	if e != nil {
		t.Fatal("public IPv6 preparation")
	}
	defer b.Clear()
	if _, e := ValidatePair(b.Xray, b.RUHop); e != nil {
		t.Fatal("IPv6 generated validation")
	}
}

func TestPairRejectsPolicyExpansionAliasesAndSecretErrors(t *testing.T) {
	b := generated(t)
	bad := [][]byte{
		nil,
		[]byte("null"),
		append(bytes.Clone(b.Xray), []byte(" {}")...),
		bytes.Repeat([]byte(" "), MaxSize+1),
		bytes.Replace(b.Xray, []byte(`"log":`), []byte(`"extra":"sensitive-input-marker","log":`), 1),
		bytes.Replace(b.Xray, []byte(`"loglevel": "none"`), []byte(`"loglevel": "none", "loglevel": "none"`), 1),
		bytes.Replace(b.Xray, []byte(`"loglevel": "none"`), []byte(`"loglevel": "none", "LogLevel": "none"`), 1),
		bytes.Replace(b.Xray, []byte(`"privateKey":`), []byte(`"PrivateKey":`), 1),
		bytes.Replace(b.Xray, []byte(`"privateKey":`), []byte(`"masterKeyLog":"sensitive-input-marker", "privateKey":`), 1),
		bytes.Replace(b.Xray, []byte(`"10.0.0.0/8",`), nil, 1),
		bytes.Replace(b.Xray, []byte(`"ForceIP"`), []byte(`"AsIs"`), 1),
		bytes.Replace(b.Xray, []byte(`"blackhole"`), []byte(`"freedom"`), 1),
		bytes.Replace(b.Xray, []byte(`"8.8.4.4/32"`), []byte(`"0.0.0.0/0"`), 2),
		bytes.Replace(b.Xray, []byte(`"show": false`), []byte(`"show": true`), 1),
		bytes.Replace(b.Xray, []byte(`"port": 443`), []byte(`"port": 443.0`), 1),
		bytes.Replace(b.Xray, []byte(`"target": "1.0.0.1:443"`), []byte(`"target": "127.0.0.1:443"`), 1),
		bytes.Replace(b.Xray, []byte(`"loglevel": "none"`), []byte(`"loglevel": null`), 1),
	}
	for _, x := range bad {
		s, e := ValidatePair(x, b.RUHop)
		if !errors.Is(e, ErrConfig) || s.ConfigurationValidated || s.Ready || strings.Contains(e.Error(), "sensitive-input-marker") || strings.Contains(e.Error(), "privateKey") || bytes.Contains(x, []byte(e.Error())) {
			t.Fatal("unsafe configuration accepted or leaked")
		}
	}
	for _, h := range [][]byte{
		bytes.Replace(b.RUHop, []byte(`"insecure": false`), []byte(`"insecure": true`), 1),
		bytes.Replace(b.RUHop, []byte(`"type": "vless"`), []byte(`"type": "direct"`), 1),
		bytes.Replace(b.RUHop, []byte(`"tls":`), []byte(`"detour":"direct","tls":`), 1),
		bytes.Replace(b.RUHop, []byte(`"packet_encoding": "xudp"`), []byte(`"packet_encoding": ""`), 1),
	} {
		if _, e := ValidatePair(b.Xray, h); !errors.Is(e, ErrConfig) {
			t.Fatal("unsafe hop accepted")
		}
	}
}

func TestSensitiveBundleCannotBecomeReport(t *testing.T) {
	b := generated(t)
	if _, e := json.Marshal(b); e == nil {
		t.Fatal("sensitive bundle serialized")
	}
	for _, s := range []string{fmt.Sprint(b), fmt.Sprintf("%#v", b)} {
		if strings.Contains(s, "privateKey") || strings.Contains(s, "uuid") || strings.Contains(s, "8.8.8.8") {
			t.Fatal("sensitive bundle formatted")
		}
	}
	b.Clear()
	if len(b.Xray) != 0 || len(b.RUHop) != 0 {
		t.Fatal("bundle clear")
	}
}

func FuzzValidatePairClosed(f *testing.F) {
	// Fuzz inputs may be persisted by Go. Never seed with generated credentials;
	// positive matching-key round trips are exercised only in memory above.
	f.Add([]byte(`{}`), []byte(`{}`))
	f.Add([]byte(`null`), []byte(`[]`))
	f.Add([]byte(`{"log":{},"log":{}}`), []byte(`{}`))
	f.Fuzz(func(t *testing.T, x, h []byte) {
		s, e := ValidatePair(x, h)
		if e == nil && (!s.ConfigurationValidated || s.Ready || s.KernelGuardVerified || s.RuntimeInstalled || s.NativeSyntaxValidated || s.ClientVerified || s.RoutingVerified) {
			t.Fatal("parser created stronger evidence")
		}
		if e != nil && !errors.Is(e, ErrConfig) {
			t.Fatal("non-sanitized parser error")
		}
	})
}
