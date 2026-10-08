package foreignsetup

import (
	"bytes"
	"testing"
)

func TestNamespaceIPv4AdapterPreservesPrivatePair(t *testing.T) {
	b := generated(t)
	before := bytes.Clone(b.Xray)
	defer clear(before)
	x, e := NamespaceIPv4Config(b.Xray, b.RUHop)
	if e != nil {
		t.Fatal("IPv4 adapter rejected generated pair")
	}
	defer clear(x)
	if !bytes.Equal(b.Xray, before) || ValidateNamespaceIPv4Config(x, b.Xray, b.RUHop) != nil {
		t.Fatal("adapter mutated or failed exact binding")
	}
	var original, adapted xrayConfig
	if decode(b.Xray, &original) != nil || decode(x, &adapted) != nil || adapted.DNS.QueryStrategy != "UseIPv4" || adapted.Outbounds[1].Settings.DomainStrategy != "ForceIPv4" {
		t.Fatal("wrong IPv4 execution mode")
	}
	adapted.DNS.QueryStrategy = original.DNS.QueryStrategy
	adapted.Outbounds[1].Settings.DomainStrategy = original.Outbounds[1].Settings.DomainStrategy
	restored, _ := marshal(adapted)
	defer clear(restored)
	if !bytes.Equal(restored, b.Xray) {
		t.Fatal("adapter changed credentials, peers or policy")
	}
	if ValidateNamespaceIPv4Config(b.Xray, b.Xray, b.RUHop) == nil {
		t.Fatal("unadapted config accepted")
	}
	other := generated(t)
	if _, e := NamespaceIPv4Config(b.Xray, other.RUHop); e == nil {
		t.Fatal("unrelated pair accepted")
	}
	if _, e := NamespaceIPv4Config(bytes.Replace(b.Xray, []byte(`"blackhole"`), []byte(`"freedom"`), 1), b.RUHop); e == nil {
		t.Fatal("expanded original policy accepted")
	}
}

func TestNamespaceIPv4AdapterRejectsIPv6(t *testing.T) {
	for _, i := range []Inputs{
		{"[2606:4700:4700::1111]:443", "2001:4860:4860::8888", "[2606:4700:4700::1001]:443", "www.cloudflare.com"},
		{"8.8.8.8:443", "8.8.4.4", "[2606:4700:4700::1001]:443", "www.cloudflare.com"},
	} {
		b, e := Generate(i)
		if e != nil {
			t.Fatal("IPv6 original generation")
		}
		_, e = NamespaceIPv4Config(b.Xray, b.RUHop)
		b.Clear()
		if e == nil {
			t.Fatal("IPv6 endpoint, source or camouflage accepted by IPv4 adapter")
		}
	}
}
