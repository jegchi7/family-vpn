package foreignsetup

import (
	"bytes"
	"net/netip"
)

type IPv4Binding struct{ RUIPv4, ForeignIPv4 string }

// NamespaceIPv4Config derives a NEW private, IPv4-only execution config from
// the exact original staged pair. It never rewrites the original or changes its
// credential, peer, deny-list or source binding. The generated DNS/freedom mode
// alone is not a kernel guard or a proof about a responding namespace/core.
func NamespaceIPv4Config(original, hop []byte) ([]byte, error) {
	if _, e := ValidatePair(original, hop); e != nil {
		return nil, ErrConfig
	}
	f, e := ValidateRUHop(hop)
	addr, ae := netip.ParseAddr(f)
	if e != nil || ae != nil || !addr.Is4() {
		return nil, ErrConfig
	}
	var x xrayConfig
	if decode(original, &x) != nil {
		return nil, ErrConfig
	}
	source, se := netip.ParsePrefix(x.Routing.Rules[1].Source[0])
	target, te := netip.ParseAddrPort(x.Inbounds[0].Stream.Reality.Target)
	if se != nil || te != nil || !source.Addr().Is4() || source.Bits() != 32 || !target.Addr().Is4() {
		return nil, ErrConfig
	}
	x.DNS.QueryStrategy = "UseIPv4"
	x.Outbounds[1].Settings.DomainStrategy = "ForceIPv4"
	return marshal(x)
}

// ValidateNamespaceIPv4Config accepts only the exact derived bytes and the
// separately preserved original protected pair, not arbitrary Xray configs.
func ValidateNamespaceIPv4Config(config, original, hop []byte) error {
	expected, e := NamespaceIPv4Config(original, hop)
	if e != nil {
		return ErrConfig
	}
	defer clear(expected)
	if !bytes.Equal(config, expected) {
		return ErrConfig
	}
	return nil
}
