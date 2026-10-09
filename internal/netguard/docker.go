package netguard

import (
	"errors"
	"net/netip"
)

var ErrDockerScope = errors.New("existing container packet rewrite is outside supported VPN scope")

// DockerScope describes only independently observed, nonoverlapping topology.
// It is neither a Docker identity attestation nor kernel/client acceptance.
// The caller must obtain fresh rules from fixed pinned helpers in the expected
// host namespace. Only the owner's Foreign docker0/amn0 bridge subset is known.
type DockerScope struct {
	bridges map[string]netip.Prefix
	local   map[netip.Addr]bool
	public  netip.Addr
	transit netip.Prefix
	valid   bool
}

func ForeignDockerScope(i Inputs, v Inventory) (DockerScope, error) {
	if ValidateInputs(i) != nil || i.Role != "foreign" || validateInventory(i, v) != nil {
		return DockerScope{}, ErrDockerScope
	}
	s := DockerScope{bridges: map[string]netip.Prefix{}, local: map[netip.Addr]bool{}, public: i.HostPublicIPv4, transit: i.Transit, valid: true}
	for _, a := range v.Addresses {
		if !a.Prefix.Addr().Is4() {
			continue
		}
		s.local[a.Prefix.Addr()] = true
		if a.Interface != "docker0" && a.Interface != "amn0" {
			continue
		}
		p := a.Prefix.Masked()
		private := false
		for _, allowed := range []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16")} {
			private = private || p.Bits() >= allowed.Bits() && allowed.Contains(p.Addr())
		}
		if !private || p.Bits() > 30 || p.Overlaps(i.Transit) {
			return DockerScope{}, ErrDockerScope
		}
		if _, duplicate := s.bridges[a.Interface]; duplicate {
			return DockerScope{}, ErrDockerScope
		}
		for _, other := range s.bridges {
			if other.Overlaps(p) {
				return DockerScope{}, ErrDockerScope
			}
		}
		s.bridges[a.Interface] = p
	}
	return s, nil
}

func (s DockerScope) bridgePrefix(p netip.Prefix) (string, bool) {
	if !s.valid || !p.IsValid() || !p.Addr().Is4() || p != p.Masked() || p.Overlaps(s.transit) {
		return "", false
	}
	for name, bridge := range s.bridges {
		if p.Bits() >= bridge.Bits() && bridge.Contains(p.Addr()) {
			return name, true
		}
	}
	return "", false
}

func (s DockerScope) container(a netip.Addr) (string, bool) {
	if !a.Is4() || s.local[a] {
		return "", false
	}
	return s.bridgePrefix(netip.PrefixFrom(a, 32))
}

type dockerRule struct {
	chain, target, protocol, in, out string
	negIn, negOut                    bool
	source, destination              netip.Prefix
	negSource, negDestination        bool
	sourceLocal, destinationLocal    bool
	port                             int
	translation                      netip.Addr
	translationPort                  int
	extraMatch                       bool
}

// dockerNATRule accepts exact disjoint recipes, not chains merely named DOCKER.
// The fixed UDP30759 publication is independent of our TCP443 ingress. Source
// NAT requires a positive disjoint bridge source or positive LOCAL source and
// bridge output. DNAT is reachable only from LOCAL-destination entry jumps.
func dockerNATRule(s DockerScope, r dockerRule) bool {
	if !s.valid || r.negSource || r.sourceLocal && r.source.IsValid() {
		return false
	}
	switch r.target {
	case "DOCKER":
		return (r.chain == "PREROUTING" || r.chain == "OUTPUT") && r.destinationLocal && !r.sourceLocal && !r.source.IsValid() && r.in == "" && r.out == "" && r.protocol == "" && r.port == 0 && !r.translation.IsValid() && (!r.destination.IsValid() || r.negDestination && r.destination == netip.MustParsePrefix("127.0.0.0/8"))
	case "RETURN":
		_, bridge := s.bridges[r.in]
		return r.chain == "DOCKER" && bridge && !r.negIn && r.out == "" && !r.source.IsValid() && !r.destination.IsValid() && !r.sourceLocal && !r.destinationLocal && r.protocol == "" && r.port == 0 && !r.translation.IsValid()
	case "DNAT":
		bridge, container := s.container(r.translation)
		if r.chain != "DOCKER" || !container || r.protocol != "udp" || r.port != 30759 || r.translationPort != 30759 || r.in != bridge || !r.negIn || r.out != "" || r.source.IsValid() || r.sourceLocal || r.destinationLocal || r.negDestination {
			return false
		}
		return !r.destination.IsValid() || r.destination.Bits() == 32 && s.local[r.destination.Addr()]
	case "MASQUERADE", "SNAT":
		if r.chain != "POSTROUTING" || r.in != "" || r.destinationLocal || r.negDestination || r.translationPort != 0 {
			return false
		}
		if r.target == "MASQUERADE" && r.translation.IsValid() || r.target == "SNAT" && r.translation != s.public {
			return false
		}
		if r.sourceLocal {
			_, bridge := s.bridges[r.out]
			return bridge && !r.negOut && !r.source.IsValid() && !r.destination.IsValid() && r.protocol == "" && r.port == 0
		}
		bridge, disjoint := s.bridgePrefix(r.source)
		if !disjoint {
			return false
		}
		if !r.destination.IsValid() {
			return r.out == bridge && r.negOut && r.protocol == "" && r.port == 0
		}
		// Docker's hairpin SNAT matches one exact container at both ends.
		_, container := s.container(r.source.Addr())
		return container && r.source.Bits() == 32 && r.source == r.destination && r.out == "" && r.protocol == "udp" && r.port == 30759
	}
	return false
}
