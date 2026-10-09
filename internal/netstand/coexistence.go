package netstand

import (
	"encoding/json"
	"familyvpn.local/platform/internal/netguard"
)

// Digests bind reviewed policy, not Docker identity or traffic acceptance.
// No raw rule snapshot or restoration command is persisted.
type coexistence struct {
	NFTSHA256        string `json:"nft_sha256,omitempty"`
	LegacySHA256     string `json:"legacy_sha256,omitempty"`
	LegacyIPv6SHA256 string `json:"legacy_ipv6_sha256,omitempty"`
	LegacyForward    bool   `json:"legacy_forward"`
	NFTForward       bool   `json:"nft_forward"`
}

func (c coexistence) valid(i netguard.Inputs, t Target) error {
	if i.Role != "foreign" {
		if c != (coexistence{}) {
			return ErrProtected
		}
		return nil
	}
	if !digestValid(c.NFTSHA256) {
		return ErrProtected
	}
	if t.XTLegacySHA256 == "" {
		if c.LegacySHA256 != "" || c.LegacyIPv6SHA256 != "" || c.LegacyForward {
			return ErrProtected
		}
	} else if !digestValid(c.LegacySHA256) || !digestValid(c.LegacyIPv6SHA256) {
		return ErrProtected
	}
	return nil
}

func validatePreservationMetadata(m manifest) error {
	if m.IPv4ForwardingBefore {
		if m.ForwardingBaselineSHA256 != "" || m.ForwardingExpectedSHA256 != "" {
			return ErrProtected
		}
	} else if !digestValid(m.ForwardingBaselineSHA256) || !digestValid(m.ForwardingExpectedSHA256) || m.ForwardingBaselineSHA256 == m.ForwardingExpectedSHA256 {
		return ErrProtected
	}
	return nil
}

func isForwardingEnable(s netguard.Step) bool {
	return s.Scope == "host" && s.Executable == netguard.SysctlExecutable && equalStrings(s.Args, []string{"-w", "net.ipv4.ip_forward=1"}) && len(s.Stdin) == 0
}

func coexistencePlan(p netguard.Plan, c coexistence) (netguard.Plan, error) {
	var added []netguard.Step
	for _, item := range []struct {
		needed  bool
		backend string
	}{{c.LegacyForward, "legacy"}, {c.NFTForward, "nft"}} {
		if !item.needed {
			continue
		}
		steps, e := netguard.DockerForwardInsertions(item.backend)
		if e != nil {
			return netguard.Plan{}, ErrProtected
		}
		added = append(added, steps...)
	}
	if len(added) == 0 {
		return p, nil
	}
	for n, s := range p.Steps {
		if !activationStep(s) {
			continue
		}
		steps := append([]netguard.Step(nil), p.Steps[:n]...)
		steps = append(steps, added...)
		p.Steps = append(steps, p.Steps[n:]...)
		return p, nil
	}
	return netguard.Plan{}, ErrProtected
}

func bindEnvironment(a artifacts, c coexistence, baseline, expected string) (artifacts, manifest, netguard.Plan, error) {
	var m manifest
	if json.Unmarshal(a.Manifest, &m) != nil {
		return artifacts{}, m, netguard.Plan{}, ErrProtected
	}
	m.Coexistence = c
	m.ForwardingBaselineSHA256, m.ForwardingExpectedSHA256 = baseline, expected
	if c.valid(m.Inputs, m.Target) != nil || validatePreservationMetadata(m) != nil {
		return artifacts{}, m, netguard.Plan{}, ErrProtected
	}
	p, e := netguard.Build(m.Inputs, m.Inventory)
	if e == nil {
		p, e = coexistencePlan(p, c)
	}
	if e != nil {
		return artifacts{}, m, netguard.Plan{}, ErrProtected
	}
	m.Steps = len(p.Steps)
	a.Manifest, e = json.Marshal(m)
	return a, m, p, e
}
