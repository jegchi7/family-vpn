package netguard

import (
	"encoding/json"
	"net/netip"
	"strconv"
)

// RequireScopedHostRewrite retains the conservative whole-ruleset gate, with
// one closed Foreign IPv4 ip/nat Docker subset checked independently. Unknown
// nft/xt extensions, route chains, CT writes, maps and offload still fail. This
// comparator cannot authenticate the source of JSON, nor prove traffic passes.
func RequireScopedHostRewrite(data []byte, scope DockerScope) error {
	if !scope.valid {
		return ErrDockerScope
	}
	v, err := readNFTJSON(data)
	if err != nil {
		return ErrDockerScope
	}
	root, ok := v.(map[string]any)
	if !ok || len(root) != 1 {
		return ErrDockerScope
	}
	objects, ok := root["nftables"].([]any)
	if !ok || len(objects) == 0 || len(objects) > 8192 {
		return ErrDockerScope
	}
	kept := []any{}
	table := savedTable{chains: map[string]*savedChain{}}
	tableSeen := false
	for _, raw := range objects {
		wrapper, ok := raw.(map[string]any)
		if !ok || len(wrapper) != 1 {
			return ErrDockerScope
		}
		for kind, value := range wrapper {
			m, ok := value.(map[string]any)
			if !ok {
				return ErrDockerScope
			}
			name, _ := m["table"].(string)
			if kind == "table" {
				name, _ = m["name"].(string)
			}
			if m["family"] != "ip" || name != "nat" {
				kept = append(kept, raw)
				continue
			}
			if stripHandle(m) != nil {
				return ErrDockerScope
			}
			switch kind {
			case "table":
				if len(m) != 2 || tableSeen {
					return ErrDockerScope
				}
				tableSeen = true
			case "chain":
				chainName, ok := m["name"].(string)
				if !ok || !savedName(chainName) || table.chains[chainName] != nil {
					return ErrDockerScope
				}
				chain := &savedChain{policy: "-"}
				if chainName == "DOCKER" {
					if len(m) != 3 {
						return ErrDockerScope
					}
				} else {
					hook, priority := "", json.Number("0")
					switch chainName {
					case "PREROUTING":
						hook, priority = "prerouting", json.Number("-100")
					case "OUTPUT":
						hook, priority = "output", json.Number("-100")
					case "INPUT":
						hook, priority = "input", json.Number("100")
					case "POSTROUTING":
						hook, priority = "postrouting", json.Number("100")
					default:
						return ErrDockerScope
					}
					if len(m) != 7 || m["type"] != "nat" || m["hook"] != hook || m["prio"] != priority || m["policy"] != "accept" {
						return ErrDockerScope
					}
					chain.policy = "ACCEPT"
				}
				table.chains[chainName] = chain
			case "rule":
				chainName, ok := m["chain"].(string)
				chain := table.chains[chainName]
				if !ok || len(m) != 4 || chain == nil {
					return ErrDockerScope
				}
				rule, e := nftDockerRule(chainName, m["expr"])
				if e != nil {
					return ErrDockerScope
				}
				chain.rules = append(chain.rules, rule)
			default:
				return ErrDockerScope
			}
		}
	}
	if tableSeen {
		if validateSavedTable("nat", table, scope, "ip") != nil {
			return ErrDockerScope
		}
	} else if len(table.chains) != 0 {
		return ErrDockerScope
	}
	filtered, err := json.Marshal(map[string]any{"nftables": kept})
	if err != nil || RequireNoUnownedPacketRewrite(filtered) != nil {
		return ErrDockerScope
	}
	return nil
}

func nftDockerRule(chain string, raw any) (dockerRule, error) {
	r := dockerRule{chain: chain}
	expressions, ok := raw.([]any)
	if !ok || len(expressions) == 0 || len(expressions) > 16 {
		return r, ErrDockerScope
	}
	seen := map[string]bool{}
	terminal := false
	for _, expression := range expressions {
		m, ok := expression.(map[string]any)
		if !ok || len(m) != 1 || terminal {
			return r, ErrDockerScope
		}
		for kind, value := range m {
			switch kind {
			case "counter":
				c, ok := value.(map[string]any)
				if !ok || len(c) != 2 || !nftUnsigned(c["packets"]) || !nftUnsigned(c["bytes"]) || seen[kind] {
					return r, ErrDockerScope
				}
				seen[kind] = true
			case "match":
				match, ok := value.(map[string]any)
				if !ok || len(match) != 3 || nftDockerMatch(&r, match, seen) != nil {
					return r, ErrDockerScope
				}
			case "return":
				if value != nil {
					return r, ErrDockerScope
				}
				r.target, terminal = "RETURN", true
			case "jump":
				jump, ok := value.(map[string]any)
				if !ok || len(jump) != 1 || jump["target"] != "DOCKER" {
					return r, ErrDockerScope
				}
				r.target, terminal = "DOCKER", true
			case "masquerade":
				if value != nil {
					return r, ErrDockerScope
				}
				r.target, terminal = "MASQUERADE", true
			case "snat", "dnat":
				nat, ok := value.(map[string]any)
				if !ok || len(nat) == 0 || len(nat) > 3 {
					return r, ErrDockerScope
				}
				for key := range nat {
					if key != "addr" && key != "port" && key != "family" {
						return r, ErrDockerScope
					}
				}
				if family, present := nat["family"]; present && family != "ip" {
					return r, ErrDockerScope
				}
				addr, ok := nat["addr"].(string)
				a, e := netip.ParseAddr(addr)
				if !ok || e != nil || !a.Is4() || a.String() != addr {
					return r, ErrDockerScope
				}
				r.translation = a
				if port, present := nat["port"]; present {
					p, ok := port.(json.Number)
					if !ok || !decimal(string(p), 16) || p == "0" {
						return r, ErrDockerScope
					}
					r.translationPort, _ = strconv.Atoi(string(p))
				}
				if kind == "snat" {
					r.target = "SNAT"
				} else {
					r.target = "DNAT"
				}
				terminal = true
			default:
				return r, ErrDockerScope
			}
		}
	}
	if !terminal {
		return r, ErrDockerScope
	}
	return r, nil
}

func nftUnsigned(v any) bool {
	n, ok := v.(json.Number)
	return ok && decimal(string(n), 64)
}

func nftDockerMatch(r *dockerRule, match map[string]any, seen map[string]bool) error {
	op, ok := match["op"].(string)
	if !ok || op != "==" && op != "!=" {
		return ErrDockerScope
	}
	left, ok := match["left"].(map[string]any)
	if !ok || len(left) != 1 {
		return ErrDockerScope
	}
	field := ""
	for kind, value := range left {
		m, ok := value.(map[string]any)
		if !ok {
			return ErrDockerScope
		}
		switch kind {
		case "payload":
			if len(m) != 2 {
				return ErrDockerScope
			}
			protocol, _ := m["protocol"].(string)
			name, _ := m["field"].(string)
			if protocol == "ip" && (name == "saddr" || name == "daddr") || protocol == "udp" && name == "dport" {
				field = name
			} else if protocol == "ip" && name == "protocol" {
				field = "protocol"
			} else {
				return ErrDockerScope
			}
		case "meta":
			if len(m) != 1 {
				return ErrDockerScope
			}
			key, _ := m["key"].(string)
			switch key {
			case "iifname", "oifname":
				field = key
			case "l4proto":
				field = "protocol"
			default:
				return ErrDockerScope
			}
		case "fib":
			flags, ok := m["flags"].([]any)
			if len(m) != 2 || m["result"] != "type" || !ok || len(flags) != 1 || flags[0] != "daddr" && flags[0] != "saddr" || op != "==" || match["right"] != "local" {
				return ErrDockerScope
			}
			field = "local-" + flags[0].(string)
		default:
			return ErrDockerScope
		}
	}
	if seen[field] {
		return ErrDockerScope
	}
	seen[field] = true
	switch field {
	case "saddr", "daddr":
		prefix, err := nftDockerPrefix(match["right"])
		if err != nil {
			return err
		}
		if field == "saddr" {
			r.source, r.negSource = prefix, op == "!="
		} else {
			r.destination, r.negDestination = prefix, op == "!="
		}
	case "iifname", "oifname":
		name, ok := match["right"].(string)
		if !ok || !interfaceName(name) {
			return ErrDockerScope
		}
		if field == "iifname" {
			r.in, r.negIn = name, op == "!="
		} else {
			r.out, r.negOut = name, op == "!="
		}
	case "dport":
		port, ok := match["right"].(json.Number)
		if !ok || op != "==" || !decimal(string(port), 16) || port == "0" {
			return ErrDockerScope
		}
		r.port, _ = strconv.Atoi(string(port))
	case "protocol":
		if op != "==" || match["right"] != "udp" && match["right"] != json.Number("17") {
			return ErrDockerScope
		}
		r.protocol = "udp"
	case "local-saddr":
		r.sourceLocal = true
	case "local-daddr":
		r.destinationLocal = true
	default:
		return ErrDockerScope
	}
	return nil
}

func nftDockerPrefix(raw any) (netip.Prefix, error) {
	if addr, ok := raw.(string); ok {
		a, err := netip.ParseAddr(addr)
		if err == nil && a.Is4() && a.String() == addr {
			return netip.PrefixFrom(a, 32), nil
		}
	}
	outer, ok := raw.(map[string]any)
	if !ok || len(outer) != 1 {
		return netip.Prefix{}, ErrDockerScope
	}
	m, ok := outer["prefix"].(map[string]any)
	if !ok || len(m) != 2 {
		return netip.Prefix{}, ErrDockerScope
	}
	addr, ok := m["addr"].(string)
	a, err := netip.ParseAddr(addr)
	length, numeric := m["len"].(json.Number)
	bits, errBits := strconv.Atoi(string(length))
	if !ok || err != nil || !a.Is4() || a.String() != addr || !numeric || errBits != nil || !decimal(string(length), 8) || bits > 32 {
		return netip.Prefix{}, ErrDockerScope
	}
	p := netip.PrefixFrom(a, bits)
	if p != p.Masked() {
		return netip.Prefix{}, ErrDockerScope
	}
	return p, nil
}
