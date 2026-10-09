package netguard

import (
	"bytes"
	"net/netip"
	"strconv"
	"strings"
)

type savedChain struct {
	policy string
	rules  []dockerRule
}
type savedTable struct{ chains map[string]*savedChain }

// RequireScopedIPTables validates a bounded read-only *legacy* save listing.
// Reading the default iptables-save does not establish that legacy is absent;
// the native caller must read both families from the pinned legacy multicall
// helper and separately validate the complete nft ruleset. No argument, URL,
// Docker name, filter ACCEPT, or declaration alone permits a packet rewrite.
func RequireScopedIPTables(data []byte, family string, s DockerScope) error {
	_, err := parseScopedIPTables(data, family, s)
	return err
}

func parseScopedIPTables(data []byte, family string, s DockerScope) (map[string]savedTable, error) {
	if !s.valid || family != "ip" && family != "ip6" || len(data) > 1024*1024 || bytes.IndexByte(data, 0) >= 0 || bytes.IndexByte(data, '\r') >= 0 {
		return nil, ErrDockerScope
	}
	for _, b := range data {
		if b != '\n' && (b < 32 || b > 126) {
			return nil, ErrDockerScope
		}
	}
	result := map[string]savedTable{}
	current := ""
	lines := strings.Split(string(data), "\n")
	if len(lines) > 8192 {
		return nil, ErrDockerScope
	}
	for _, line := range lines {
		if len(line) > 8192 || line != strings.TrimSpace(line) {
			return nil, ErrDockerScope
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			name := strings.TrimPrefix(line, "*")
			if current != "" || name != "filter" && name != "nat" && name != "raw" && name != "mangle" && name != "security" {
				return nil, ErrDockerScope
			}
			if _, duplicate := result[name]; duplicate {
				return nil, ErrDockerScope
			}
			result[name] = savedTable{chains: map[string]*savedChain{}}
			current = name
			continue
		}
		if current == "" {
			return nil, ErrDockerScope
		}
		table := result[current]
		if line == "COMMIT" {
			if validateSavedTable(current, table, s, family) != nil {
				return nil, ErrDockerScope
			}
			current = ""
			continue
		}
		parts := strings.Fields(line)
		if strings.HasPrefix(line, ":") {
			if len(parts) != 3 || !savedName(parts[0][1:]) || !savedCounters(parts[2]) {
				return nil, ErrDockerScope
			}
			name, policy := parts[0][1:], parts[1]
			if policy != "-" && policy != "ACCEPT" && policy != "DROP" {
				return nil, ErrDockerScope
			}
			if _, duplicate := table.chains[name]; duplicate {
				return nil, ErrDockerScope
			}
			table.chains[name] = &savedChain{policy: policy}
			continue
		}
		if len(parts) < 4 || parts[0] != "-A" {
			return nil, ErrDockerScope
		}
		chain := table.chains[parts[1]]
		if chain == nil {
			return nil, ErrDockerScope
		}
		rule, err := parseSavedRule(parts[1], parts[2:], family)
		if err != nil {
			return nil, ErrDockerScope
		}
		chain.rules = append(chain.rules, rule)
	}
	if current != "" {
		return nil, ErrDockerScope
	}
	return result, nil
}

func savedName(s string) bool {
	if s == "" || len(s) > 29 {
		return false
	}
	for _, c := range s {
		if c != '_' && c != '-' && !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func savedCounters(s string) bool {
	if len(s) < 5 || s[0] != '[' || s[len(s)-1] != ']' {
		return false
	}
	parts := strings.Split(s[1:len(s)-1], ":")
	if len(parts) != 2 {
		return false
	}
	for _, n := range parts {
		if !decimal(n, 64) {
			return false
		}
	}
	return true
}
func decimal(s string, bits int) bool {
	if s == "" || len(s) > 1 && s[0] == '0' {
		return false
	}
	n, err := strconv.ParseUint(s, 10, bits)
	return err == nil && strconv.FormatUint(n, 10) == s
}

func parseSavedRule(chain string, parts []string, family string) (dockerRule, error) {
	r := dockerRule{chain: chain}
	seen := map[string]bool{}
	modules := map[string]bool{}
	for n := 0; n < len(parts); n++ {
		neg := false
		if parts[n] == "!" {
			neg = true
			n++
			if n >= len(parts) {
				return r, ErrDockerScope
			}
		}
		key := parts[n]
		if n+1 >= len(parts) {
			return r, ErrDockerScope
		}
		n++
		value := parts[n]
		if key != "-m" {
			if seen[key] {
				return r, ErrDockerScope
			}
			seen[key] = true
		}
		switch key {
		case "-s", "-d":
			p, err := netip.ParsePrefix(value)
			if err != nil || p != p.Masked() || p.String() != value || p.Addr().Is4In6() || p.Addr().Is4() != (family == "ip") {
				return r, ErrDockerScope
			}
			if key == "-s" {
				r.source, r.negSource = p, neg
			} else {
				r.destination, r.negDestination = p, neg
			}
		case "-i", "-o":
			if !interfaceName(value) {
				return r, ErrDockerScope
			}
			if key == "-i" {
				r.in, r.negIn = value, neg
			} else {
				r.out, r.negOut = value, neg
			}
		case "-p":
			if neg || value != "tcp" && value != "udp" && value != "icmp" && value != "ipv6-icmp" {
				return r, ErrDockerScope
			}
			r.protocol = value
		case "-m":
			if neg || modules[value] || value != "tcp" && value != "udp" && value != "conntrack" && value != "state" && value != "addrtype" {
				return r, ErrDockerScope
			}
			modules[value] = true
			r.extraMatch = true
		case "--dport", "--sport":
			if neg || !decimal(value, 16) || value == "0" {
				return r, ErrDockerScope
			}
			port, _ := strconv.Atoi(value)
			if key == "--dport" {
				r.port = port
			} else {
				r.extraMatch = true
			}
		case "--dst-type", "--src-type":
			if neg || value != "LOCAL" {
				return r, ErrDockerScope
			}
			if key == "--dst-type" {
				r.destinationLocal = true
			} else {
				r.sourceLocal = true
			}
		case "--ctstate", "--state":
			if neg || !savedStates(value) {
				return r, ErrDockerScope
			}
			r.extraMatch = true
		case "-j":
			if neg || !savedName(value) {
				return r, ErrDockerScope
			}
			r.target = value
		case "--to-destination":
			if neg {
				return r, ErrDockerScope
			}
			addrport, err := netip.ParseAddrPort(value)
			if err != nil || addrport.String() != value || !addrport.Addr().Is4() || addrport.Port() == 0 {
				return r, ErrDockerScope
			}
			r.translation, r.translationPort = addrport.Addr(), int(addrport.Port())
		case "--to-source":
			addr, err := netip.ParseAddr(value)
			if neg || err != nil || !addr.Is4() || addr.String() != value {
				return r, ErrDockerScope
			}
			r.translation = addr
		case "--reject-with":
			if neg || value != "icmp-port-unreachable" && value != "tcp-reset" && value != "icmp6-port-unreachable" {
				return r, ErrDockerScope
			}
		default:
			return r, ErrDockerScope
		}
	}
	if r.target == "" || modules["udp"] && r.protocol != "udp" || modules["tcp"] && r.protocol != "tcp" || (r.sourceLocal || r.destinationLocal) && !modules["addrtype"] || seen["--ctstate"] && !modules["conntrack"] || seen["--state"] && !modules["state"] || (seen["--dport"] || seen["--sport"]) && !modules[r.protocol] || seen["--to-source"] && r.target != "SNAT" || seen["--to-destination"] && r.target != "DNAT" || seen["--reject-with"] && r.target != "REJECT" {
		return r, ErrDockerScope
	}
	return r, nil
}

func savedStates(value string) bool {
	seen := map[string]bool{}
	for _, s := range strings.Split(value, ",") {
		if seen[s] || s != "NEW" && s != "ESTABLISHED" && s != "RELATED" && s != "INVALID" && s != "UNTRACKED" {
			return false
		}
		seen[s] = true
	}
	return true
}

func validateSavedTable(name string, table savedTable, scope DockerScope, family string) error {
	if len(table.chains) == 0 || len(table.chains) > 256 {
		return ErrDockerScope
	}
	hooks := map[string][]string{
		"nat": {"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"}, "filter": {"INPUT", "FORWARD", "OUTPUT"},
		"raw": {"PREROUTING", "OUTPUT"}, "mangle": {"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}, "security": {"INPUT", "FORWARD", "OUTPUT"},
	}
	base := map[string]bool{}
	for _, chain := range hooks[name] {
		c := table.chains[chain]
		if c == nil || c.policy == "-" || name == "nat" && c.policy != "ACCEPT" {
			return ErrDockerScope
		}
		base[chain] = true
	}
	localEntry := 0
	for chainName, chain := range table.chains {
		if !base[chainName] && chain.policy != "-" || name == "nat" && !base[chainName] && chainName != "DOCKER" {
			return ErrDockerScope
		}
		for _, r := range chain.rules {
			if name == "nat" {
				if family != "ip" || !dockerNATRule(scope, r) {
					return ErrDockerScope
				}
				if r.target == "DOCKER" {
					localEntry++
					if table.chains["DOCKER"] == nil {
						return ErrDockerScope
					}
				}
				continue
			}
			if r.translation.IsValid() {
				return ErrDockerScope
			}
			switch r.target {
			case "ACCEPT", "DROP", "RETURN", "REJECT":
			default:
				if forbiddenLegacyTarget(r.target) {
					return ErrDockerScope
				}
				if target := table.chains[r.target]; target == nil || target.policy != "-" {
					return ErrDockerScope
				}
			}
		}
	}
	if name == "nat" && table.chains["DOCKER"] != nil && len(table.chains["DOCKER"].rules) > 0 && localEntry == 0 {
		return ErrDockerScope
	}
	return nil
}

func forbiddenLegacyTarget(s string) bool {
	switch s {
	case "DNAT", "SNAT", "MASQUERADE", "NETMAP", "REDIRECT", "TPROXY", "MARK", "CONNMARK", "CT", "NOTRACK", "SYNPROXY", "NFQUEUE", "QUEUE", "TEE", "TRACE", "CLASSIFY", "SECMARK", "CONNSECMARK", "TCPMSS", "DSCP", "TOS", "TTL", "HL", "CHECKSUM", "HMARK", "SET", "RATEEST", "AUDIT", "LOG", "ULOG", "NFLOG":
		return true
	}
	return false
}
