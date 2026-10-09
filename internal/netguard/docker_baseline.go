package netguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

const LegacyXtablesExecutable = "/usr/sbin/xtables-legacy-multi"

// Linux PID0 has no /proc process directory. A fixed nonexistent proc executable
// prevents libxtables from invoking a configured modprobe during failed reads
// or writes. Operators cannot supply a replacement executable or module helper.
const LegacyDisableModuleAutoload = "/proc/0/exe"

// DockerForwardInsertions is an operator-only supplement, installed after the
// owned nft guards and before veth UP. It does not reorder/remove existing
// Docker entries. Both exact head rules and unchanged shared baseline must be
// read back before activation. Nothing executes here.
func DockerForwardInsertions(backend string) ([]Step, error) {
	switch backend {
	case "legacy":
		return []Step{
			{Scope: "host", Executable: LegacyXtablesExecutable, Args: []string{"iptables", "-M", LegacyDisableModuleAutoload, "-w", "2", "-t", "filter", "-I", "FORWARD", "1", "-i", HostVeth, "-j", "ACCEPT"}},
			{Scope: "host", Executable: LegacyXtablesExecutable, Args: []string{"iptables", "-M", LegacyDisableModuleAutoload, "-w", "2", "-t", "filter", "-I", "FORWARD", "2", "-o", HostVeth, "-j", "ACCEPT"}},
		}, nil
	case "nft":
		// insert without position prepends; reverse writes produce iif then oif.
		return []Step{
			{Scope: "host", Executable: NFTExecutable, Args: []string{"insert", "rule", "ip", "filter", "FORWARD", "oifname", HostVeth, "accept"}},
			{Scope: "host", Executable: NFTExecutable, Args: []string{"insert", "rule", "ip", "filter", "FORWARD", "iifname", HostVeth, "accept"}},
		}, nil
	}
	return nil, ErrDockerScope
}

// LegacyPolicySHA256 preserves original ordering, match tokens and verdicts.
// Only dump comments and declaration counters are omitted. When owned=true the
// exact two owned leading rules are verified and omitted, never guessed. Hashes
// are a configuration fence, not a freshness, kernel, or Docker attestation.
func LegacyPolicySHA256(data []byte, family string, scope DockerScope, owned bool) (string, error) {
	if RequireScopedIPTables(data, family, scope) != nil || owned && (family != "ip" || VerifyLegacyForwardingGuard(data, scope) != nil) {
		return "", ErrDockerScope
	}
	lines := []string{}
	table := ""
	skipped := 0
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			table = line[1:]
		}
		fields := strings.Fields(line)
		if !owned {
			for _, token := range fields {
				if token == HostVeth || token == NamespaceVeth {
					return "", ErrDockerScope
				}
			}
		}
		if strings.HasPrefix(line, ":") {
			fields = fields[:2]
		}
		if owned && table == "filter" && len(fields) > 1 && fields[0] == "-A" && fields[1] == "FORWARD" && skipped < 2 {
			skipped++
			continue
		}
		lines = append(lines, strings.Join(fields, " "))
	}
	if owned && skipped != 2 {
		return "", ErrDockerScope
	}
	return policyHash([]byte(strings.Join(lines, "\n"))), nil
}

// NFTPolicySHA256 excludes the separately measured owned tables, exact owned
// shared-chain head rules, dump handles/metainfo and changing counters. Every
// other declaration, predicate, chain policy/priority and rule order is fenced.
func NFTPolicySHA256(data []byte, scope DockerScope, owned bool) (string, error) {
	if RequireScopedHostRewrite(data, scope) != nil || owned && VerifyNFTForwardingGuard(data, scope) != nil {
		return "", ErrDockerScope
	}
	objects, err := nftObjects(data)
	if err != nil {
		return "", err
	}
	kept := []any{}
	skipped := 0
	for _, raw := range objects {
		wrapper := raw.(map[string]any)
		include := true
		for kind, body := range wrapper {
			if kind == "metainfo" {
				include = false
				continue
			}
			m := body.(map[string]any)
			name, _ := m["table"].(string)
			if kind == "table" {
				name, _ = m["name"].(string)
			}
			if name == HostTable || name == NATTable {
				include = false
				continue
			}
			if !owned {
				b, err := json.Marshal(m)
				if err != nil || containsJSONInterface(b, HostVeth) || containsJSONInterface(b, NamespaceVeth) {
					return "", ErrDockerScope
				}
			}
			if stripHandle(m) != nil {
				return "", ErrDockerScope
			}
			if owned && kind == "rule" && m["family"] == "ip" && m["table"] == "filter" && m["chain"] == "FORWARD" && skipped < 2 {
				skipped++
				include = false
				continue
			}
			if kind == "rule" {
				exprs := m["expr"].([]any)
				for _, expr := range exprs {
					e := expr.(map[string]any)
					if c, ok := e["counter"].(map[string]any); ok {
						if normalizeCounter(c) != nil {
							return "", ErrDockerScope
						}
					}
				}
			} else if kind == "counter" {
				if normalizeCounter(m) != nil {
					return "", ErrDockerScope
				}
			}
		}
		if include {
			kept = append(kept, raw)
		}
	}
	if owned && skipped != 2 {
		return "", ErrDockerScope
	}
	b, err := json.Marshal(kept)
	if err != nil {
		return "", ErrDockerScope
	}
	return policyHash(b), nil
}

func normalizeCounter(m map[string]any) error {
	for _, key := range []string{"packets", "bytes"} {
		if value, exists := m[key]; exists {
			if !nftUnsigned(value) {
				return ErrDockerScope
			}
			m[key] = 0
		}
	}
	return nil
}

func policyHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
