package netguard

import (
	"encoding/json"
	"reflect"
)

// LegacyForwardingNeedsGuard reports whether a shared IPv4 filter/FORWARD
// chain needs owned leading accepts. It never declares runtime/client readiness.
// These two rules bypass only unrelated filtering for packets on our veth; the
// separate, later nft guard must still enforce all tuples and destination deny.
func LegacyForwardingNeedsGuard(data []byte, scope DockerScope) (bool, error) {
	tables, err := parseScopedIPTables(data, "ip", scope)
	if err != nil {
		return false, err
	}
	table, present := tables["filter"]
	if !present {
		return false, nil
	}
	chain := table.chains["FORWARD"]
	return chain.policy == "DROP" || len(chain.rules) != 0, nil
}

// VerifyLegacyForwardingGuard requires both exact accepts at the head, no
// duplicates elsewhere and no hidden extra predicate. Kernel readback must
// additionally verify the independent owned nft guard on every activation.
func VerifyLegacyForwardingGuard(data []byte, scope DockerScope) error {
	tables, err := parseScopedIPTables(data, "ip", scope)
	if err != nil {
		return err
	}
	table, present := tables["filter"]
	if !present || table.chains["FORWARD"] == nil {
		return ErrDockerScope
	}
	rules := table.chains["FORWARD"].rules
	want := []dockerRule{{chain: "FORWARD", target: "ACCEPT", in: HostVeth}, {chain: "FORWARD", target: "ACCEPT", out: HostVeth}}
	if len(rules) < 2 || !reflect.DeepEqual(rules[:2], want) {
		return ErrDockerScope
	}
	for _, r := range rules[2:] {
		if r.in == HostVeth || r.out == HostVeth {
			return ErrDockerScope
		}
	}
	return nil
}

// NFTForwardingNeedsGuard validates the Foreign rewrite subset and detects the
// standard ip/filter/FORWARD chain. A closed owned head readback is separately
// required after insertions. Native nft xt match statements remain unsupported.
func NFTForwardingNeedsGuard(data []byte, scope DockerScope) (bool, error) {
	if RequireScopedHostRewrite(data, scope) != nil {
		return false, ErrDockerScope
	}
	objects, err := nftObjects(data)
	if err != nil {
		return false, err
	}
	found := false
	for _, raw := range objects {
		wrapper := raw.(map[string]any)
		if chain, ok := wrapper["chain"].(map[string]any); ok && chain["family"] == "ip" && chain["table"] == "filter" && chain["name"] == "FORWARD" {
			if found || chain["type"] != "filter" || chain["hook"] != "forward" || chain["prio"] != json.Number("0") || chain["policy"] != "accept" && chain["policy"] != "drop" {
				return false, ErrDockerScope
			}
			found = true
		}
	}
	return found, nil
}

func VerifyNFTForwardingGuard(data []byte, scope DockerScope) error {
	needed, err := NFTForwardingNeedsGuard(data, scope)
	if err != nil || !needed {
		return ErrDockerScope
	}
	objects, err := nftObjects(data)
	if err != nil {
		return err
	}
	want := []any{ownedForwardNFT("iifname"), ownedForwardNFT("oifname")}
	actual := []any{}
	for _, raw := range objects {
		wrapper := raw.(map[string]any)
		m, ok := wrapper["rule"].(map[string]any)
		if !ok || m["family"] != "ip" || m["table"] != "filter" || m["chain"] != "FORWARD" {
			continue
		}
		if stripHandle(m) != nil || len(m) != 4 {
			return ErrDockerScope
		}
		actual = append(actual, m["expr"])
	}
	if len(actual) < 2 || !reflect.DeepEqual(actual[:2], want) {
		return ErrDockerScope
	}
	for _, expr := range actual[2:] {
		// A later mention of the owned interface indicates an unexpected shared
		// writer. Bounded JSON string equality also catches hidden predicates.
		b, err := json.Marshal(expr)
		if err != nil || containsJSONInterface(b, HostVeth) {
			return ErrDockerScope
		}
	}
	return nil
}

func nftObjects(data []byte) ([]any, error) {
	v, err := readNFTJSON(data)
	if err != nil {
		return nil, ErrDockerScope
	}
	root, ok := v.(map[string]any)
	if !ok || len(root) != 1 {
		return nil, ErrDockerScope
	}
	objects, ok := root["nftables"].([]any)
	if !ok {
		return nil, ErrDockerScope
	}
	return objects, nil
}

func ownedForwardNFT(key string) []any {
	return []any{
		map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": key}}, "right": HostVeth}},
		map[string]any{"accept": nil},
	}
}

func containsJSONInterface(data []byte, name string) bool {
	var v any
	if json.Unmarshal(data, &v) != nil {
		return true
	}
	var walk func(any) bool
	walk = func(v any) bool {
		switch x := v.(type) {
		case string:
			return x == name
		case []any:
			for _, child := range x {
				if walk(child) {
					return true
				}
			}
		case map[string]any:
			for _, child := range x {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	return walk(v)
}
