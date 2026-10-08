package netguard

import "encoding/json"

// RequireNoUnownedPacketRewrite is a deliberately conservative first-stand
// inventory gate. Existing filter firewalls may remain, but unrelated NAT,
// packet assignment, conntrack overrides and flow offload are unsupported.
// Nothing is removed or rewritten. This is not native evidence by itself and,
// after installation, must be paired with VerifyNFTReadback for owned tables.
func RequireNoUnownedPacketRewrite(data []byte) error {
	v, err := readNFTJSON(data)
	if err != nil {
		return ErrReadback
	}
	root, ok := v.(map[string]any)
	if !ok || len(root) != 1 {
		return ErrReadback
	}
	objects, ok := root["nftables"].([]any)
	if !ok || len(objects) == 0 || len(objects) > 8192 {
		return ErrReadback
	}
	metainfo := false
	for _, raw := range objects {
		wrapper, ok := raw.(map[string]any)
		if !ok || len(wrapper) != 1 {
			return ErrReadback
		}
		for kind, body := range wrapper {
			m, ok := body.(map[string]any)
			if !ok {
				return ErrReadback
			}
			if kind == "metainfo" {
				if metainfo || len(m) != 3 || m["json_schema_version"] != json.Number("1") {
					return ErrReadback
				}
				if _, ok := m["version"].(string); !ok {
					return ErrReadback
				}
				if _, ok := m["release_name"].(string); !ok {
					return ErrReadback
				}
				metainfo = true
				continue
			}
			family, fok := m["family"].(string)
			table, tok := m["table"].(string)
			if kind == "table" {
				table, tok = m["name"].(string)
			}
			if !fok || !tok || family == "" || table == "" {
				return ErrReadback
			}
			if table == NamespaceTable {
				return ErrReadback
			}
			if table == HostTable || table == NATTable {
				if table == HostTable && family != "inet" || table == NATTable && family != "ip" {
					return ErrReadback
				}
				continue
			}
			switch kind {
			case "table", "set", "map", "counter", "quota", "limit":
				// These declare data only; all referencing rule statements below
				// are restricted independently. Unknown declaration kinds fail.
			case "chain":
				if ty, ok := m["type"]; ok && ty != "filter" {
					return ErrReadback
				}
			case "rule":
				exprs, ok := m["expr"].([]any)
				if !ok || len(exprs) == 0 || len(exprs) > 64 {
					return ErrReadback
				}
				for _, expr := range exprs {
					e, ok := expr.(map[string]any)
					if !ok || len(e) != 1 {
						return ErrReadback
					}
					for statement, value := range e {
						switch statement {
						case "match":
							match, ok := value.(map[string]any)
							if !ok || len(match) != 3 {
								return ErrReadback
							}
							if _, ok := match["op"].(string); !ok {
								return ErrReadback
							}
							if !readOnlyNFTExpression(match["left"]) || !readOnlyNFTExpression(match["right"]) {
								return ErrReadback
							}
						case "accept", "drop", "continue", "return":
							if value != nil {
								return ErrReadback
							}
						case "jump", "goto":
							j, ok := value.(map[string]any)
							if !ok || len(j) != 1 {
								return ErrReadback
							}
							if _, ok := j["target"].(string); !ok {
								return ErrReadback
							}
						case "reject", "counter", "limit", "quota", "log":
							// Verdict, accounting/rate limit or existing firewall
							// logging cannot assign a packet, route or CT tuple.
						default:
							return ErrReadback
						}
					}
				}
			default:
				return ErrReadback
			}
		}
	}
	if !metainfo {
		return ErrReadback
	}
	return nil
}

func readOnlyNFTExpression(v any) bool {
	switch x := v.(type) {
	case string, json.Number, nil, bool:
		return true
	case []any:
		for _, e := range x {
			if !readOnlyNFTExpression(e) {
				return false
			}
		}
		return true
	case map[string]any:
		if len(x) != 1 {
			return false
		}
		for kind, body := range x {
			switch kind {
			case "payload", "meta", "ct", "exthdr", "rt", "fib", "socket", "osf", "numgen", "jhash", "symhash", "prefix":
				// Closed read expression nodes carry plain descriptors. No nested
				// expression statement is accepted under an unfamiliar property.
				m, ok := body.(map[string]any)
				if !ok {
					return false
				}
				for _, property := range m {
					switch property.(type) {
					case string, json.Number, bool, nil:
					default:
						return false
					}
				}
				return true
			case "set", "range", "concat", "&", "|", "^", "<<", ">>", "+", "-", "*", "/", "%":
				a, ok := body.([]any)
				if !ok {
					return false
				}
				return readOnlyNFTExpression(a)
			default:
				return false
			}
		}
	}
	return false
}
