package netguard

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"testing"
)

// Synthetic parser/comparator tests only. No nft executable or kernel is used.
func readbackPlan(t *testing.T, role string) Plan {
	t.Helper()
	i := Inputs{Role: role, RUIPv4: netip.MustParseAddr("8.8.8.8"), ForeignIPv4: netip.MustParseAddr("9.9.9.9"), HostPublicIPv4: netip.MustParseAddr("8.8.8.8"), Transit: netip.MustParsePrefix("10.233.64.0/30"), Uplink: "eth0"}
	if role == "foreign" {
		i.HostPublicIPv4 = i.ForeignIPv4
	}
	v := Inventory{Interfaces: []string{"lo", "eth0"}, Addresses: []Address{{Interface: "lo", Prefix: netip.MustParsePrefix("127.0.0.1/8")}, {Interface: "eth0", Prefix: netip.PrefixFrom(i.HostPublicIPv4, 24)}}, Routes: []Route{{Interface: "eth0", Destination: netip.MustParsePrefix("0.0.0.0/0")}}, IPv4Forwarding: true}
	p, e := Build(i, v)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func numberIP(n uint64) string {
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}).String()
}
func syntheticNFT(t *testing.T, p Plan, scope string) map[string]any {
	t.Helper()
	script := p.HostFirewall
	if scope == Namespace {
		script = p.NamespaceFirewall
	}
	model, e := expectedNFT(script)
	if e != nil {
		t.Fatal(e)
	}
	a := []any{map[string]any{"metainfo": map[string]any{"version": "0.9.3", "release_name": "synthetic", "json_schema_version": json.Number("1")}}}
	keys := []string{}
	for key := range model.objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		kind := strings.SplitN(key, "/", 2)[0]
		m := model.objects[key].(map[string]any)
		m["handle"] = json.Number("1")
		if kind == "set" {
			ranges := m["elem"].([]ipRange)
			elements := []any{}
			for _, r := range ranges {
				if r.lo == r.hi {
					elements = append(elements, numberIP(r.lo))
				} else {
					elements = append(elements, map[string]any{"range": []any{numberIP(r.lo), numberIP(r.hi)}})
				}
			}
			m["elem"] = elements
		}
		a = append(a, map[string]any{kind: m})
	}
	keys = nil
	for key := range model.rules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts := strings.Split(key, "/")
		for _, expr := range model.rules[key] {
			m := map[string]any{"family": parts[0], "table": parts[1], "chain": parts[2], "expr": expr, "handle": json.Number("2")}
			a = append(a, map[string]any{"rule": m})
		}
	}
	return map[string]any{"nftables": a}
}
func encodeNFT(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func firstObject(t *testing.T, v map[string]any, kind string) map[string]any {
	t.Helper()
	for _, raw := range v["nftables"].([]any) {
		if m, ok := raw.(map[string]any)[kind].(map[string]any); ok {
			return m
		}
	}
	t.Fatal("missing object")
	return nil
}

func TestNFTReadbackClosedBoundary(t *testing.T) {
	for _, role := range []string{"ru", "foreign"} {
		for _, scope := range []string{"host", Namespace} {
			t.Run(role+"/"+scope, func(t *testing.T) {
				p := readbackPlan(t, role)
				if e := VerifyNFTReadback(p, scope, encodeNFT(t, syntheticNFT(t, p, scope))); e != nil {
					t.Fatal(e)
				}
			})
		}
	}
	p := readbackPlan(t, "ru")
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"missing_objects", func(v map[string]any) { v["nftables"] = v["nftables"].([]any)[:1] }},
		{"table_wrong_family", func(v map[string]any) { firstObject(t, v, "table")["family"] = "ip6" }},
		{"extra_owned_object", func(v map[string]any) {
			v["nftables"] = append(v["nftables"].([]any), map[string]any{"flowtable": map[string]any{"family": "inet", "table": HostTable, "name": "bypass"}})
		}},
		{"extra_chain", func(v map[string]any) {
			v["nftables"] = append(v["nftables"].([]any), map[string]any{"chain": map[string]any{"family": "inet", "table": HostTable, "name": "unexpected"}})
		}},
		{"extra_rule", func(v map[string]any) {
			v["nftables"] = append(v["nftables"].([]any), map[string]any{"rule": map[string]any{"family": "inet", "table": HostTable, "chain": "from_data_pre", "expr": []any{map[string]any{"accept": nil}}}})
		}},
		{"extra_comment", func(v map[string]any) { firstObject(t, v, "rule")["comment"] = "opaque" }},
		{"unknown_expression", func(v map[string]any) {
			firstObject(t, v, "rule")["expr"] = []any{map[string]any{"xt": map[string]any{"name": "unknown"}}}
		}},
		{"unknown_chain_field", func(v map[string]any) { firstObject(t, v, "chain")["dev"] = "eth0" }},
		{"set_missing_metadata_deny", func(v map[string]any) { m := firstObject(t, v, "set"); m["elem"] = m["elem"].([]any)[1:] }},
		{"set_extra_range", func(v map[string]any) {
			m := firstObject(t, v, "set")
			m["elem"] = append(m["elem"].([]any), "8.8.4.4")
		}},
		{"set_timeout", func(v map[string]any) { firstObject(t, v, "set")["timeout"] = json.Number("60") }},
		{"bad_handle", func(v map[string]any) { firstObject(t, v, "rule")["handle"] = json.Number("-1") }},
		{"schema_unknown", func(v map[string]any) { firstObject(t, v, "metainfo")["json_schema_version"] = json.Number("2") }},
		{"duplicate_meta", func(v map[string]any) { v["nftables"] = append(v["nftables"].([]any), v["nftables"].([]any)[0]) }},
		{"rule_order", func(v map[string]any) {
			a := v["nftables"].([]any)
			indices := []int{}
			chain := ""
			for n, raw := range a {
				m, ok := raw.(map[string]any)["rule"].(map[string]any)
				if !ok {
					continue
				}
				if chain == "" {
					chain = m["chain"].(string)
				}
				if m["chain"] == chain {
					indices = append(indices, n)
				}
			}
			if len(indices) < 2 {
				t.Fatal("insufficient rules")
			}
			a[indices[0]], a[indices[1]] = a[indices[1]], a[indices[0]]
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := syntheticNFT(t, p, "host")
			tc.mutate(v)
			if e := VerifyNFTReadback(p, "host", encodeNFT(t, v)); e == nil {
				t.Fatal("changed evidence accepted")
			}
		})
	}
	v := syntheticNFT(t, p, "host")
	v["nftables"] = append(v["nftables"].([]any), map[string]any{"table": map[string]any{"family": "inet", "name": "host_management", "handle": json.Number("8")}})
	if e := VerifyNFTReadback(p, "host", encodeNFT(t, v)); e != nil {
		t.Fatal("unowned host filter table changed guard comparison")
	}
	v = syntheticNFT(t, p, Namespace)
	v["nftables"] = append(v["nftables"].([]any), map[string]any{"table": map[string]any{"family": "inet", "name": "unowned", "handle": json.Number("8")}})
	if e := VerifyNFTReadback(p, Namespace, encodeNFT(t, v)); e == nil {
		t.Fatal("extra namespace table accepted")
	}
}

func TestNFTReadbackFreshTypedCTAndBounds(t *testing.T) {
	p := readbackPlan(t, "ru")
	v := syntheticNFT(t, p, "host")
	// Old libnftables uses explicitly typed "ip daddr"/"ip saddr" keys.
	for _, raw := range v["nftables"].([]any) {
		m, ok := raw.(map[string]any)["rule"].(map[string]any)
		if !ok {
			continue
		}
		for _, s := range m["expr"].([]any) {
			match, ok := s.(map[string]any)["match"].(map[string]any)
			if !ok {
				continue
			}
			ct, ok := match["left"].(map[string]any)["ct"].(map[string]any)
			if ok && ct["family"] == "ip" {
				ct["key"] = "ip " + ct["key"].(string)
				delete(ct, "family")
			}
		}
	}
	if e := VerifyNFTReadback(p, "host", encodeNFT(t, v)); e != nil {
		t.Fatal(e)
	}
	for _, b := range [][]byte{[]byte(`{"nftables":[],"nftables":[]}`), append(encodeNFT(t, v), []byte(` {}`)...), []byte(strings.Repeat("[", 26) + "0" + strings.Repeat("]", 26)), []byte(strings.Repeat(" ", (1<<20)+1))} {
		if e := VerifyNFTReadback(p, "host", b); e == nil {
			t.Fatal("ambiguous or unbounded evidence accepted")
		}
	}
	// Independent upstream JSON statement shape: state is a bitmask membership,
	// not equality, and direction/protocol are distinct fields.
	expr, e := compileNFTRule("ct state invalid drop")
	if e != nil {
		t.Fatal(e)
	}
	expected := `[{"match":{"left":{"ct":{"key":"state"}},"op":"in","right":"invalid"}},{"drop":null}]`
	if string(encodeNFT(t, expr)) != expected {
		t.Fatal("state mask compiled incorrectly")
	}
	if _, e := compileNFTRule("ct direction reply ct original protocol tcp tcp sport 443 accept"); e != nil {
		t.Fatal(e)
	}
	if _, e := compileNFTRule("counter accept"); e == nil {
		t.Fatal("unsupported dialect accepted")
	}
}
