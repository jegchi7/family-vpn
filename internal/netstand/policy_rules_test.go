package netstand

import (
	"encoding/json"
	"errors"
	"testing"
)

func standardPolicyRules() []map[string]any {
	return []map[string]any{
		{"priority": 0, "src": "all", "table": "255"},
		{"priority": 32766, "src": "all", "table": "254"},
		{"priority": 32767, "src": "all", "table": "253"},
	}
}
func TestPolicyRulesRejectAlternateSelectionAndTableAliases(t *testing.T) {
	standard := standardPolicyRules()
	standard[0]["protocol"] = "2"
	standard[0]["flags"] = []string{}
	data, _ := json.Marshal(standard)
	if e := parsePolicyRules(data); e != nil {
		t.Fatal("numeric kernel RPDB rejected", e)
	}
	for _, tc := range []struct {
		name, key string
		value     any
	}{
		{"mark rule", "fwmark", "0x1"},
		{"input interface", "iif", "fvpn-host"},
		{"output interface", "oif", "eth0"},
		{"goto", "goto", 32767},
		{"suppress", "suppress_prefixlen", 0},
		{"source", "src", "10.231.240.0"},
		{"source length", "srclen", 30},
		{"destination", "dst", "46.9.10.11"},
		{"UID selector", "uid_start", 65534},
		{"port selector", "dport", 443},
		{"inverted selector", "not", nil},
		{"NAT rule", "nat_gateway", "1.1.1.1"},
		{"table alias", "table", "main"},
		{"alternate table", "table", "200"},
		{"numeric field alias", "table", 254},
		{"nonkernel protocol", "protocol", "99"},
		{"named protocol alias", "protocol", "kernel"},
		{"unknown flag", "flags", []string{"unresolved"}},
		{"alternate action", "action", "blackhole"},
		{"unknown selector", "unexpected", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := standardPolicyRules()
			rules[1][tc.key] = tc.value
			data, _ := json.Marshal(rules)
			if e := parsePolicyRules(data); !errors.Is(e, ErrInventory) {
				t.Fatal("unsupported RPDB accepted", e)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func([]map[string]any) []map[string]any
	}{
		{"missing default rule", func(r []map[string]any) []map[string]any { return r[:2] }},
		{"extra priority", func(r []map[string]any) []map[string]any {
			return append(r, map[string]any{"priority": 100, "src": "all", "table": "200"})
		}},
		{"rule reordered", func(r []map[string]any) []map[string]any { r[0], r[1] = r[1], r[0]; return r }},
		{"duplicate main rule", func(r []map[string]any) []map[string]any { r[2] = r[1]; return r }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := json.Marshal(tc.change(standardPolicyRules()))
			if parsePolicyRules(data) == nil {
				t.Fatal("nonstandard policy accepted")
			}
		})
	}
	for _, data := range [][]byte{[]byte(`[{"priority":0,"src":"all","table":"255","table":"254"}]`), []byte(`[] {}`), nil} {
		if parsePolicyRules(data) == nil {
			t.Fatal("ambiguous policy document accepted")
		}
	}
}
