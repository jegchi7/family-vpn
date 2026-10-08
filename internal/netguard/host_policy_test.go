package netguard

import (
	"encoding/json"
	"errors"
	"testing"
)

func filterInventory(t *testing.T, extra ...any) []byte {
	t.Helper()
	objects := []any{
		map[string]any{"metainfo": map[string]any{"version": "0.9.3", "release_name": "test", "json_schema_version": 1}},
		map[string]any{"table": map[string]any{"family": "inet", "name": "existing_firewall"}},
		map[string]any{"chain": map[string]any{"family": "inet", "table": "existing_firewall", "name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
		map[string]any{"rule": map[string]any{"family": "inet", "table": "existing_firewall", "chain": "input", "expr": []any{
			map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "tcp", "field": "dport"}}, "right": 22}},
			map[string]any{"counter": map[string]any{"packets": 0, "bytes": 0}}, map[string]any{"accept": nil},
		}}},
	}
	objects = append(objects, extra...)
	b, err := json.Marshal(map[string]any{"nftables": objects})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestHostInventoryPreservesFiltersAndRejectsPacketRewrite(t *testing.T) {
	if err := RequireNoUnownedPacketRewrite(filterInventory(t)); err != nil {
		t.Fatal("existingSSHfilterrejected", err)
	}
	for _, statement := range []string{"dnat", "snat", "masquerade", "redirect", "tproxy", "mangle", "notrack", "flow", "fwd", "dup", "queue", "vmap", "ct helper", "ct timeout", "ct expectation", "add", "update", "delete", "synproxy", "unknown"} {
		t.Run(statement, func(t *testing.T) {
			rule := map[string]any{"rule": map[string]any{"family": "inet", "table": "existing_firewall", "chain": "input", "expr": []any{map[string]any{statement: nil}}}}
			if err := RequireNoUnownedPacketRewrite(filterInventory(t, rule)); !errors.Is(err, ErrReadback) {
				t.Fatal("packetrewriteaccepted", err)
			}
		})
	}
	for _, typ := range []string{"nat", "route", "unknown"} {
		extra := map[string]any{"chain": map[string]any{"family": "ip", "table": "docker", "name": "prerouting", "type": typ, "hook": "prerouting", "prio": -100, "policy": "accept"}}
		if RequireNoUnownedPacketRewrite(filterInventory(t, extra)) == nil {
			t.Fatal("unownedbasechainrewriteaccepted")
		}
	}
	for _, kind := range []string{"flowtable", "ct helper", "ct timeout", "ct expectation", "unknown"} {
		extra := map[string]any{kind: map[string]any{"family": "inet", "table": "existing_firewall", "name": "offload"}}
		if RequireNoUnownedPacketRewrite(filterInventory(t, extra)) == nil {
			t.Fatal("unownedoffload/CTobjectaccepted")
		}
	}
}
func TestHostInventoryOwnNameCannotHideUnownedRewrite(t *testing.T) {
	for _, tc := range []struct{ family, name string }{{"ip", HostTable}, {"inet", NATTable}, {"inet", NamespaceTable}} {
		extra := map[string]any{"table": map[string]any{"family": tc.family, "name": tc.name}}
		if RequireNoUnownedPacketRewrite(filterInventory(t, extra)) == nil {
			t.Fatal("ownednamealiasaccepted")
		}
	}
	for _, bad := range [][]byte{nil, []byte(`{"nftables":[],"nftables":[]}`), []byte(`{"nftables":[{"metainfo":{"version":"test","release_name":"test","json_schema_version":2}}]}`), append(filterInventory(t), []byte(`{}`)...)} {
		if RequireNoUnownedPacketRewrite(bad) == nil {
			t.Fatal("malformedinventoryaccepted")
		}
	}
}
