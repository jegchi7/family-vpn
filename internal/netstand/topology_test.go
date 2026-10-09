package netstand

import (
	"bytes"
	"encoding/json"
	"familyvpn.local/platform/internal/netguard"
	"reflect"
	"testing"
)

type topologyFixture struct{ data [6][]map[string]any }

func (f topologyFixture) json(t *testing.T) [6][]byte {
	t.Helper()
	var out [6][]byte
	for n := range f.data {
		var e error
		out[n], e = json.Marshal(f.data[n])
		if e != nil {
			t.Fatal(e)
		}
	}
	return out
}
func (f topologyFixture) check(t *testing.T, p netguard.Plan, activated bool) (netguard.Inventory, error) {
	t.Helper()
	d := f.json(t)
	return validateKernelTopology(d[0], d[1], d[2], d[3], d[4], d[5], p, activated)
}
func topologyLink(name string, index, peer int, up bool) map[string]any {
	flags := []string{"BROADCAST", "MULTICAST"}
	kind := "ether"
	if name == "lo" {
		flags = []string{"LOOPBACK"}
		kind = "loopback"
	}
	if up {
		flags = append(flags, "UP", "LOWER_UP")
	} else {
		flags = append(flags, "NO-CARRIER")
	}
	m := map[string]any{"ifname": name, "ifindex": index, "flags": flags, "mtu": 1500, "link_type": kind, "qdisc": "noqueue"}
	if peer != 0 {
		m["link_index"] = peer
		m["link_netnsid"] = 0
		m["linkinfo"] = map[string]any{"info_kind": "veth"}
	}
	return m
}
func topologyAddress(name string, index int, ip string, bits int, scope string) map[string]any {
	return map[string]any{"ifname": name, "ifindex": index, "addr_info": []any{map[string]any{"family": "inet", "local": ip, "prefixlen": bits, "scope": scope, "label": name, "valid_life_time": 4294967295, "preferred_life_time": 4294967295}}}
}
func topologyRoute(dev, dst, table, kind, scope, protocol, source string) map[string]any {
	r := map[string]any{"dev": dev, "dst": dst, "table": table, "protocol": protocol, "flags": []string{}}
	if kind != "unicast" {
		r["type"] = map[string]string{"local": "2", "broadcast": "3"}[kind]
	}
	if scope != "" {
		r["scope"] = map[string]string{"host": "254", "link": "253", "global": "0"}[scope]
	}
	if source != "" {
		r["prefsrc"] = source
	}
	return r
}
func activeTopology() topologyFixture {
	f := topologyFixture{}
	f.data[0] = []map[string]any{topologyLink("lo", 1, 0, true), topologyLink("eth0", 2, 0, true), topologyLink(netguard.HostVeth, 10, 11, true)}
	f.data[1] = []map[string]any{topologyAddress("lo", 1, "127.0.0.1", 8, "host"), topologyAddress("eth0", 2, "8.8.4.4", 24, "global"), topologyAddress(netguard.HostVeth, 10, "10.222.0.1", 30, "global")}
	hostDefault := topologyRoute("eth0", "default", "254", "unicast", "", "3", "")
	hostDefault["gateway"] = "8.8.4.1"
	f.data[2] = []map[string]any{hostDefault, topologyRoute(netguard.HostVeth, "10.222.0.0/30", "254", "unicast", "link", "2", "10.222.0.1"), topologyRoute(netguard.HostVeth, "10.222.0.1", "255", "local", "host", "2", "10.222.0.1"), topologyRoute(netguard.HostVeth, "10.222.0.0", "255", "broadcast", "link", "2", "10.222.0.1"), topologyRoute(netguard.HostVeth, "10.222.0.3", "255", "broadcast", "link", "2", "10.222.0.1")}
	f.data[3] = []map[string]any{topologyLink("lo", 1, 0, true), topologyLink(netguard.NamespaceVeth, 11, 10, true)}
	f.data[4] = []map[string]any{topologyAddress("lo", 1, "127.0.0.1", 8, "host"), topologyAddress(netguard.NamespaceVeth, 11, "10.222.0.2", 30, "global")}
	nsDefault := topologyRoute(netguard.NamespaceVeth, "default", "254", "unicast", "", "3", "")
	nsDefault["gateway"] = "10.222.0.1"
	f.data[5] = []map[string]any{nsDefault, topologyRoute(netguard.NamespaceVeth, "10.222.0.0/30", "254", "unicast", "link", "2", "10.222.0.2"), topologyRoute(netguard.NamespaceVeth, "10.222.0.2", "255", "local", "host", "2", "10.222.0.2"), topologyRoute(netguard.NamespaceVeth, "10.222.0.0", "255", "broadcast", "link", "2", "10.222.0.2"), topologyRoute(netguard.NamespaceVeth, "10.222.0.3", "255", "broadcast", "link", "2", "10.222.0.2"), topologyRoute("lo", "127.0.0.0/8", "255", "local", "host", "2", "127.0.0.1"), topologyRoute("lo", "127.0.0.1", "255", "local", "host", "2", "127.0.0.1"), topologyRoute("lo", "127.0.0.0", "255", "broadcast", "link", "2", "127.0.0.1"), topologyRoute("lo", "127.255.255.255", "255", "broadcast", "link", "2", "127.0.0.1")}
	return f
}
func beforeUPTopology() topologyFixture {
	f := activeTopology()
	f.data[0][2] = topologyLink(netguard.HostVeth, 10, 11, false)
	f.data[3][0] = topologyLink("lo", 1, 0, false)
	f.data[3][1] = topologyLink(netguard.NamespaceVeth, 11, 10, false)
	f.data[4][0]["addr_info"] = []any{}
	f.data[2] = []map[string]any{f.data[2][0], f.data[2][2]}
	f.data[5] = []map[string]any{f.data[5][2]}
	return f
}
func TestTopologyPhasesRequireFinalKernelRoutesWithoutInventingPreUPState(t *testing.T) {
	i, _, _, p := syntheticPlan(t)
	before := beforeUPTopology()
	if _, e := before.check(t, p, false); e != nil {
		t.Fatal("Linux pre-UP state rejected", e)
	}
	if _, e := before.check(t, p, true); e == nil {
		t.Fatal("inactive topology became final proof")
	}
	afterHost := beforeUPTopology()
	afterHost.data[0][2] = topologyLink(netguard.HostVeth, 10, 11, true)
	afterHost.data[2] = activeTopology().data[2]
	if _, e := afterHost.check(t, p, false); e != nil {
		t.Fatal("host-UP/namespace-DOWN phase rejected", e)
	}
	afterLo := afterHost
	afterLo.data[3][0] = topologyLink("lo", 1, 0, true)
	afterLo.data[4][0] = activeTopology().data[4][0]
	afterLo.data[5] = append(afterLo.data[5], activeTopology().data[5][5:]...)
	if _, e := afterLo.check(t, p, false); e != nil {
		t.Fatal("loopback-UP phase rejected", e)
	}
	full := activeTopology()
	inventory, e := full.check(t, p, true)
	if e != nil {
		t.Fatal("complete activated topology rejected", e)
	}
	if inventory.IPv4Forwarding {
		t.Fatal("topology fabricated sysctl observation")
	}
	if len(inventory.Interfaces) != 2 || len(inventory.Addresses) != 2 || len(inventory.Routes) != 1 {
		t.Fatal("owned objects leaked into reconstructed baseline")
	}
	inventory.IPv4Forwarding = true
	rebuilt, e := netguard.Build(i, inventory)
	if e != nil || !bytes.Equal(rebuilt.HostFirewall, p.HostFirewall) || !bytes.Equal(rebuilt.NamespaceFirewall, p.NamespaceFirewall) {
		t.Fatal("fresh management inventory failed canonical rebuild", e)
	}
	for n := range full.data {
		for a, b := 0, len(full.data[n])-1; a < b; a, b = a+1, b-1 {
			full.data[n][a], full.data[n][b] = full.data[n][b], full.data[n][a]
		}
	}
	if _, e := full.check(t, p, true); e != nil {
		t.Fatal("inventory order incorrectly determined topology", e)
	}
}

func TestTopologyRejectsWrongPeersExtraAddressesAndRoutingOverrides(t *testing.T) {
	_, _, _, p := syntheticPlan(t)
	for _, tc := range []struct {
		name   string
		change func(*topologyFixture)
	}{
		{"wrong host peer", func(f *topologyFixture) { f.data[0][2]["link_index"] = 12 }},
		{"wrong namespace peer", func(f *topologyFixture) { f.data[3][1]["link_index"] = 12 }},
		{"missing cross namespace proof", func(f *topologyFixture) { delete(f.data[0][2], "link_netnsid") }},
		{"wrong veth type", func(f *topologyFixture) { f.data[0][2]["linkinfo"] = map[string]any{"info_kind": "bridge"} }},
		{"veth tunnel metadata", func(f *topologyFixture) {
			f.data[3][1]["linkinfo"] = map[string]any{"info_kind": "veth", "info_data": map[string]any{"mode": "tunnel"}}
		}},
		{"master bridge", func(f *topologyFixture) { f.data[0][2]["master"] = "br0" }},
		{"promiscuous veth", func(f *topologyFixture) { f.data[0][2]["flags"] = []string{"UP", "BROADCAST", "MULTICAST", "PROMISC"} }},
		{"duplicate ifindex", func(f *topologyFixture) { f.data[0][2]["ifindex"] = 2 }},
		{"duplicate interface", func(f *topologyFixture) { f.data[0] = append(f.data[0], f.data[0][2]) }},
		{"extra namespace interface", func(f *topologyFixture) { f.data[3] = append(f.data[3], topologyLink("eth1", 20, 21, true)) }},
		{"fixed peer still in host", func(f *topologyFixture) {
			f.data[0] = append(f.data[0], topologyLink(netguard.NamespaceVeth, 21, 22, true))
		}},
		{"uplink XDP", func(f *topologyFixture) {
			f.data[0][1]["xdp"] = map[string]any{"mode": "generic", "prog": map[string]any{"id": 1}}
		}},
		{"empty XDP", func(f *topologyFixture) { f.data[0][1]["xdp"] = nil }},
		{"namespace XDP", func(f *topologyFixture) { f.data[3][1]["xdpdrv"] = 1 }},
		{"wrong assigned address", func(f *topologyFixture) {
			f.data[4][1] = topologyAddress(netguard.NamespaceVeth, 11, "10.222.0.3", 30, "global")
		}},
		{"wrong address index", func(f *topologyFixture) { f.data[4][1]["ifindex"] = 12 }},
		{"duplicate address row", func(f *topologyFixture) { f.data[4][0] = f.data[4][1] }},
		{"namespace IPv6", func(f *topologyFixture) {
			f.data[4][1]["addr_info"] = []any{map[string]any{"family": "inet6", "local": "::1", "prefixlen": 128}}
		}},
		{"extra veth address", func(f *topologyFixture) {
			f.data[1][2]["addr_info"] = append(f.data[1][2]["addr_info"].([]any), map[string]any{"family": "inet", "local": "10.222.1.1", "prefixlen": 24})
		}},
		{"peer address", func(f *topologyFixture) { f.data[4][1]["addr_info"].([]any)[0].(map[string]any)["peer"] = "10.222.0.1" }},
		{"broadcast alias", func(f *topologyFixture) {
			f.data[4][1]["addr_info"].([]any)[0].(map[string]any)["broadcast"] = "8.8.8.8"
		}},
		{"global loopback scope", func(f *topologyFixture) { f.data[4][0]["addr_info"].([]any)[0].(map[string]any)["scope"] = "global" }},
		{"wrong default gateway", func(f *topologyFixture) { f.data[5][0]["gateway"] = "8.8.8.8" }},
		{"wrong default table", func(f *topologyFixture) { f.data[5][0]["table"] = "200" }},
		{"named table alias", func(f *topologyFixture) { f.data[5][0]["table"] = "main" }},
		{"duplicate default", func(f *topologyFixture) { f.data[5] = append(f.data[5], f.data[5][0]) }},
		{"encapsulation bypass", func(f *topologyFixture) { f.data[5][0]["encap"] = map[string]any{"type": "seg6"} }},
		{"multipath bypass", func(f *topologyFixture) { f.data[5][0]["multipath"] = []any{} }},
		{"source selector", func(f *topologyFixture) { f.data[5][0]["from"] = "10.0.0.0/8" }},
		{"foreign scope route", func(f *topologyFixture) {
			f.data[5] = append(f.data[5], topologyRoute("lo", "1.1.1.1/32", "254", "unicast", "link", "2", "127.0.0.1"))
		}},
		{"owned route gateway", func(f *topologyFixture) { f.data[2][1]["gateway"] = "10.222.0.2" }},
		{"other iface overlaps transit", func(f *topologyFixture) {
			f.data[2] = append(f.data[2], topologyRoute("eth0", "10.222.0.0/24", "254", "unicast", "link", "2", "8.8.4.4"))
		}},
		{"missing namespace default", func(f *topologyFixture) { f.data[5] = f.data[5][1:] }},
		{"missing connected", func(f *topologyFixture) { f.data[5] = append(f.data[5][:1], f.data[5][2:]...) }},
		{"missing local address route", func(f *topologyFixture) { f.data[5] = append(f.data[5][:2], f.data[5][3:]...) }},
		{"missing loopback route", func(f *topologyFixture) { f.data[5] = append(f.data[5][:5], f.data[5][6:]...) }},
		{"missing loopback local route", func(f *topologyFixture) { f.data[5] = append(f.data[5][:6], f.data[5][7:]...) }},
		{"owned down final", func(f *topologyFixture) { f.data[3][1] = topologyLink(netguard.NamespaceVeth, 11, 10, false) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := activeTopology()
			tc.change(&f)
			if _, e := f.check(t, p, true); e == nil {
				t.Fatal("altered topology accepted")
			}
		})
	}
	data := activeTopology().json(t)
	data[0] = bytes.Replace(data[0], []byte(`"ifindex":10`), []byte(`"ifindex":10,"ifindex":10`), 1)
	if _, e := validateKernelTopology(data[0], data[1], data[2], data[3], data[4], data[5], p, true); e == nil {
		t.Fatal("duplicate JSON accepted")
	}
}

func TestTCGuardRejectsPacketActionsAndUnknownInterfaces(t *testing.T) {
	good := []byte(`[{"kind":"noqueue","handle":"0:","dev":"lo","root":true,"refcnt":2},{"kind":"mq","handle":"0:","dev":"eth0","root":true,"options":{}},{"kind":"fq_codel","handle":"0:","dev":"eth0","parent":":1","options":{}},{"kind":"fq_codel","handle":"0:","dev":"eth0","parent":":2","options":{}}]`)
	if e := parseQdiscs(good, []string{"lo", "eth0"}); e != nil {
		t.Fatal("ordinary qdiscs rejected", e)
	}
	for _, kind := range []string{"clsact", "ingress", "htb", "prio", "bpf", "netem", "unknown"} {
		data := bytes.Replace(good, []byte(`"noqueue"`), []byte(`"`+kind+`"`), 1)
		if parseQdiscs(data, []string{"lo", "eth0"}) == nil {
			t.Fatal("unsupported qdisc accepted", kind)
		}
	}
	for _, data := range [][]byte{nil, []byte(`[]`), []byte(`[{}]`), bytes.Replace(good, []byte(`"eth0"`), []byte(`"other"`), 1), bytes.Replace(good, []byte(`"root":true`), []byte(`"root":false`), 1), bytes.Replace(good, []byte(`"mq"`), []byte(`"fq"`), 1), bytes.Replace(good, []byte(`"refcnt":2`), []byte(`"refcnt":2,"bpf":{}`), 1)} {
		if parseQdiscs(data, []string{"lo", "eth0"}) == nil {
			t.Fatal("ambiguous TC state accepted")
		}
	}
	if parseEmptyTCFilters([]byte(`[]`)) != nil {
		t.Fatal("empty filters rejected")
	}
	for _, data := range [][]byte{nil, []byte(`[{}]`), []byte(`[{"kind":"bpf","options":{"actions":[]}}]`), []byte(`[] {}`), []byte(`{}`)} {
		if parseEmptyTCFilters(data) == nil {
			t.Fatal("TC action declaration accepted")
		}
	}
	links, _ := json.Marshal(activeTopology().data[0])
	if _, e := parseLinks(links); e != nil {
		t.Fatal(e)
	}
	links = bytes.Replace(links, []byte(`"ifname":"eth0"`), []byte(`"ifname":"eth0","xdp":{}`), 1)
	if _, e := parseLinks(links); e == nil {
		t.Fatal("initial preflight ignored XDP attachment")
	}
}

func TestKernelSysctlProofUsesExactClosedEffectiveInterfaceSettings(t *testing.T) {
	host := []byte("1\n1\n1\n0\n0\n0\n1\n")
	ns := []byte("1\n1\n1\n1\n0\n1\n0\n0\n0\n1\n0\n0\n0\n1\n0\n0\n0\n1\n0\n0\n0\n")
	for _, tc := range []struct {
		scope string
		data  []byte
	}{{"host", host}, {netguard.Namespace, ns}} {
		keys := kernelSysctlKeys(tc.scope)
		if len(keys) != bytes.Count(tc.data, []byte("\n")) {
			t.Fatal("sysctl vector mismatch")
		}
		if validateKernelSysctls(tc.scope, tc.data) != nil {
			t.Fatal("exact sysctl readback rejected")
		}
		for n := 0; n < len(tc.data); n += 2 {
			changed := bytes.Clone(tc.data)
			if changed[n] == '0' {
				changed[n] = '1'
			} else {
				changed[n] = '0'
			}
			if validateKernelSysctls(tc.scope, changed) == nil {
				t.Fatal("effective sysctl mismatch accepted", keys[n/2])
			}
		}
		for _, changed := range [][]byte{nil, bytes.TrimSpace(tc.data), append(bytes.Clone(tc.data), '\n'), bytes.ReplaceAll(tc.data, []byte("\n"), []byte("\r\n")), append([]byte("key = "), tc.data...)} {
			if validateKernelSysctls(tc.scope, changed) == nil {
				t.Fatal("incomplete/noncanonical sysctl accepted")
			}
		}
		other := kernelSysctlKeys(tc.scope)
		other[0] = "changed"
		if reflect.DeepEqual(other, kernelSysctlKeys(tc.scope)) {
			t.Fatal("mutable sysctl key list")
		}
	}
	if validateKernelSysctls("arbitrary", host) == nil || kernelSysctlKeys("arbitrary") != nil {
		t.Fatal("arbitrary scope accepted")
	}
}
