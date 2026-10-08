package netstand

import (
	"bytes"
	"encoding/json"
	"familyvpn.local/platform/internal/netguard"
	"net/netip"
	"strconv"
)

// These parsers consume fixed-tool observations only. They neither select a
// target namespace nor create permission to execute a core.
type kernelLink struct {
	index, peer int
	up          bool
	row         map[string]any
}

func integer(v any, minimum, maximum int) (int, bool) {
	n, ok := v.(json.Number)
	x, e := strconv.Atoi(string(n))
	return x, ok && e == nil && strconv.Itoa(x) == string(n) && x >= minimum && x <= maximum
}

func kernelLinks(data []byte) (map[string]kernelLink, []string, error) {
	rows, e := records(data, 256)
	if e != nil || len(rows) == 0 {
		return nil, nil, ErrInventory
	}
	out := map[string]kernelLink{}
	indexes := map[int]bool{}
	names := []string{}
	for _, row := range rows {
		name, ok := text(row, "ifname")
		index, valid := integer(row["ifindex"], 1, 1<<30)
		if !ok || name == "" || !valid || indexes[index] {
			return nil, nil, ErrInventory
		}
		if _, duplicate := out[name]; duplicate {
			return nil, nil, ErrInventory
		}
		// Even an attachment on an unrelated uplink can redirect a packet before
		// it reaches the owned nft hooks. An empty/unknown XDP declaration is not
		// evidence of absence.
		for _, key := range []string{"xdp", "xdpgeneric", "xdpdrv", "xdpoffload"} {
			if _, exists := row[key]; exists {
				return nil, nil, ErrInventory
			}
		}
		flags, ok := row["flags"].([]any)
		if !ok || len(flags) == 0 || len(flags) > 32 {
			return nil, nil, ErrInventory
		}
		seen := map[string]bool{}
		up := false
		for _, f := range flags {
			s, ok := f.(string)
			if !ok || s == "" || seen[s] {
				return nil, nil, ErrInventory
			}
			seen[s] = true
			up = up || s == "UP"
		}
		peer := 0
		if raw, exists := row["link_index"]; exists {
			peer, valid = integer(raw, 1, 1<<30)
			if !valid {
				return nil, nil, ErrInventory
			}
		}
		out[name] = kernelLink{index: index, peer: peer, up: up, row: row}
		indexes[index] = true
		names = append(names, name)
	}
	return out, names, nil
}

func ownedLink(l kernelLink, loopback, activated bool) error {
	if activated && !l.up {
		return ErrInventory
	}
	for _, key := range []string{"master", "link", "vrf", "slave_kind", "protinfo", "af_spec"} {
		if _, exists := l.row[key]; exists {
			return ErrInventory
		}
	}
	flags := l.row["flags"].([]any)
	seen := map[string]bool{}
	for _, f := range flags {
		s := f.(string)
		switch s {
		case "UP", "LOWER_UP", "NO-CARRIER", "BROADCAST", "MULTICAST", "LOOPBACK":
		default:
			return ErrInventory
		}
		seen[s] = true
	}
	if loopback {
		if !seen["LOOPBACK"] || seen["BROADCAST"] || seen["MULTICAST"] || l.peer != 0 || l.row["link_type"] != "loopback" {
			return ErrInventory
		}
		if _, exists := l.row["linkinfo"]; exists {
			return ErrInventory
		}
		return nil
	}
	if seen["LOOPBACK"] || !seen["BROADCAST"] || !seen["MULTICAST"] || l.peer == 0 || l.row["link_type"] != "ether" {
		return ErrInventory
	}
	if mtu, ok := integer(l.row["mtu"], 68, 65535); !ok || mtu != 1500 {
		return ErrInventory
	}
	if _, ok := integer(l.row["link_netnsid"], 0, 1<<30); !ok {
		return ErrInventory
	}
	info, ok := l.row["linkinfo"].(map[string]any)
	if !ok || info["info_kind"] != "veth" {
		return ErrInventory
	}
	for key, value := range info {
		if key == "info_kind" {
			continue
		}
		if key != "info_data" {
			return ErrInventory
		}
		m, ok := value.(map[string]any)
		if !ok || len(m) != 0 {
			return ErrInventory
		}
	}
	return nil
}

func topologyAddresses(data []byte, links map[string]kernelLink, owned map[string]netip.Prefix, allowMissingLoopback bool) ([]netguard.Address, error) {
	rows, e := records(data, 256)
	if e != nil || len(rows) != len(links) {
		return nil, ErrInventory
	}
	seen := map[string]bool{}
	for _, row := range rows {
		name, ok := text(row, "ifname")
		l, exists := links[name]
		index, valid := integer(row["ifindex"], 1, 1<<30)
		if !ok || !exists || seen[name] || !valid || index != l.index {
			return nil, ErrInventory
		}
		seen[name] = true
		if expected, own := owned[name]; own {
			addresses, ok := row["addr_info"].([]any)
			if !ok {
				return nil, ErrInventory
			}
			if allowMissingLoopback && name == "lo" && !l.up && len(addresses) == 0 {
				continue
			}
			if len(addresses) != 1 {
				return nil, ErrInventory
			}
			a, ok := addresses[0].(map[string]any)
			if !ok || a["family"] != "inet" || a["local"] != expected.Addr().String() {
				return nil, ErrInventory
			}
			bits, valid := integer(a["prefixlen"], 0, 32)
			if !valid || bits != expected.Bits() {
				return nil, ErrInventory
			}
			for key := range a {
				switch key {
				case "family", "local", "prefixlen", "broadcast", "scope", "label", "valid_life_time", "preferred_life_time":
				default:
					return nil, ErrInventory
				}
			}
			if scope, exists := a["scope"]; exists && scope != "global" && !(name == "lo" && scope == "host") {
				return nil, ErrInventory
			}
			if scope, exists := a["scope"]; exists && name == "lo" && scope != "host" {
				return nil, ErrInventory
			}
			if broadcast, exists := a["broadcast"]; exists {
				expectedBroadcast := expected.Masked().Addr().Next().Next().Next().String()
				if name == "lo" {
					expectedBroadcast = "127.255.255.255"
				}
				if broadcast != expectedBroadcast {
					return nil, ErrInventory
				}
			}
			if label, exists := a["label"]; exists && label != name {
				return nil, ErrInventory
			}
			for _, key := range []string{"valid_life_time", "preferred_life_time"} {
				if value, exists := a[key]; exists {
					if value != "forever" && value != json.Number("4294967295") {
						return nil, ErrInventory
					}
				}
			}
		}
	}
	return parseAddresses(data)
}

func routeTable(row map[string]any) (string, bool) {
	if table, exists := row["table"]; exists {
		s, ok := table.(string)
		return s, ok && (s == "255" || s == "254" || s == "253")
	}
	return "254", true
}

func topologyRoutes(data []byte, iface string, ip netip.Addr, transit netip.Prefix, gateway netip.Addr, active bool, namespace bool) ([]netguard.Route, error) {
	rows, e := records(data, 1024)
	if e != nil || len(rows) == 0 {
		return nil, ErrInventory
	}
	seen := map[string]bool{}
	connected, local, def, loopback, loopbackLocal := false, false, false, false, false
	out := []netguard.Route{}
	for _, row := range rows {
		for key := range row {
			switch key {
			case "dst", "gateway", "dev", "protocol", "scope", "prefsrc", "table", "flags", "metric", "type":
			default:
				return nil, ErrInventory
			}
		}
		table, ok := routeTable(row)
		if !ok {
			return nil, ErrInventory
		}
		// ip -j -4 -N route show table all keeps table ids numeric. No custom
		// route table, encapsulation, multipath or route selector is supported.
		b, e := json.Marshal([]map[string]any{row})
		if e != nil {
			return nil, ErrInventory
		}
		parsed, e := parseRoutes(b)
		if e != nil || len(parsed) != 1 {
			return nil, ErrInventory
		}
		r := parsed[0]
		key := table + "|" + r.Interface + "|" + r.Destination.String() + "|"
		kind := "1"
		if value, exists := row["type"]; exists {
			kind, ok = value.(string)
			if !ok {
				return nil, ErrInventory
			}
		}
		if kind != "1" && kind != "2" && kind != "3" {
			return nil, ErrInventory
		}
		key += kind
		if seen[key] {
			return nil, ErrInventory
		}
		seen[key] = true
		if r.Interface != iface && !(namespace && r.Interface == "lo") {
			if namespace || r.Destination.Bits() != 0 && r.Destination.Overlaps(transit) {
				return nil, ErrInventory
			}
			out = append(out, r)
			continue
		}
		if _, exists := row["metric"]; exists {
			return nil, ErrInventory
		}
		if flags, exists := row["flags"]; exists {
			list, ok := flags.([]any)
			if !ok || len(list) > 1 || len(list) == 1 && (list[0] != "linkdown" || active) {
				return nil, ErrInventory
			}
		}
		if source, exists := row["prefsrc"]; exists && source != ip.String() && !(r.Interface == "lo" && source == "127.0.0.1") {
			return nil, ErrInventory
		}
		if r.Interface == "lo" {
			if table != "255" || row["protocol"] != "2" {
				return nil, ErrInventory
			}
			if _, exists := row["gateway"]; exists {
				return nil, ErrInventory
			}
			switch r.Destination.String() {
			case "127.0.0.0/8":
				if kind != "2" || row["scope"] != "254" {
					return nil, ErrInventory
				}
				loopback = true
			case "127.0.0.1/32":
				if kind != "2" || row["scope"] != "254" {
					return nil, ErrInventory
				}
				loopbackLocal = true
			case "127.0.0.0/32", "127.255.255.255/32":
				if kind != "3" || row["scope"] != "253" {
					return nil, ErrInventory
				}
			default:
				return nil, ErrInventory
			}
			continue
		}
		if r.Destination.Bits() == 0 {
			if !namespace || def || table != "254" || kind != "1" || row["gateway"] != gateway.String() {
				return nil, ErrInventory
			}
			if scope, exists := row["scope"]; exists && scope != "0" {
				return nil, ErrInventory
			}
			if protocol, exists := row["protocol"]; exists && protocol != "3" {
				return nil, ErrInventory
			}
			def = true
			continue
		}
		if _, exists := row["gateway"]; exists {
			return nil, ErrInventory
		}
		if row["protocol"] != "2" {
			return nil, ErrInventory
		}
		switch {
		case r.Destination == transit && table == "254" && kind == "1" && row["scope"] == "253":
			connected = true
		case r.Destination == netip.PrefixFrom(ip, 32) && table == "255" && kind == "2" && row["scope"] == "254":
			local = true
		case table == "255" && kind == "3" && row["scope"] == "253" && r.Destination.Bits() == 32 && (r.Destination.Addr() == transit.Addr() || r.Destination.Addr() == transit.Addr().Next().Next().Next()):
		default:
			return nil, ErrInventory
		}
	}
	if !local || active && !connected || namespace && active && (!def || !loopback || !loopbackLocal) {
		return nil, ErrInventory
	}
	return out, nil
}

func validateKernelTopology(hostLinks, hostAddresses, hostRoutes, namespaceLinks, namespaceAddresses, namespaceRoutes []byte, p netguard.Plan, activated bool) (netguard.Inventory, error) {
	var inventory netguard.Inventory
	transit, e := netip.ParsePrefix(p.Transit)
	hostIP, h := netip.ParseAddr(p.HostIPv4)
	nsIP, n := netip.ParseAddr(p.NamespaceIPv4)
	if e != nil || h != nil || n != nil || !transit.IsValid() || transit.Bits() != 30 || transit != transit.Masked() || !transit.Addr().Is4() || hostIP != transit.Addr().Next() || nsIP != hostIP.Next() {
		return inventory, ErrInventory
	}
	host, names, e := kernelLinks(hostLinks)
	if e != nil {
		return inventory, e
	}
	ns, _, e := kernelLinks(namespaceLinks)
	if e != nil || len(ns) != 2 {
		return inventory, ErrInventory
	}
	hv, haveHost := host[netguard.HostVeth]
	nv, haveNS := ns[netguard.NamespaceVeth]
	lo, haveLo := ns["lo"]
	if !haveHost || !haveNS || !haveLo || hv.peer != nv.index || nv.peer != hv.index || ownedLink(hv, false, activated) != nil || ownedLink(nv, false, activated) != nil || ownedLink(lo, true, activated) != nil {
		return inventory, ErrInventory
	}
	if _, wrong := host[netguard.NamespaceVeth]; wrong {
		return inventory, ErrInventory
	}
	addresses, e := topologyAddresses(hostAddresses, host, map[string]netip.Prefix{netguard.HostVeth: netip.PrefixFrom(hostIP, 30)}, false)
	if e != nil {
		return inventory, e
	}
	if _, e = topologyAddresses(namespaceAddresses, ns, map[string]netip.Prefix{netguard.NamespaceVeth: netip.PrefixFrom(nsIP, 30), "lo": netip.MustParsePrefix("127.0.0.1/8")}, !activated); e != nil {
		return inventory, e
	}
	for _, name := range names {
		if name != netguard.HostVeth {
			inventory.Interfaces = append(inventory.Interfaces, name)
		}
	}
	for _, address := range addresses {
		if address.Interface != netguard.HostVeth {
			inventory.Addresses = append(inventory.Addresses, address)
		}
	}
	inventory.Routes, e = topologyRoutes(hostRoutes, netguard.HostVeth, hostIP, transit, netip.Addr{}, hv.up, false)
	if e != nil {
		return netguard.Inventory{}, e
	}
	if _, e = topologyRoutes(namespaceRoutes, netguard.NamespaceVeth, nsIP, transit, hostIP, activated, true); e != nil {
		return netguard.Inventory{}, e
	}
	return inventory, nil
}

// No filter/action declaration is supported by this first primary stand.
func parseEmptyTCFilters(data []byte) error {
	rows, e := records(data, 0)
	if e != nil || len(rows) != 0 {
		return ErrInventory
	}
	return nil
}

func parseQdiscs(data []byte, allowedInterfaces []string) error {
	if len(allowedInterfaces) == 0 || len(allowedInterfaces) > 256 {
		return ErrInventory
	}
	allowed := map[string]bool{}
	for _, name := range allowedInterfaces {
		if name == "" || allowed[name] {
			return ErrInventory
		}
		allowed[name] = true
	}
	rows, e := records(data, 4096)
	if e != nil || len(rows) == 0 {
		return ErrInventory
	}
	seen := map[string]bool{}
	interfaces := map[string]bool{}
	roots := map[string]string{}
	children := map[string]bool{}
	for _, row := range rows {
		name, ok := text(row, "dev")
		kind, valid := text(row, "kind")
		if !ok || !allowed[name] || !valid {
			return ErrInventory
		}
		switch kind {
		case "noqueue", "mq", "pfifo_fast", "fq_codel", "fq":
		default:
			return ErrInventory
		}
		for key := range row {
			switch key {
			case "kind", "handle", "dev", "parent", "root", "refcnt", "options":
			default:
				return ErrInventory
			}
		}
		handle, ok := text(row, "handle")
		if !ok || handle == "" || len(handle) > 16 {
			return ErrInventory
		}
		parent, _ := text(row, "parent")
		key := name + "|" + handle + "|" + parent
		if seen[key] {
			return ErrInventory
		}
		seen[key] = true
		interfaces[name] = true
		if root, exists := row["root"]; exists {
			if root != true || roots[name] != "" {
				return ErrInventory
			}
			roots[name] = kind
		} else if parent, ok := text(row, "parent"); !ok || parent == "" || len(parent) > 16 {
			return ErrInventory
		} else {
			children[name] = true
		}
		if _, exists := row["root"]; exists {
			if _, exists := row["parent"]; exists {
				return ErrInventory
			}
		}
		if ref, exists := row["refcnt"]; exists {
			if _, ok := integer(ref, 0, 1<<30); !ok {
				return ErrInventory
			}
		}
		if options, exists := row["options"]; exists {
			if _, ok := options.(map[string]any); !ok {
				return ErrInventory
			}
		}
	}
	if len(interfaces) != len(allowed) {
		return ErrInventory
	}
	for name := range allowed {
		if roots[name] == "" || children[name] && roots[name] != "mq" {
			return ErrInventory
		}
	}
	return nil
}

func kernelSysctlKeys(scope string) []string {
	if scope == "host" {
		return []string{"net.ipv4.ip_forward", "net.ipv6.conf." + netguard.HostVeth + ".disable_ipv6", "net.ipv4.conf." + netguard.HostVeth + ".rp_filter", "net.ipv4.conf." + netguard.HostVeth + ".accept_redirects", "net.ipv4.conf." + netguard.HostVeth + ".send_redirects", "net.ipv4.conf." + netguard.HostVeth + ".route_localnet"}
	}
	if scope != netguard.Namespace {
		return nil
	}
	keys := []string{"net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6", "net.ipv6.conf.lo.disable_ipv6", "net.ipv6.conf." + netguard.NamespaceVeth + ".disable_ipv6", "net.ipv4.ip_forward"}
	for _, iface := range []string{"all", "default", "lo", netguard.NamespaceVeth} {
		for _, setting := range []string{"rp_filter", "accept_redirects", "send_redirects", "route_localnet"} {
			keys = append(keys, "net.ipv4.conf."+iface+"."+setting)
		}
	}
	return keys
}

func validateKernelSysctls(scope string, data []byte) error {
	keys := kernelSysctlKeys(scope)
	if len(keys) == 0 {
		return ErrInventory
	}
	expected := []byte("1\n1\n1\n0\n0\n0\n")
	if scope == netguard.Namespace {
		expected = []byte("1\n1\n1\n1\n0\n1\n0\n0\n0\n1\n0\n0\n0\n1\n0\n0\n0\n1\n0\n0\n0\n")
	}
	if !bytes.Equal(data, expected) {
		return ErrInventory
	}
	return nil
}
