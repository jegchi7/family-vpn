package netstand

import (
	"bytes"
	"encoding/json"
	"familyvpn.local/platform/internal/netguard"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

func decoded(data []byte) (any, error) {
	if len(data) == 0 || len(data) > 1024*1024 {
		return nil, ErrInventory
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) (any, error)
	value = func(depth int) (any, error) {
		if depth > 32 {
			return nil, ErrInventory
		}
		t, e := d.Token()
		if e != nil {
			return nil, ErrInventory
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return t, nil
		}
		if delim == '[' {
			var a []any
			for d.More() {
				v, e := value(depth + 1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			if t, e := d.Token(); e != nil || t != json.Delim(']') {
				return nil, ErrInventory
			}
			return a, nil
		}
		if delim == '{' {
			o := map[string]any{}
			for d.More() {
				t, e := d.Token()
				k, ok := t.(string)
				if e != nil || !ok {
					return nil, ErrInventory
				}
				if _, exists := o[k]; exists {
					return nil, ErrInventory
				}
				v, e := value(depth + 1)
				if e != nil {
					return nil, e
				}
				o[k] = v
			}
			if t, e := d.Token(); e != nil || t != json.Delim('}') {
				return nil, ErrInventory
			}
			return o, nil
		}
		return nil, ErrInventory
	}
	v, e := value(0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrInventory
	}
	return v, nil
}
func records(data []byte, max int) ([]map[string]any, error) {
	value, e := decoded(data)
	a, ok := value.([]any)
	if e != nil || !ok || len(a) > max {
		return nil, ErrInventory
	}
	out := make([]map[string]any, len(a))
	for n, v := range a {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, ErrInventory
		}
		out[n] = m
	}
	return out, nil
}
func text(m map[string]any, key string) (string, bool) { s, ok := m[key].(string); return s, ok }
func parseLinks(data []byte) ([]string, error) {
	_, names, e := kernelLinks(data)
	return names, e
}
func parseAddresses(data []byte) ([]netguard.Address, error) {
	rows, e := records(data, 256)
	if e != nil {
		return nil, e
	}
	out := []netguard.Address{}
	for _, row := range rows {
		name, ok := text(row, "ifname")
		if !ok {
			return nil, ErrInventory
		}
		addresses, ok := row["addr_info"].([]any)
		if !ok {
			return nil, ErrInventory
		}
		for _, v := range addresses {
			a, ok := v.(map[string]any)
			if !ok {
				return nil, ErrInventory
			}
			family, ok := text(a, "family")
			if !ok || (family != "inet" && family != "inet6") {
				return nil, ErrInventory
			}
			local, ok := text(a, "local")
			ip, e := netip.ParseAddr(local)
			bits, valid := a["prefixlen"].(json.Number)
			n, bitsErr := strconv.Atoi(string(bits))
			if !ok || e != nil || !valid || bitsErr != nil || ip.Is4In6() || ip.Zone() != "" || family == "inet" && !ip.Is4() || family == "inet6" && !ip.Is6() {
				return nil, ErrInventory
			}
			prefix := netip.PrefixFrom(ip, n)
			if !prefix.IsValid() {
				return nil, ErrInventory
			}
			out = append(out, netguard.Address{Interface: name, Prefix: prefix})
			if len(out) > 512 {
				return nil, ErrInventory
			}
		}
	}
	return out, nil
}
func parseRoutes(data []byte) ([]netguard.Route, error) {
	rows, e := records(data, 1024)
	if e != nil {
		return nil, e
	}
	out := make([]netguard.Route, 0, len(rows))
	for _, row := range rows {
		iface, ok := text(row, "dev")
		dst, valid := text(row, "dst")
		if !ok || !valid || iface == "" {
			return nil, ErrInventory
		}
		var p netip.Prefix
		if dst == "default" {
			p = netip.MustParsePrefix("0.0.0.0/0")
		} else if strings.Contains(dst, "/") {
			p, e = netip.ParsePrefix(dst)
		} else {
			var ip netip.Addr
			ip, e = netip.ParseAddr(dst)
			if e == nil {
				p = netip.PrefixFrom(ip, ip.BitLen())
			}
		}
		if e != nil || !p.IsValid() || !p.Addr().Is4() || p != p.Masked() {
			return nil, ErrInventory
		}
		out = append(out, netguard.Route{Interface: iface, Destination: p})
	}
	return out, nil
}

// The first stand supports the ordinary IPv4 RPDB only. Route-table contents
// alone do not rule out fwmark/iif/goto/suppress/UID policy selection. Callers
// use fixed `ip -j -4 -N rule show`; numeric table names avoid rt_tables aliases.
func parsePolicyRules(data []byte) error {
	rows, e := records(data, 3)
	if e != nil || len(rows) != 3 {
		return ErrInventory
	}
	priorities := []string{"0", "32766", "32767"}
	tables := []string{"255", "254", "253"}
	for n, row := range rows {
		for key := range row {
			switch key {
			case "priority", "src", "table", "protocol", "flags":
			default:
				return ErrInventory
			}
		}
		priority, ok := row["priority"].(json.Number)
		if !ok || string(priority) != priorities[n] || row["src"] != "all" {
			return ErrInventory
		}
		table, ok := row["table"].(string)
		if !ok || table != tables[n] {
			return ErrInventory
		}
		if protocol, exists := row["protocol"]; exists && protocol != "2" {
			return ErrInventory
		}
		if flags, exists := row["flags"]; exists {
			a, ok := flags.([]any)
			if !ok || len(a) != 0 {
				return ErrInventory
			}
		}
	}
	return nil
}
func parseNamespaces(data []byte) (bool, error) {
	if len(data) > 1024*1024 {
		return false, ErrInventory
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) > 1024 {
		return false, ErrInventory
	}
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || len(line) > 256 {
			return false, ErrInventory
		}
		if fields[0] == netguard.Namespace {
			return true, nil
		}
	}
	return false, nil
}
func ownedTables(data []byte) (bool, error) {
	value, e := decoded(data)
	top, ok := value.(map[string]any)
	if e != nil || !ok || len(top) != 1 {
		return false, ErrInventory
	}
	items, ok := top["nftables"].([]any)
	if !ok || len(items) > 4096 {
		return false, ErrInventory
	}
	for _, v := range items {
		m, ok := v.(map[string]any)
		if !ok || len(m) != 1 {
			return false, ErrInventory
		}
		if _, meta := m["metainfo"]; meta {
			continue
		}
		obj, ok := m["table"].(map[string]any)
		if !ok {
			return false, ErrInventory
		}
		name, n := text(obj, "name")
		family, f := text(obj, "family")
		if !n || !f {
			return false, ErrInventory
		}
		if name == netguard.HostTable || name == netguard.NATTable || name == netguard.NamespaceTable {
			return true, nil
		}
		_ = family
	}
	return false, nil
}
func forwarding(data []byte) (bool, error) {
	if bytes.Equal(data, []byte("0\n")) {
		return false, nil
	}
	if bytes.Equal(data, []byte("1\n")) {
		return true, nil
	}
	return false, ErrInventory
}
func port443Free(data []byte) error {
	if len(data) == 0 || len(data) > 1024*1024 {
		return ErrInventory
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 1 || !strings.Contains(lines[0], "local_address") {
		return ErrInventory
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return ErrInventory
		}
		local := strings.Split(fields[1], ":")
		if len(local) != 2 {
			return ErrInventory
		}
		port, e := strconv.ParseUint(local[1], 16, 16)
		if e != nil {
			return ErrInventory
		}
		if port == 443 && fields[3] == "0A" {
			return ErrInventory
		}
	}
	return nil
}
