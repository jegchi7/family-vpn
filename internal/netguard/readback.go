package netguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

var ErrReadback = errors.New("VPN kernel guard readback rejected")

// VerifyNFTReadback compares a freshly obtained, pinned nft JSON listing with
// the closed plan. It is a comparator, not an attestation of its input source.
// The caller must bind the read to the expected host/namespace and tool. A
// namespace listing must contain exactly our table. Unrelated host tables are
// retained; their rules are never imported as evidence for our guard.
func VerifyNFTReadback(p Plan, scope string, data []byte) error {
	var script []byte
	if scope == "host" {
		script = p.HostFirewall
	} else if scope == Namespace {
		script = p.NamespaceFirewall
	} else {
		return ErrReadback
	}
	expected, err := expectedNFT(script)
	if err != nil {
		return ErrReadback
	}
	root, err := readNFTJSON(data)
	if err != nil {
		return ErrReadback
	}
	rm, ok := root.(map[string]any)
	if !ok || len(rm) != 1 {
		return ErrReadback
	}
	objects, ok := rm["nftables"].([]any)
	if !ok || len(objects) == 0 || len(objects) > 8192 {
		return ErrReadback
	}
	actual := nftModel{objects: map[string]any{}, rules: map[string][]any{}}
	meta := false
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
				if meta || len(m) != 3 || m["json_schema_version"] != json.Number("1") {
					return ErrReadback
				}
				if _, ok := m["version"].(string); !ok {
					return ErrReadback
				}
				if _, ok := m["release_name"].(string); !ok {
					return ErrReadback
				}
				meta = true
				continue
			}
			family, f := m["family"].(string)
			name, n := m["table"].(string)
			if kind == "table" {
				name, n = m["name"].(string)
			}
			if !f || !n {
				return ErrReadback
			}
			owned := name == HostTable || name == NATTable || name == NamespaceTable
			if !owned {
				if scope != "host" {
					return ErrReadback
				}
				continue
			}
			if (scope == "host" && name == NamespaceTable) || (scope == Namespace && name != NamespaceTable) {
				return ErrReadback
			}
			if err := stripHandle(m); err != nil {
				return ErrReadback
			}
			if kind == "rule" {
				chain, ok := m["chain"].(string)
				if !ok || len(m) != 4 {
					return ErrReadback
				}
				expr, ok := m["expr"].([]any)
				if !ok {
					return ErrReadback
				}
				norm, e := normalizeRule(expr)
				if e != nil {
					return ErrReadback
				}
				key := family + "/" + name + "/" + chain
				actual.rules[key] = append(actual.rules[key], norm)
				continue
			}
			if kind != "table" && kind != "chain" && kind != "set" {
				return ErrReadback
			}
			if kind == "set" {
				if err := normalizeNamedSet(m); err != nil {
					return ErrReadback
				}
			}
			objectName, ok := m["name"].(string)
			if !ok {
				return ErrReadback
			}
			key := kind + "/" + family + "/" + name + "/" + objectName
			if _, exists := actual.objects[key]; exists {
				return ErrReadback
			}
			actual.objects[key] = m
		}
	}
	if !meta || !reflect.DeepEqual(expected, actual) {
		return ErrReadback
	}
	return nil
}

type nftModel struct {
	objects map[string]any
	rules   map[string][]any
}

// Reject duplicate object keys, depth/size overflow and trailing documents.
// Ordinary json.Unmarshal would silently accept duplicate keys in evidence.
func readNFTJSON(data []byte) (any, error) {
	if len(data) == 0 || len(data) > 1<<20 {
		return nil, ErrReadback
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > 24 {
			return nil, ErrReadback
		}
		t, err := d.Token()
		if err != nil {
			return nil, ErrReadback
		}
		switch t {
		case json.Delim('{'):
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, ErrReadback
				}
				s, ok := k.(string)
				if !ok {
					return nil, ErrReadback
				}
				if _, exists := m[s]; exists {
					return nil, ErrReadback
				}
				v, e := read(depth + 1)
				if e != nil {
					return nil, e
				}
				m[s] = v
			}
			if t, e := d.Token(); e != nil || t != json.Delim('}') {
				return nil, ErrReadback
			}
			return m, nil
		case json.Delim('['):
			a := []any{}
			for d.More() {
				if len(a) >= 8192 {
					return nil, ErrReadback
				}
				v, e := read(depth + 1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			if t, e := d.Token(); e != nil || t != json.Delim(']') {
				return nil, ErrReadback
			}
			return a, nil
		default:
			if _, ok := t.(json.Delim); ok {
				return nil, ErrReadback
			}
			return t, nil
		}
	}
	v, e := read(0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrReadback
	}
	return v, nil
}
func stripHandle(m map[string]any) error {
	if v, ok := m["handle"]; ok {
		n, ok := v.(json.Number)
		if !ok {
			return ErrReadback
		}
		value, e := strconv.ParseUint(string(n), 10, 64)
		if e != nil || value == 0 {
			return ErrReadback
		}
		delete(m, "handle")
	}
	return nil
}
func object(kind string, m map[string]any, model *nftModel) error {
	family, _ := m["family"].(string)
	table, _ := m["table"].(string)
	name, _ := m["name"].(string)
	if kind == "table" {
		table = name
	}
	key := kind + "/" + family + "/" + table + "/" + name
	if _, ok := model.objects[key]; ok {
		return ErrReadback
	}
	model.objects[key] = m
	return nil
}

// This compiler is intentionally limited to our generated dialect. It is never
// exposed as a parser for operator-supplied firewall scripts or permission files.
func expectedNFT(script []byte) (nftModel, error) {
	out := nftModel{objects: map[string]any{}, rules: map[string][]any{}}
	family, table, chain := "", "", ""
	for _, line := range strings.Split(string(script), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "}" {
			if chain != "" {
				chain = ""
			} else if table != "" {
				family, table = "", ""
			} else {
				return out, ErrReadback
			}
			continue
		}
		if strings.HasPrefix(line, "table ") {
			f := strings.Fields(line)
			if len(f) != 4 || f[3] != "{" || table != "" {
				return out, ErrReadback
			}
			family, table = f[1], f[2]
			if object("table", map[string]any{"family": family, "name": table}, &out) != nil {
				return out, ErrReadback
			}
			continue
		}
		if table == "" {
			return out, ErrReadback
		}
		if strings.HasPrefix(line, "set blocked {") {
			const prefix = "set blocked { type ipv4_addr; flags interval; elements = { "
			if chain != "" || !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, " }; }") {
				return out, ErrReadback
			}
			elems := []any{}
			for _, s := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(line, prefix), " }; }"), ", ") {
				v, e := nftLiteral(s)
				if e != nil {
					return out, e
				}
				elems = append(elems, v)
			}
			m := map[string]any{"family": family, "table": table, "name": "blocked", "type": "ipv4_addr", "flags": []any{"interval"}, "elem": elems}
			if normalizeNamedSet(m) != nil || object("set", m, &out) != nil {
				return out, ErrReadback
			}
			continue
		}
		if strings.HasPrefix(line, "chain ") {
			f := strings.Fields(line)
			if chain != "" || len(f) < 3 || f[2] != "{" {
				return out, ErrReadback
			}
			chain = f[1]
			m := map[string]any{"family": family, "table": table, "name": chain}
			if len(f) != 3 {
				if len(f) != 11 || f[3] != "type" || f[5] != "hook" || f[7] != "priority" || f[9] != "policy" || (f[10] != "accept;" && f[10] != "drop;") {
					return out, ErrReadback
				}
				priority, e := strconv.Atoi(strings.TrimSuffix(f[8], ";"))
				if e != nil {
					return out, ErrReadback
				}
				m["type"], m["hook"], m["prio"], m["policy"] = f[4], f[6], json.Number(strconv.Itoa(priority)), strings.TrimSuffix(f[10], ";")
			}
			if object("chain", m, &out) != nil {
				return out, ErrReadback
			}
			continue
		}
		if chain == "" {
			return out, ErrReadback
		}
		expr, e := compileNFTRule(line)
		if e != nil {
			return out, e
		}
		norm, e := normalizeRule(expr)
		if e != nil {
			return out, e
		}
		key := family + "/" + table + "/" + chain
		out.rules[key] = append(out.rules[key], norm)
	}
	if table != "" || chain != "" || len(out.objects) == 0 {
		return out, ErrReadback
	}
	return out, nil
}

func nftLiteral(s string) (any, error) {
	if strings.HasPrefix(s, "\"") {
		var v string
		if json.Unmarshal([]byte(s), &v) != nil {
			return nil, ErrReadback
		}
		return v, nil
	}
	if p, e := netip.ParsePrefix(s); e == nil && p.Addr().Is4() && p == p.Masked() {
		return map[string]any{"prefix": map[string]any{"addr": p.Addr().String(), "len": json.Number(strconv.Itoa(p.Bits()))}}, nil
	}
	if n, e := strconv.ParseUint(s, 10, 32); e == nil {
		return json.Number(strconv.FormatUint(n, 10)), nil
	}
	if s == "" {
		return nil, ErrReadback
	}
	return s, nil
}
func compileNFTRule(line string) ([]any, error) {
	tokens := strings.Fields(strings.NewReplacer("{", " { ", "}", " } ", ",", " , ").Replace(line))
	expr := []any{}
	for n := 0; n < len(tokens); {
		start := n
		op := "=="
		var left any
		switch tokens[n] {
		case "accept", "drop":
			if n != len(tokens)-1 {
				return nil, ErrReadback
			}
			expr = append(expr, map[string]any{tokens[n]: nil})
			n++
		case "jump":
			if n+2 != len(tokens) {
				return nil, ErrReadback
			}
			expr = append(expr, map[string]any{"jump": map[string]any{"target": tokens[n+1]}})
			n += 2
		case "dnat", "snat":
			if n+3 != len(tokens) || tokens[n+1] != "to" {
				return nil, ErrReadback
			}
			m := map[string]any{}
			a := tokens[n+2]
			if endpoint, e := netip.ParseAddrPort(a); e == nil {
				m["addr"] = endpoint.Addr().String()
				m["port"] = json.Number(strconv.Itoa(int(endpoint.Port())))
			} else if ip, e := netip.ParseAddr(a); e == nil && ip.Is4() {
				m["addr"] = ip.String()
			} else {
				return nil, ErrReadback
			}
			expr = append(expr, map[string]any{tokens[n]: m})
			n += 3
		case "iifname", "oifname":
			left = map[string]any{"meta": map[string]any{"key": tokens[n]}}
			n++
		case "meta":
			if n+1 >= len(tokens) {
				return nil, ErrReadback
			}
			left = map[string]any{"meta": map[string]any{"key": tokens[n+1]}}
			n += 2
		case "ct":
			n++
			if n >= len(tokens) {
				return nil, ErrReadback
			}
			m := map[string]any{}
			if tokens[n] == "original" || tokens[n] == "reply" {
				m["dir"] = tokens[n]
				n++
			}
			if n >= len(tokens) {
				return nil, ErrReadback
			}
			if tokens[n] == "ip" {
				m["family"] = "ip"
				n++
				if n >= len(tokens) {
					return nil, ErrReadback
				}
			}
			m["key"] = tokens[n]
			left = map[string]any{"ct": m}
			n++
		case "ip", "tcp", "udp", "icmp":
			if n+1 >= len(tokens) {
				return nil, ErrReadback
			}
			left = map[string]any{"payload": map[string]any{"protocol": tokens[n], "field": tokens[n+1]}}
			n += 2
		default:
			return nil, ErrReadback
		}
		if left != nil {
			if n >= len(tokens) {
				return nil, ErrReadback
			}
			if tokens[n] == "!=" {
				op = "!="
				n++
			}
			if n >= len(tokens) {
				return nil, ErrReadback
			}
			var right any
			if tokens[n] == "{" {
				n++
				a := []any{}
				for n < len(tokens) && tokens[n] != "}" {
					if tokens[n] == "," {
						n++
						continue
					}
					v, e := nftLiteral(tokens[n])
					if e != nil {
						return nil, e
					}
					a = append(a, v)
					n++
				}
				if n >= len(tokens) || len(a) == 0 {
					return nil, ErrReadback
				}
				n++
				right = map[string]any{"set": a}
			} else {
				v, e := nftLiteral(tokens[n])
				if e != nil {
					return nil, e
				}
				right = v
				n++
			}
			if m, ok := left.(map[string]any)["ct"].(map[string]any); ok && m["key"] == "state" && op == "==" {
				op = "in"
			}
			expr = append(expr, map[string]any{"match": map[string]any{"left": left, "right": right, "op": op}})
		}
		if n <= start {
			return nil, ErrReadback
		}
	}
	return expr, nil
}

func normalizeRule(expr []any) ([]any, error) {
	if len(expr) == 0 || len(expr) > 32 {
		return nil, ErrReadback
	}
	for n, raw := range expr {
		m, ok := raw.(map[string]any)
		if !ok || len(m) != 1 {
			return nil, ErrReadback
		}
		if match, ok := m["match"].(map[string]any); ok {
			if n == len(expr)-1 || len(match) != 3 {
				return nil, ErrReadback
			}
			left, ok := match["left"].(map[string]any)
			if !ok || len(left) != 1 {
				return nil, ErrReadback
			}
			context := ""
			if ct, ok := left["ct"].(map[string]any); ok {
				key, ok := ct["key"].(string)
				if !ok {
					return nil, ErrReadback
				}
				// nft 0.9.3 emits these explicitly typed keys; current releases
				// emit key + family. An untyped old saddr/daddr is not accepted.
				if key == "ip saddr" || key == "ip daddr" {
					if _, exists := ct["family"]; exists {
						return nil, ErrReadback
					}
					ct["key"] = strings.TrimPrefix(key, "ip ")
					ct["family"] = "ip"
					key = ct["key"].(string)
				}
				context = "ct/" + key
			} else if meta, ok := left["meta"].(map[string]any); ok {
				key, _ := meta["key"].(string)
				context = "meta/" + key
			} else if payload, ok := left["payload"].(map[string]any); ok {
				protocol, _ := payload["protocol"].(string)
				field, _ := payload["field"].(string)
				context = protocol + "/" + field
			} else {
				return nil, ErrReadback
			}
			v, e := normalizeRight(match["right"], context)
			if e != nil {
				return nil, e
			}
			match["right"] = v
		} else {
			if n != len(expr)-1 {
				return nil, ErrReadback
			}
			for kind, v := range m {
				switch kind {
				case "accept", "drop":
					if v != nil {
						return nil, ErrReadback
					}
				case "jump":
					j, ok := v.(map[string]any)
					if !ok || len(j) != 1 {
						return nil, ErrReadback
					}
				case "snat", "dnat":
					j, ok := v.(map[string]any)
					if !ok {
						return nil, ErrReadback
					}
					if family, exists := j["family"]; exists {
						if family != "ip" {
							return nil, ErrReadback
						}
						delete(j, "family")
					}
				default:
					return nil, ErrReadback
				}
			}
		}
	}
	return expr, nil
}
func normalizeRight(v any, context string) (any, error) {
	if m, ok := v.(map[string]any); ok {
		if len(m) != 1 {
			return nil, ErrReadback
		}
		if raw, ok := m["set"]; ok {
			a, ok := raw.([]any)
			if !ok || len(a) == 0 || len(a) > 32 {
				return nil, ErrReadback
			}
			return normalizeAnonymousSet(a, context)
		}
		if raw, ok := m["prefix"].(map[string]any); ok {
			p, e := prefixValue(raw)
			if e != nil {
				return nil, e
			}
			if p.Bits() == 32 {
				return p.Addr().String(), nil
			}
			return map[string]any{"prefix": map[string]any{"addr": p.Addr().String(), "len": json.Number(strconv.Itoa(p.Bits()))}}, nil
		}
		return nil, ErrReadback
	}
	if a, ok := v.([]any); ok {
		if context != "ct/state" {
			return nil, ErrReadback
		}
		return normalizeAnonymousSet(a, context)
	}
	if s, ok := v.(string); ok {
		codes := map[string]map[string]string{"meta/nfproto": {"ipv4": "2"}, "meta/l4proto": {"tcp": "6", "udp": "17", "icmp": "1"}, "ip/protocol": {"tcp": "6", "udp": "17", "icmp": "1"}, "ct/protocol": {"tcp": "6", "udp": "17", "icmp": "1"}, "ct/direction": {"original": "0", "reply": "1"}, "icmp/type": {"destination-unreachable": "3", "time-exceeded": "11", "parameter-problem": "12"}, "ct/state": {"invalid": "1", "established": "2", "related": "4", "new": "8"}}
		if code, ok := codes[context][s]; ok {
			return json.Number(code), nil
		}
		return s, nil
	}
	if _, ok := v.(json.Number); ok {
		return v, nil
	}
	return nil, ErrReadback
}
func normalizeAnonymousSet(a []any, context string) (any, error) {
	out := make([]any, len(a))
	keys := make([]string, len(a))
	seen := map[string]bool{}
	for n, v := range a {
		x, e := normalizeRight(v, context)
		if e != nil {
			return nil, e
		}
		b, e := json.Marshal(x)
		if e != nil || seen[string(b)] {
			return nil, ErrReadback
		}
		seen[string(b)] = true
		keys[n] = string(b)
		out[n] = x
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := json.Marshal(out[i])
		b, _ := json.Marshal(out[j])
		return string(a) < string(b)
	})
	return map[string]any{"set": out}, nil
}
func prefixValue(m map[string]any) (netip.Prefix, error) {
	if len(m) != 2 {
		return netip.Prefix{}, ErrReadback
	}
	a, ok := m["addr"].(string)
	if !ok {
		return netip.Prefix{}, ErrReadback
	}
	n, ok := m["len"].(json.Number)
	if !ok {
		return netip.Prefix{}, ErrReadback
	}
	bits, e := strconv.Atoi(string(n))
	ip, ie := netip.ParseAddr(a)
	if e != nil || ie != nil || !ip.Is4() || bits < 0 || bits > 32 {
		return netip.Prefix{}, ErrReadback
	}
	p := netip.PrefixFrom(ip, bits)
	if p != p.Masked() {
		return netip.Prefix{}, ErrReadback
	}
	return p, nil
}

type ipRange struct{ lo, hi uint64 }

func ipNumber(a netip.Addr) uint64 {
	b := a.As4()
	return uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
}
func elementRange(v any) (ipRange, error) {
	if s, ok := v.(string); ok {
		a, e := netip.ParseAddr(s)
		if e != nil || !a.Is4() {
			return ipRange{}, ErrReadback
		}
		n := ipNumber(a)
		return ipRange{n, n}, nil
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return ipRange{}, ErrReadback
	}
	if pm, ok := m["prefix"].(map[string]any); ok {
		p, e := prefixValue(pm)
		if e != nil {
			return ipRange{}, e
		}
		lo := ipNumber(p.Addr())
		return ipRange{lo, lo + (uint64(1) << uint(32-p.Bits())) - 1}, nil
	}
	if a, ok := m["range"].([]any); ok && len(a) == 2 {
		lo, e := elementRange(a[0])
		hi, he := elementRange(a[1])
		if e != nil || he != nil || lo.lo != lo.hi || hi.lo != hi.hi || lo.lo > hi.hi {
			return ipRange{}, ErrReadback
		}
		return ipRange{lo.lo, hi.hi}, nil
	}
	return ipRange{}, ErrReadback
}
func normalizeNamedSet(m map[string]any) error {
	if len(m) != 6 || m["type"] != "ipv4_addr" || !reflect.DeepEqual(m["flags"], []any{"interval"}) {
		return ErrReadback
	}
	a, ok := m["elem"].([]any)
	if !ok || len(a) == 0 || len(a) > 1024 {
		return ErrReadback
	}
	ranges := make([]ipRange, len(a))
	for n, v := range a {
		r, e := elementRange(v)
		if e != nil {
			return e
		}
		ranges[n] = r
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].lo < ranges[j].lo })
	merged := []ipRange{}
	for _, r := range ranges {
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			if r.lo <= last.hi {
				return ErrReadback
			}
			if r.lo == last.hi+1 {
				last.hi = r.hi
				continue
			}
		}
		merged = append(merged, r)
	}
	m["elem"] = merged
	return nil
}
