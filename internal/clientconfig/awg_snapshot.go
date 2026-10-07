package clientconfig

import (
	"bytes"
	"crypto/ecdh"
	"familyvpn.local/platform/internal/profilevault"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Parse a bounded showconf-shaped readback. It is never executed as awg-quick.
func awgSections(data []byte) (map[string]string, []map[string]string, error) {
	if len(data) == 0 || len(data) > profilevault.MaxSize || !utf8.Valid(data) {
		return nil, nil, ErrSnapshot
	}
	for _, c := range string(data) {
		if (unicode.IsControl(c) && c != '\r' && c != '\n' && c != '\t') || unicode.Is(unicode.Cf, c) {
			return nil, nil, ErrSnapshot
		}
	}
	iface := map[string]string{}
	peers := []map[string]string{}
	var fields map[string]string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if strings.ContainsRune(line, '\r') {
			return nil, nil, ErrSnapshot
		}
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.EqualFold(line, "[Interface]") && fields == nil {
			fields = iface
			continue
		}
		if strings.EqualFold(line, "[Peer]") && fields != nil && len(peers) < 256 {
			fields = map[string]string{}
			peers = append(peers, fields)
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		if !ok || fields == nil || value == "" || strings.HasPrefix(line, "[") {
			return nil, nil, ErrSnapshot
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, nil, ErrSnapshot
		}
		fields[key] = value
	}
	if fields == nil {
		return nil, nil, ErrSnapshot
	}
	return iface, peers, nil
}

func awgSnapshotField(key, value string, peer bool) bool {
	if peer {
		switch key {
		case "publickey", "presharedkey":
			b, ok := awgKey(value)
			clear(b)
			return ok
		case "endpoint":
			return awgEndpoint(value)
		case "allowedips":
			for _, part := range strings.Split(value, ",") {
				if _, e := netip.ParsePrefix(strings.TrimSpace(part)); e != nil {
					return false
				}
			}
			return true
		case "persistentkeepalive":
			_, _, ok := awgRange(value, 16)
			return ok
		case "advancedsecurity":
			return value == "on" || value == "off"
		}
		return false
	}
	switch key {
	case "privatekey", "headerprotectionkey":
		b, ok := awgKey(value)
		clear(b)
		return ok
	case "listenport", "jc", "jmin", "jmax", "s1", "s2", "s3", "s4":
		_, ok := awgNumber(value, 16)
		return ok
	case "h1", "h2", "h3", "h4":
		_, _, ok := awgRange(value, 32)
		return ok
	case "contentpaddingaddition", "rekeyaftertime", "rekeytimeout", "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts":
		_, _, ok := awgRange(value, 16)
		return ok
	case "randomtrailers", "disablecookies":
		return value == "on" || value == "off"
	case "i1", "i2", "i3", "i4", "i5":
		return awgCPS(value)
	case "fwmark":
		if value == "off" {
			return true
		}
		// showconf prints nonzero marks as 0x%x. This is readback metadata,
		// never a permission to import a client FwMark or modify routing.
		if strings.HasPrefix(value, "0x") {
			hex := value[2:]
			if len(hex) < 1 || len(hex) > 8 {
				return false
			}
			for _, c := range hex {
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
					return false
				}
			}
			_, e := strconv.ParseUint(hex, 16, 32)
			return e == nil
		}
		_, ok := awgNumber(value, 32)
		return ok
	}
	return false
}

func awgEqualKey(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	x, ok := awgKey(a)
	defer clear(x)
	y, other := awgKey(b)
	defer clear(y)
	return ok && other && bytes.Equal(x, y)
}

// CheckAWGSnapshot compares peer identity, server identity, port and shared wire
// parameters. Configuration bytes alone are not evidence of a running core.
// No endpoint lookup, connection, private key, address or raw error is returned.
func CheckAWGSnapshot(client, snapshot []byte, endpoint string) ([]string, error) {
	v, e := Validate(AWG31Conf, client)
	if e != nil {
		return nil, e
	}
	ci, cp, e := awgSections(client)
	if e != nil || len(cp) != 1 {
		return nil, ErrInvalid
	}
	si, peers, e := awgSections(snapshot)
	if e != nil {
		return nil, e
	}
	for k, value := range si {
		if !awgSnapshotField(k, value, false) {
			return nil, ErrSnapshot
		}
	}
	for _, peer := range peers {
		for k, value := range peer {
			if !awgSnapshotField(k, value, true) {
				return nil, ErrSnapshot
			}
		}
		if peer["publickey"] == "" {
			return nil, ErrSnapshot
		}
	}
	if !awgEndpoint(endpoint) || si["privatekey"] == "" || si["listenport"] == "" {
		return nil, ErrSnapshot
	}
	fields := []string{}
	_, port, _ := net.SplitHostPort(endpoint)
	expected, _ := awgNumber(port, 16)
	listen, _ := awgNumber(si["listenport"], 16)
	if expected == 0 || listen != expected || cp[0]["endpoint"] != endpoint {
		fields = append(fields, "endpoint")
	}
	private, _ := awgKey(si["privatekey"])
	defer clear(private)
	key, e := ecdh.X25519().NewPrivateKey(private)
	if e != nil {
		return nil, ErrSnapshot
	}
	serverPublic, _ := awgKey(cp[0]["publickey"])
	defer clear(serverPublic)
	if !bytes.Equal(key.PublicKey().Bytes(), serverPublic) {
		fields = append(fields, "server_key")
	}
	if !awgEqualKey(ci["headerprotectionkey"], si["headerprotectionkey"]) {
		fields = append(fields, "header_protection")
	}
	for _, name := range []string{"s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4"} {
		bits := 16
		if name[0] == 'h' {
			bits = 32
		}
		a, b, _ := awgRange(ci[name], bits)
		x, y, ok := awgRange(si[name], bits)
		if !ok || a != x || b != y {
			fields = append(fields, name)
		}
	}
	for _, name := range []string{"randomtrailers", "disablecookies"} {
		// Treat omitted booleans as off on both sides; an omitted client
		// value must not silently accept an explicitly enabled server mode.
		a, b := ci[name], si[name]
		if a == "" {
			a = "off"
		}
		if b == "" {
			b = "off"
		}
		if a != b {
			fields = append(fields, name)
		}
	}
	addresses := []netip.Addr{}
	for _, p := range strings.Split(ci["address"], ",") {
		prefix, _ := netip.ParsePrefix(strings.TrimSpace(p))
		addresses = append(addresses, prefix.Addr())
	}
	var selected map[string]string
	for _, peer := range peers {
		pub, _ := awgKey(peer["publickey"])
		same := bytes.Equal(pub, v.credential[:])
		clear(pub)
		if same {
			if selected != nil {
				return nil, ErrSnapshot
			}
			selected = peer
			continue
		}
		for _, p := range strings.Split(peer["allowedips"], ",") {
			prefix, e := netip.ParsePrefix(strings.TrimSpace(p))
			if e != nil {
				continue
			}
			for _, addr := range addresses {
				if prefix.Contains(addr) {
					fields = append(fields, "address_conflict")
					break
				}
			}
		}
	}
	if selected == nil {
		fields = append(fields, "peer_missing")
		return uniqueAWGFields(fields), nil
	}
	// The M1 AWG3.1 readback contract requires explicit positive evidence
	// for this selected peer. Missing metadata is unknown, not enabled.
	// This conservative policy does not claim every core exposes this flag.
	if selected["advancedsecurity"] != "on" {
		fields = append(fields, "advanced_security")
	}
	if !awgEqualKey(cp[0]["presharedkey"], selected["presharedkey"]) {
		fields = append(fields, "preshared_key")
	}
	seen := map[netip.Addr]bool{}
	for _, p := range strings.Split(selected["allowedips"], ",") {
		prefix, e := netip.ParsePrefix(strings.TrimSpace(p))
		if e != nil || prefix.Bits() != prefix.Addr().BitLen() || seen[prefix.Addr()] {
			fields = append(fields, "peer_addresses")
			continue
		}
		seen[prefix.Addr()] = true
	}
	if len(seen) != len(addresses) {
		fields = append(fields, "peer_addresses")
	}
	for _, addr := range addresses {
		if !seen[addr] {
			fields = append(fields, "peer_addresses")
		}
	}
	return uniqueAWGFields(fields), nil
}

func uniqueAWGFields(fields []string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, f := range fields {
		if !seen[f] {
			result = append(result, f)
			seen[f] = true
		}
	}
	return result
}
