package clientconfig

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrSnapshot = errors.New("invalid or unsupported server configuration snapshot")
var ErrSnapshotRevision = errors.New("server configuration snapshot revision differs")

// JSON object keys must be unique, including differently cased aliases accepted
// by encoding/json. Limit nesting before decoding management-side data.
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrSnapshot
	}
	t, e := d.Token()
	if e != nil {
		return ErrSnapshot
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return ErrSnapshot
			}
			s, ok := k.(string)
			if !ok || !textValue(s) {
				return ErrSnapshot
			}
			canonical := strings.ToLower(s)
			if seen[canonical] {
				return ErrSnapshot
			}
			seen[canonical] = true
			if e = uniqueJSON(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e = uniqueJSON(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return ErrSnapshot
	}
	end, e := d.Token()
	if e != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
		return ErrSnapshot
	}
	return nil
}

// exactObject deliberately rejects unknown fields in the selected security
// subset. Other inbounds and root sections are inspected only for JSON ambiguity.
func exactObject(data []byte, allowed ...string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if json.Unmarshal(data, &m) != nil || m == nil {
		return nil, ErrSnapshot
	}
	for k := range m {
		found := false
		for _, a := range allowed {
			if k == a {
				found = true
				break
			}
		}
		if !found {
			return nil, ErrSnapshot
		}
	}
	return m, nil
}

func stringField(m map[string]json.RawMessage, key string) (string, error) {
	var s string
	b, ok := m[key]
	if !ok || bytes.Equal(b, []byte("null")) || json.Unmarshal(b, &s) != nil || !textValue(s) {
		return "", ErrSnapshot
	}
	return s, nil
}
func stringList(m map[string]json.RawMessage, key string) ([]string, error) {
	var list []string
	if json.Unmarshal(m[key], &list) != nil || len(list) == 0 || len(list) > 1024 {
		return nil, ErrSnapshot
	}
	for _, s := range list {
		if !textValue(s) {
			return nil, ErrSnapshot
		}
	}
	return list, nil
}
func uuidBytes(s string) ([]byte, error) {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return nil, ErrSnapshot
	}
	b, e := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if e != nil || len(b) != 16 || bytes.Equal(b, make([]byte, 16)) {
		return nil, ErrSnapshot
	}
	return b, nil
}
func sameHost(a, b string) bool {
	ia, ea := netip.ParseAddr(a)
	ib, eb := netip.ParseAddr(b)
	if ea == nil && eb == nil {
		return ia == ib
	}
	return ea != nil && eb != nil && strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// CheckXraySnapshot is a read-only configuration comparison, never evidence of
// a running core, routing, endpoint reachability, or mobile-client compatibility.
// The server snapshot (including privateKey) stays in the trusted CLI memory.
// Only fixed field names may be returned; neither values nor parser errors escape.
func CheckXraySnapshot(format string, client, snapshot []byte, tag, endpoint, expectedSHA string) ([]string, error) {
	validated, e := Validate(format, client)
	if e != nil {
		return nil, e
	}
	if len(snapshot) == 0 || len(snapshot) > 64*1024 || !utf8.Valid(snapshot) || len(tag) == 0 || len(tag) > 64 {
		return nil, ErrSnapshot
	}
	for _, r := range tag {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
			return nil, ErrSnapshot
		}
	}
	pin, e := hex.DecodeString(expectedSHA)
	if e != nil || len(pin) != 32 || expectedSHA != strings.ToLower(expectedSHA) {
		return nil, ErrSnapshot
	}
	digest := sha256.Sum256(snapshot)
	if !bytes.Equal(pin, digest[:]) {
		return nil, ErrSnapshotRevision
	}
	d := json.NewDecoder(bytes.NewReader(snapshot))
	d.UseNumber()
	if uniqueJSON(d, 0) != nil {
		return nil, ErrSnapshot
	}
	if _, e = d.Token(); !errors.Is(e, io.EOF) {
		return nil, ErrSnapshot
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(snapshot, &root) != nil || root == nil {
		return nil, ErrSnapshot
	}
	var inbounds []json.RawMessage
	if json.Unmarshal(root["inbounds"], &inbounds) != nil || len(inbounds) == 0 || len(inbounds) > 1024 {
		return nil, ErrSnapshot
	}
	var selected []byte
	for _, b := range inbounds {
		var obj map[string]json.RawMessage
		if json.Unmarshal(b, &obj) != nil || obj == nil {
			return nil, ErrSnapshot
		}
		var t string
		if raw, ok := obj["tag"]; ok {
			if json.Unmarshal(raw, &t) != nil {
				return nil, ErrSnapshot
			}
		}
		if t == tag {
			if selected != nil {
				return nil, ErrSnapshot
			}
			selected = b
		}
	}
	if selected == nil {
		return nil, ErrSnapshot
	}
	in, e := exactObject(selected, "tag", "listen", "port", "protocol", "settings", "streamSettings", "sniffing")
	if e != nil {
		return nil, e
	}
	protocol, e := stringField(in, "protocol")
	if e != nil || protocol != "vless" {
		return nil, ErrSnapshot
	}
	var port int
	if json.Unmarshal(in["port"], &port) != nil || port < 1 || port > 65535 {
		return nil, ErrSnapshot
	}
	listen := ""
	if _, ok := in["listen"]; ok {
		listen, e = stringField(in, "listen")
		if e != nil {
			return nil, e
		}
	}
	if listen != "" {
		ip, e := netip.ParseAddr(listen)
		if e != nil || ip.Zone() != "" {
			return nil, ErrSnapshot
		}
	}
	settings, e := exactObject(in["settings"], "clients", "decryption", "fallbacks")
	if e != nil {
		return nil, e
	}
	decryption, e := stringField(settings, "decryption")
	if e != nil || decryption != "none" {
		return nil, ErrSnapshot
	}
	if raw, ok := settings["fallbacks"]; ok {
		var f []json.RawMessage
		if json.Unmarshal(raw, &f) != nil || len(f) != 0 {
			return nil, ErrSnapshot
		}
	}
	stream, e := exactObject(in["streamSettings"], "network", "security", "realitySettings")
	if e != nil {
		return nil, e
	}
	network, e := stringField(stream, "network")
	if e != nil || (network != "tcp" && network != "raw") {
		return nil, ErrSnapshot
	}
	security, e := stringField(stream, "security")
	if e != nil || security != "reality" {
		return nil, ErrSnapshot
	}
	reality, e := exactObject(stream["realitySettings"], "privateKey", "serverNames", "shortIds", "target", "dest", "show", "xver")
	if e != nil {
		return nil, e
	}
	// Version/time restrictions, FinalMask, ML-DSA and custom transports are not
	// silently ignored. This subset must be widened only after a core round-trip.
	if _, target := reality["target"]; target {
		if _, dest := reality["dest"]; dest {
			return nil, ErrSnapshot
		}
		if _, e = stringField(reality, "target"); e != nil {
			return nil, e
		}
	} else {
		if _, e = stringField(reality, "dest"); e != nil {
			return nil, e
		}
	}
	if raw, ok := reality["show"]; ok {
		var b bool
		if json.Unmarshal(raw, &b) != nil {
			return nil, ErrSnapshot
		}
	}
	if raw, ok := reality["xver"]; ok {
		var n int
		if json.Unmarshal(raw, &n) != nil || n != 0 {
			return nil, ErrSnapshot
		}
	}
	private, e := stringField(reality, "privateKey")
	if e != nil {
		return nil, e
	}
	key, e := base64.RawURLEncoding.Strict().DecodeString(private)
	defer clear(key)
	if e != nil || len(key) != 32 || bytes.Equal(key, make([]byte, 32)) {
		return nil, ErrSnapshot
	}
	pair, e := ecdh.X25519().NewPrivateKey(key)
	if e != nil {
		return nil, ErrSnapshot
	}
	names, e := stringList(reality, "serverNames")
	if e != nil {
		return nil, e
	}
	shorts, e := stringList(reality, "shortIds")
	if e != nil {
		return nil, e
	}
	for _, s := range shorts {
		if len(s) > 16 || len(s)%2 != 0 {
			return nil, ErrSnapshot
		}
		if _, e = hex.DecodeString(s); e != nil {
			return nil, ErrSnapshot
		}
	}
	var clients []json.RawMessage
	if json.Unmarshal(settings["clients"], &clients) != nil || len(clients) == 0 || len(clients) > 1024 {
		return nil, ErrSnapshot
	}
	seen := map[string]bool{}
	found := false
	flow := ""
	for _, raw := range clients {
		c, e := exactObject(raw, "id", "flow", "email", "level")
		if e != nil {
			return nil, e
		}
		id, e := stringField(c, "id")
		if e != nil {
			return nil, e
		}
		b, e := uuidBytes(id)
		if e != nil {
			return nil, e
		}
		exact := bytes.Equal(b, validated.credential[:16])
		b[6], b[7] = 0, 0
		normal := hex.EncodeToString(b)
		if seen[normal] {
			clear(b)
			return nil, ErrSnapshot
		}
		seen[normal] = true
		if exact {
			found = true
			flow, e = stringField(c, "flow")
			if e != nil {
				clear(b)
				return nil, e
			}
		}
		clear(b)
	}
	u, _ := url.Parse(strings.TrimSuffix(strings.TrimSuffix(string(client), "\n"), "\r"))
	q := u.Query()
	host, epPort, e := net.SplitHostPort(endpoint)
	if e != nil || host == "" {
		return nil, ErrSnapshot
	}
	n, e := strconv.Atoi(epPort)
	if e != nil || n < 1 || n > 65535 {
		return nil, ErrSnapshot
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		if ip.Zone() != "" {
			return nil, ErrSnapshot
		}
	} else if !hostname(host) {
		return nil, ErrSnapshot
	}
	mismatch := []string{}
	if !sameHost(host, u.Hostname()) || epPort != u.Port() {
		mismatch = append(mismatch, "endpoint")
	}
	if strconv.Itoa(port) != u.Port() {
		mismatch = append(mismatch, "port")
	}
	if listen != "" && listen != "0.0.0.0" && listen != "::" && !sameHost(listen, host) {
		mismatch = append(mismatch, "listen_mapping")
	}
	if !found {
		mismatch = append(mismatch, "credential")
	} else if flow != q.Get("flow") {
		mismatch = append(mismatch, "flow")
	}
	pub, _ := base64.RawURLEncoding.DecodeString(q.Get("pbk"))
	defer clear(pub)
	if !bytes.Equal(pub, pair.PublicKey().Bytes()) {
		mismatch = append(mismatch, "public_key")
	}
	nameMatch := false
	for _, s := range names {
		if s == q.Get("sni") {
			nameMatch = true
		}
	}
	if !nameMatch {
		mismatch = append(mismatch, "server_name")
	}
	shortMatch := false
	for _, s := range shorts {
		if strings.EqualFold(s, q.Get("sid")) {
			shortMatch = true
		}
	}
	if !shortMatch {
		mismatch = append(mismatch, "short_id")
	}
	return mismatch, nil
}
