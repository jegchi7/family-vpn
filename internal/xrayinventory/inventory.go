// Package xrayinventory checks independently pinned deployment expectations.
// Inventory is not an attestation of the responding core or configuration.
package xrayinventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/runtimeenv"
	"io"
	"net/netip"
	"strings"
	"unicode/utf8"
)

const MaxSize = 64 << 10
const MaxTargets = 16
const Path = "/etc/family-vpn/xray-inventory.json"

var ErrInventory = errors.New("Xray inventory unavailable or changed")

type Expected struct {
	Server, Tag, ToolSHA256 string
	Scope                   runtimeenv.Scope
}

func ValidPin(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func ValidTarget(server, tag, pin string) bool {
	a, e := netip.ParseAddrPort(server)
	if e != nil || a.Addr().Zone() != "" || a.Addr() != netip.MustParseAddr("127.0.0.1") && a.Addr() != netip.IPv6Loopback() || a.Port() == 0 || a.String() != server {
		return false
	}
	if len(tag) == 0 || len(tag) > 64 || tag[0] == '-' || !ValidPin(pin) {
		return false
	}
	for _, c := range tag {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-", c)) {
			return false
		}
	}
	return true
}

func (e Expected) Valid() bool { return ValidTarget(e.Server, e.Tag, e.ToolSHA256) && e.Scope.Valid() }

type entry struct {
	server, tag, tool, toolVersion, core, coreVersion, config string
}
type inventory struct {
	scope   runtimeenv.Scope
	kernel  string
	targets []entry
	digest  [32]byte
}

// Objects are closed and case sensitive; duplicates are rejected before maps.
func unique(d *json.Decoder, depth int) error {
	if depth > 8 {
		return ErrInventory
	}
	t, e := d.Token()
	if e != nil {
		return ErrInventory
	}
	delim, compound := t.(json.Delim)
	if !compound {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return ErrInventory
			}
			s, ok := key.(string)
			if !ok || seen[strings.ToLower(s)] {
				return ErrInventory
			}
			seen[strings.ToLower(s)] = true
			if e := unique(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e := unique(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return ErrInventory
	}
	end, e := d.Token()
	if e != nil || delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
		return ErrInventory
	}
	return nil
}
func object(data []byte, fields ...string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if json.Unmarshal(data, &m) != nil || len(m) != len(fields) {
		return nil, ErrInventory
	}
	for _, key := range fields {
		if len(m[key]) == 0 || bytes.Equal(bytes.TrimSpace(m[key]), []byte("null")) {
			return nil, ErrInventory
		}
	}
	return m, nil
}
func stringField(data []byte) (string, error) {
	var s string
	if json.Unmarshal(data, &s) != nil || s == "" {
		return "", ErrInventory
	}
	return s, nil
}
func version(s string) bool {
	if len(s) < 1 || len(s) > 64 || !(s[0] >= '0' && s[0] <= '9' || s[0] >= 'A' && s[0] <= 'Z' || s[0] >= 'a' && s[0] <= 'z') {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || strings.ContainsRune("._+-", c)) {
			return false
		}
	}
	return true
}
func parse(data []byte) (inventory, error) {
	if len(data) == 0 || len(data) > MaxSize || !utf8.Valid(data) {
		return inventory{}, ErrInventory
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if unique(d, 0) != nil {
		return inventory{}, ErrInventory
	}
	if _, e := d.Token(); !errors.Is(e, io.EOF) {
		return inventory{}, ErrInventory
	}
	m, e := object(data, "schema_version", "boot_id", "netns_device", "netns_inode", "kernel_release", "xray")
	if e != nil || !bytes.Equal(bytes.TrimSpace(m["schema_version"]), []byte("1")) {
		return inventory{}, ErrInventory
	}
	var i inventory
	if i.scope.BootID, e = stringField(m["boot_id"]); e != nil {
		return inventory{}, ErrInventory
	}
	if json.Unmarshal(m["netns_device"], &i.scope.NetNSDevice) != nil || json.Unmarshal(m["netns_inode"], &i.scope.NetNSInode) != nil || !i.scope.Valid() {
		return inventory{}, ErrInventory
	}
	if i.kernel, e = stringField(m["kernel_release"]); e != nil || !version(i.kernel) {
		return inventory{}, ErrInventory
	}
	var targets []json.RawMessage
	if json.Unmarshal(m["xray"], &targets) != nil || len(targets) < 1 || len(targets) > MaxTargets {
		return inventory{}, ErrInventory
	}
	seen := map[string]bool{}
	servers := map[string]entry{}
	for _, raw := range targets {
		m, e := object(raw, "api_server", "inbound_tag", "tool_sha256", "tool_version", "core_sha256", "core_version", "config_sha256")
		if e != nil {
			return inventory{}, e
		}
		var v entry
		for name, dest := range map[string]*string{"api_server": &v.server, "inbound_tag": &v.tag, "tool_sha256": &v.tool, "tool_version": &v.toolVersion, "core_sha256": &v.core, "core_version": &v.coreVersion, "config_sha256": &v.config} {
			if *dest, e = stringField(m[name]); e != nil {
				return inventory{}, e
			}
		}
		key := v.server + "/" + v.tag
		if !ValidTarget(v.server, v.tag, v.tool) || !ValidPin(v.core) || !ValidPin(v.config) || !version(v.toolVersion) || !version(v.coreVersion) || seen[key] {
			return inventory{}, ErrInventory
		}
		if old, exists := servers[v.server]; exists && (old.tool != v.tool || old.toolVersion != v.toolVersion || old.core != v.core || old.coreVersion != v.coreVersion || old.config != v.config) {
			return inventory{}, ErrInventory
		}
		seen[key] = true
		servers[v.server] = v
		i.targets = append(i.targets, v)
	}
	i.digest = sha256.Sum256(data)
	return i, nil
}
func (i inventory) check(pin string, expected Expected) error {
	if !ValidPin(pin) || !expected.Valid() || i.scope != expected.Scope || hex.EncodeToString(i.digest[:]) != pin {
		return ErrInventory
	}
	for _, v := range i.targets {
		if v.server == expected.Server && v.tag == expected.Tag && v.tool == expected.ToolSHA256 {
			return nil
		}
	}
	return ErrInventory
}
