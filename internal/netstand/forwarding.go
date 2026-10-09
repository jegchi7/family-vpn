package netstand

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"familyvpn.local/platform/internal/netguard"
	"familyvpn.local/platform/internal/runtimeenv"
)

// A forwarding baseline is current trusted process memory. It cannot be
// reconstructed from a manifest, journal, caller JSON or a prior observation.
// Linux 5.4/5.15 inet_forward_change changes all.accept_redirects,
// default.forwarding, every interface.forwarding and wanted/active LRO.
// The complete reviewed IPv4 devconf vector is observed as well: an unexpected
// additional change is a failed operation, not a reason to restore unknown data.
var forwardingConfKeys = []string{
	"accept_local", "accept_redirects", "accept_source_route", "arp_accept",
	"arp_announce", "arp_filter", "arp_ignore", "arp_notify", "bc_forwarding",
	"bootp_relay", "disable_policy", "disable_xfrm", "drop_gratuitous_arp",
	"drop_unicast_in_l2_multicast", "force_igmp_version", "forwarding",
	"igmpv2_unsolicited_report_interval", "igmpv3_unsolicited_report_interval",
	"ignore_routes_with_linkdown", "log_martians", "mc_forwarding", "medium_id",
	"promote_secondaries", "proxy_arp", "proxy_arp_pvlan", "route_localnet",
	"rp_filter", "secure_redirects", "send_redirects", "shared_media",
	"src_valid_mark", "tag",
}

type forwardingFeatures struct {
	names []string
	words [][4]uint32 // available, requested, active, never_changed
}

type forwardingObservation struct {
	scope    runtimeenv.Scope
	global   int32
	links    map[string]int
	conf     map[string]map[string]int32
	features map[string]forwardingFeatures
}

type forwardingPreservation struct {
	before forwardingObservation
	uplink string
	used   bool
	source forwardingPinnedSource
}

type forwardingPinnedSource interface {
	check() error
	write(context.Context, Target, forwardingWrite) error
	close()
}

func (p *forwardingPreservation) close() {
	if p == nil {
		return
	}
	if p.source != nil {
		p.source.close()
	}
	*p = forwardingPreservation{used: true}
}

func (p forwardingPreservation) MarshalJSON() ([]byte, error) { return nil, ErrForwarding }
func (p forwardingPreservation) String() string               { return "[private forwarding baseline]" }
func (p forwardingPreservation) GoString() string             { return p.String() }

func forwardingName(s string) bool {
	if len(s) < 1 || len(s) > 15 || s == "." || s == ".." || s == "all" || s == "default" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func forwardingNumber(data []byte) (int32, error) {
	if len(data) < 2 || len(data) > 12 || data[len(data)-1] != '\n' {
		return 0, ErrForwarding
	}
	s := string(data[:len(data)-1])
	v, e := strconv.ParseInt(s, 10, 32)
	if e != nil || strconv.FormatInt(v, 10) != s {
		return 0, ErrForwarding
	}
	return int32(v), nil
}

func validateForwardingConf(c map[string]int32) error {
	if len(c) != len(forwardingConfKeys) {
		return ErrForwarding
	}
	for _, key := range forwardingConfKeys {
		if _, exists := c[key]; !exists {
			return ErrForwarding
		}
	}
	for _, key := range []string{"forwarding", "accept_redirects"} {
		if c[key] != 0 && c[key] != 1 {
			return ErrForwarding
		}
	}
	return nil
}

func validateForwardingFeatures(f forwardingFeatures) error {
	if len(f.names) == 0 || len(f.names) > 256 || len(f.words) != (len(f.names)+31)/32 {
		return ErrForwarding
	}
	lro := -1
	seen := map[string]bool{}
	for n, name := range f.names {
		// Kernel feature tables contain unnamed reserved positions. An empty
		// position remains part of the exact vector, never an inferred feature.
		if name == "" {
			continue
		}
		if len(name) > 31 || seen[name] {
			return ErrForwarding
		}
		seen[name] = true
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return ErrForwarding
			}
		}
		if name == "rx-lro" {
			lro = n
		}
	}
	if lro < 0 || f.words[lro/32][1]&(1<<uint(lro%32)) != 0 || f.words[lro/32][2]&(1<<uint(lro%32)) != 0 {
		return ErrForwarding
	}
	for _, word := range f.words {
		// Even already-off LRO invokes netdev_update_features. A pending request
		// for another mutable feature could be reconciled by that call. Never
		// attempt the global transition on such a baseline.
		if (word[1]^word[2])&word[0] != 0 {
			return ErrForwarding
		}
	}
	if remainder := len(f.names) % 32; remainder != 0 {
		valid := uint32(1<<uint(remainder)) - 1
		for _, word := range f.words[len(f.words)-1] {
			if word & ^valid != 0 {
				return ErrForwarding
			}
		}
	}
	return nil
}

func validateForwardingObservation(o forwardingObservation, owned bool) error {
	if !o.scope.Valid() || (o.global != 0 && o.global != 1) || len(o.links) == 0 || len(o.links) > 256 || len(o.features) != len(o.links) || len(o.conf) != len(o.links)+2 || o.conf["all"]["forwarding"] != o.global {
		return ErrForwarding
	}
	indexes := map[int]bool{}
	for name, index := range o.links {
		if !forwardingName(name) || index < 1 || index > 1<<30 || indexes[index] || name == netguard.NamespaceVeth || name == netguard.HostVeth && !owned || validateForwardingFeatures(o.features[name]) != nil {
			return ErrForwarding
		}
		indexes[index] = true
	}
	for name, c := range o.conf {
		if name != "all" && name != "default" {
			if _, exists := o.links[name]; !exists {
				return ErrForwarding
			}
		}
		if validateForwardingConf(c) != nil {
			return ErrForwarding
		}
	}
	return nil
}

func cloneForwarding(o forwardingObservation) forwardingObservation {
	c := forwardingObservation{scope: o.scope, global: o.global, links: map[string]int{}, conf: map[string]map[string]int32{}, features: map[string]forwardingFeatures{}}
	for name, index := range o.links {
		c.links[name] = index
	}
	for name, values := range o.conf {
		c.conf[name] = map[string]int32{}
		for key, value := range values {
			c.conf[name][key] = value
		}
	}
	for name, values := range o.features {
		c.features[name] = forwardingFeatures{append([]string(nil), values.names...), append([][4]uint32(nil), values.words...)}
	}
	return c
}

func newForwardingPreservation(o forwardingObservation, uplink string) (*forwardingPreservation, error) {
	if validateForwardingObservation(o, false) != nil || o.global != 0 || !forwardingName(uplink) || o.links[uplink] == 0 {
		return nil, ErrForwarding
	}
	// IPv4 forwarding is evaluated per ingress interface in Linux. A global
	// zero alone cannot establish that unrelated forwarding was disabled.
	for name := range o.links {
		if name != "lo" && o.conf[name]["forwarding"] != 0 {
			return nil, ErrForwarding
		}
	}
	return &forwardingPreservation{before: cloneForwarding(o), uplink: uplink}, nil
}

// Fingerprints contain only expected non-secret behavior. Interface indexes
// are observed separately during the operation; the expected digest never
// creates an identity or permits restoring values after process restart.
func forwardingFingerprint(o forwardingObservation) string {
	type row struct {
		Name     string
		Values   map[string]int32
		Names    []string
		Features [][4]uint32
	}
	names := make([]string, 0, len(o.conf))
	for name := range o.conf {
		if name != netguard.HostVeth {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	rows := make([]row, 0, len(names))
	for _, name := range names {
		f := o.features[name]
		rows = append(rows, row{name, o.conf[name], f.names, f.words})
	}
	b, e := json.Marshal(struct {
		Scope  runtimeenv.Scope
		Global int32
		Rows   []row
	}{o.scope, o.global, rows})
	if e != nil {
		return ""
	}
	return hash(b)
}

func (p *forwardingPreservation) baselineHash() string {
	if p == nil || validateForwardingObservation(p.before, false) != nil {
		return ""
	}
	return forwardingFingerprint(p.before)
}

func (p *forwardingPreservation) expected() forwardingObservation {
	o := cloneForwarding(p.before)
	o.global = 1
	o.conf["all"]["forwarding"] = 1
	o.conf[p.uplink]["forwarding"] = 1
	return o
}

func (p *forwardingPreservation) expectedHash() string {
	if p.baselineHash() == "" {
		return ""
	}
	return forwardingFingerprint(p.expected())
}

func (p *forwardingPreservation) ownedBefore(o forwardingObservation) (forwardingObservation, error) {
	if validateForwardingObservation(o, true) != nil || len(o.links) != len(p.before.links)+1 || o.links[netguard.HostVeth] == 0 {
		return forwardingObservation{}, ErrForwarding
	}
	for name, index := range p.before.links {
		if o.links[name] != index {
			return forwardingObservation{}, ErrForwarding
		}
	}
	if forwardingFingerprint(o) != p.baselineHash() {
		return forwardingObservation{}, ErrForwarding
	}
	owned := o.conf[netguard.HostVeth]
	for _, key := range forwardingConfKeys {
		expected := p.before.conf["default"][key]
		switch key {
		case "forwarding", "rp_filter":
			expected = 1
		case "accept_redirects", "send_redirects", "route_localnet":
			expected = 0
		}
		if owned[key] != expected {
			return forwardingObservation{}, ErrForwarding
		}
	}
	return cloneForwarding(o), nil
}

type forwardingWrite struct {
	interfaceName string // empty means the closed global ip_forward file
	key           string
	value         int32
}

type forwardingBackend interface {
	Observe(context.Context) (forwardingObservation, error)
	Guard(context.Context) error
	Write(context.Context, forwardingWrite) error
}

func exactForwarding(o, expected forwardingObservation) bool {
	if validateForwardingObservation(o, true) != nil || o.scope != expected.scope || o.global != expected.global || len(o.links) != len(expected.links) || len(o.conf) != len(expected.conf) {
		return false
	}
	for name, index := range expected.links {
		if o.links[name] != index {
			return false
		}
	}
	// Unlike the restart fingerprint, the live comparison includes every owned
	// veth setting and its complete feature vector.
	a, _ := json.Marshal(o.conf)
	b, _ := json.Marshal(expected.conf)
	if string(a) != string(b) {
		return false
	}
	for name, f := range o.features {
		want := expected.features[name]
		if strings.Join(f.names, "\x00") != strings.Join(want.names, "\x00") || len(f.words) != len(want.words) {
			return false
		}
		for n, word := range f.words {
			if word != want.words[n] {
				return false
			}
		}
	}
	return true
}

// preserve consumes the in-memory baseline once. Every failed/cancelled write
// remains an incomplete journalled operation; no inverse ip_forward toggle or
// persisted-baseline replay occurs. The persistent host guard must already
// block unrelated forwarding before this function is called.
func (p *forwardingPreservation) preserve(ctx context.Context, b forwardingBackend) error {
	if p == nil || p.used || p.baselineHash() == "" || ctx.Err() != nil {
		return ErrForwarding
	}
	current, e := b.Observe(ctx)
	if e != nil {
		return ErrForwarding
	}
	expected, e := p.ownedBefore(current)
	if e != nil || b.Guard(ctx) != nil || ctx.Err() != nil {
		return ErrForwarding
	}
	p.used = true
	writes := []forwardingWrite{{key: "ip_forward", value: 1}, {interfaceName: "default", key: "forwarding", value: p.before.conf["default"]["forwarding"]}, {interfaceName: "all", key: "accept_redirects", value: p.before.conf["all"]["accept_redirects"]}}
	names := make([]string, 0, len(p.before.links))
	for name := range p.before.links {
		if name != p.uplink {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		writes = append(writes, forwardingWrite{interfaceName: name, key: "forwarding", value: p.before.conf[name]["forwarding"]})
	}
	for n, w := range writes {
		if ctx.Err() != nil || b.Guard(ctx) != nil || ctx.Err() != nil {
			return ErrForwarding
		}
		observed, e := b.Observe(ctx)
		if e != nil || !exactForwarding(observed, expected) {
			return ErrForwarding
		}
		if b.Write(ctx, w) != nil {
			return ErrForwarding
		}
		if n == 0 {
			expected.global = 1
			expected.conf["all"]["forwarding"] = 1
			expected.conf["all"]["accept_redirects"] = 0
			expected.conf["default"]["forwarding"] = 1
			for name := range expected.links {
				expected.conf[name]["forwarding"] = 1
			}
		} else {
			expected.conf[w.interfaceName][w.key] = w.value
		}
		observed, e = b.Observe(ctx)
		if e != nil || !exactForwarding(observed, expected) || ctx.Err() != nil {
			return ErrForwarding
		}
	}
	observed, e := b.Observe(ctx)
	if e != nil || forwardingFingerprint(observed) != p.expectedHash() || b.Guard(ctx) != nil || ctx.Err() != nil {
		return ErrForwarding
	}
	return nil
}
