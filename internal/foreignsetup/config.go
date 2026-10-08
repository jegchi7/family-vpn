// Package foreignsetup prepares a private, constrained Foreign primary hop.
// Its configuration validation is never runtime, client or kernel evidence.
package foreignsetup

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/coreinstall"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"unicode/utf8"
)

const XrayVersion = coreinstall.XrayVersion
const SingBoxVersion = coreinstall.SingBoxVersion
const MaxSize = 64 << 10
const StageDirectory = "/etc/family-vpn/foreign-staging"

var ErrInput = errors.New("invalid Foreign preparation input")
var ErrConfig = errors.New("Foreign staged configuration rejected")
var ErrStage = errors.New("Foreign private stage unavailable or already exists")
var ErrPlatform = errors.New("Foreign private staging requires Linux root")
var ErrNative = errors.New("Foreign native syntax check unavailable or rejected")

// Inputs contains only operator-selected, non-secret deployment parameters.
// It does not take arbitrary config, executable, output path or credentials.
type Inputs struct {
	Endpoint      string
	RUSource      string
	RealityTarget string
	ServerName    string
}

// Bundle is sensitive trusted-CLI memory. Never serialize it into a report,
// portal DB, audit, fixture, log or user profile. Clear releases the byte slices.
type Bundle struct {
	Xray  []byte
	RUHop []byte
}

func (Bundle) String() string   { return "private Foreign staging bundle" }
func (Bundle) GoString() string { return "private Foreign staging bundle" }
func (Bundle) MarshalJSON() ([]byte, error) {
	return nil, errors.New("private Foreign bundle cannot be serialized as a report")
}

func (b *Bundle) Clear() {
	clear(b.Xray)
	clear(b.RUHop)
	b.Xray, b.RUHop = nil, nil
}

// Summary deliberately contains neither endpoint nor credentials/config hash.
type Summary struct {
	ConfigurationValidated bool   `json:"configuration_validated"`
	NativeSyntaxValidated  bool   `json:"native_syntax_validated"`
	RuntimeInstalled       bool   `json:"runtime_installed"`
	KernelGuardVerified    bool   `json:"kernel_guard_verified"`
	RoutingVerified        bool   `json:"routing_verified"`
	DNSVerified            bool   `json:"dns_verified"`
	ClientVerified         bool   `json:"client_verified"`
	Ready                  bool   `json:"ready"`
	BackupConfigured       bool   `json:"backup_configured"`
	XrayVersion            string `json:"xray_version"`
	RUHopCoreVersion       string `json:"ru_hop_core_version"`
}

func safeSummary(valid bool) Summary {
	return Summary{ConfigurationValidated: valid, XrayVersion: XrayVersion, RUHopCoreVersion: SingBoxVersion}
}

// Include private, special-use, documentation, metadata and transition ranges.
// This application policy does not replace an actual-destination kernel guard.
var denied = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "168.63.129.16/32",
	"::/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
	"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7",
	"fe80::/10", "fec0::/10", "ff00::/8",
}

func publicIP(s string) (netip.Addr, bool) {
	a, e := netip.ParseAddr(s)
	if e != nil || a.Zone() != "" || a.Is4In6() || a.String() != s || !a.IsGlobalUnicast() {
		return netip.Addr{}, false
	}
	// Public IPv6 preparation is deliberately limited to current global space.
	if a.Is6() && !netip.MustParsePrefix("2000::/3").Contains(a) {
		return netip.Addr{}, false
	}
	for _, p := range denied {
		if netip.MustParsePrefix(p).Contains(a) {
			return netip.Addr{}, false
		}
	}
	return a, true
}

func endpoint(s string) (netip.Addr, bool) {
	a, e := netip.ParseAddrPort(s)
	if e != nil || a.Port() != 443 || a.String() != s {
		return netip.Addr{}, false
	}
	return publicIP(a.Addr().String())
}

func serverName(s string) bool {
	if len(s) < 3 || len(s) > 253 || strings.ToLower(s) != s || !strings.Contains(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	if _, e := netip.ParseAddr(s); e == nil {
		return false
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".invalid", ".test", ".example", ".home.arpa"} {
		if strings.HasSuffix(s, suffix) {
			return false
		}
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// ValidateInputs performs no entropy generation, filesystem or network calls.
func ValidateInputs(i Inputs) error {
	f, ok := endpoint(i.Endpoint)
	r, rok := publicIP(i.RUSource)
	t, tok := endpoint(i.RealityTarget)
	if !ok || !rok || !tok || f.Is4() != r.Is4() || f == r || f == t || r == t || !serverName(i.ServerName) {
		return ErrInput
	}
	return nil
}

type xrayLog struct {
	Level string `json:"loglevel"`
}
type xrayDNS struct {
	Servers       []string `json:"servers"`
	QueryStrategy string   `json:"queryStrategy"`
	Tag           string   `json:"tag"`
}
type xrayClient struct {
	ID   string `json:"id"`
	Flow string `json:"flow"`
}
type xrayInboundSettings struct {
	Clients    []xrayClient `json:"clients"`
	Decryption string       `json:"decryption"`
}
type realityLimit struct {
	AfterBytes    int `json:"afterBytes"`
	BytesPerSec   int `json:"bytesPerSec"`
	BurstBytesSec int `json:"burstBytesPerSec"`
}
type xrayReality struct {
	Show                  bool         `json:"show"`
	Target                string       `json:"target"`
	Xver                  int          `json:"xver"`
	ServerNames           []string     `json:"serverNames"`
	PrivateKey            string       `json:"privateKey"`
	ShortIDs              []string     `json:"shortIds"`
	MaxTimeDiff           int          `json:"maxTimeDiff"`
	LimitFallbackUpload   realityLimit `json:"limitFallbackUpload"`
	LimitFallbackDownload realityLimit `json:"limitFallbackDownload"`
}
type xrayStream struct {
	Network  string      `json:"network"`
	Security string      `json:"security"`
	Reality  xrayReality `json:"realitySettings"`
}
type xrayInbound struct {
	Tag      string              `json:"tag"`
	Listen   string              `json:"listen"`
	Port     int                 `json:"port"`
	Protocol string              `json:"protocol"`
	Settings xrayInboundSettings `json:"settings"`
	Stream   xrayStream          `json:"streamSettings"`
}
type xrayOutboundSettings struct {
	DomainStrategy string `json:"domainStrategy,omitempty"`
}
type xrayOutbound struct {
	Tag      string               `json:"tag"`
	Protocol string               `json:"protocol"`
	Settings xrayOutboundSettings `json:"settings"`
}
type xrayRule struct {
	Type        string   `json:"type"`
	IP          []string `json:"ip,omitempty"`
	Source      []string `json:"source,omitempty"`
	InboundTag  []string `json:"inboundTag,omitempty"`
	Port        string   `json:"port,omitempty"`
	Network     string   `json:"network,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}
type xrayRouting struct {
	DomainStrategy string     `json:"domainStrategy"`
	Rules          []xrayRule `json:"rules"`
}
type xrayConfig struct {
	Log       xrayLog        `json:"log"`
	DNS       xrayDNS        `json:"dns"`
	Inbounds  []xrayInbound  `json:"inbounds"`
	Outbounds []xrayOutbound `json:"outbounds"`
	Routing   xrayRouting    `json:"routing"`
}
type singUTLS struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint"`
}
type singReality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
}
type singTLS struct {
	Enabled    bool        `json:"enabled"`
	ServerName string      `json:"server_name"`
	Insecure   bool        `json:"insecure"`
	UTLS       singUTLS    `json:"utls"`
	Reality    singReality `json:"reality"`
}

// ruHop is only an outbound fragment. It cannot configure RU listeners,
// namespace, DNS, routing, firewall, selector or a DIRECT fallback.
type ruHop struct {
	Type           string  `json:"type"`
	Tag            string  `json:"tag"`
	Server         string  `json:"server"`
	ServerPort     int     `json:"server_port"`
	UUID           string  `json:"uuid"`
	Flow           string  `json:"flow"`
	PacketEncoding string  `json:"packet_encoding"`
	TLS            singTLS `json:"tls"`
}

func oneIP(a netip.Addr) string {
	return netip.PrefixFrom(a, a.BitLen()).String()
}
func marshal(v any) ([]byte, error) {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return nil, ErrConfig
	}
	return append(b, '\n'), nil
}
func assemble(i Inputs, id, privateKey, shortID string) (Bundle, error) {
	if ValidateInputs(i) != nil || !validUUID(id) || !validShortID(shortID) {
		return Bundle{}, ErrConfig
	}
	k, e := base64.RawURLEncoding.Strict().DecodeString(privateKey)
	defer clear(k)
	if e != nil || len(k) != 32 || len(privateKey) != 43 || bytes.Equal(k, make([]byte, 32)) {
		return Bundle{}, ErrConfig
	}
	key, e := ecdh.X25519().NewPrivateKey(k)
	if e != nil {
		return Bundle{}, ErrConfig
	}
	f, _ := endpoint(i.Endpoint)
	r, _ := publicIP(i.RUSource)
	destinations := append(append([]string{}, denied...), oneIP(r), oneIP(f))
	limit := realityLimit{AfterBytes: 4096, BytesPerSec: 1024, BurstBytesSec: 2048}
	listen := "0.0.0.0"
	if f.Is6() {
		listen = "::"
	}
	x := xrayConfig{
		Log:       xrayLog{"none"},
		DNS:       xrayDNS{[]string{"1.1.1.1", "9.9.9.9"}, "UseIP", "foreign-dns"},
		Inbounds:  []xrayInbound{{Tag: "foreign-primary", Listen: listen, Port: 443, Protocol: "vless", Settings: xrayInboundSettings{[]xrayClient{{id, "xtls-rprx-vision"}}, "none"}, Stream: xrayStream{"tcp", "reality", xrayReality{false, i.RealityTarget, 0, []string{i.ServerName}, privateKey, []string{shortID}, 60000, limit, limit}}}},
		Outbounds: []xrayOutbound{{"blocked", "blackhole", xrayOutboundSettings{}}, {"foreign-egress", "freedom", xrayOutboundSettings{"ForceIP"}}},
		Routing: xrayRouting{"IPOnDemand", []xrayRule{
			{Type: "field", IP: destinations, OutboundTag: "blocked"},
			{Type: "field", Source: []string{oneIP(r)}, InboundTag: []string{"foreign-primary"}, OutboundTag: "foreign-egress"},
			{Type: "field", IP: []string{"1.1.1.1/32", "9.9.9.9/32"}, InboundTag: []string{"foreign-dns"}, Port: "53", Network: "udp,tcp", OutboundTag: "foreign-egress"},
		}},
	}
	h := ruHop{"vless", "foreign-primary", f.String(), 443, id, "xtls-rprx-vision", "xudp", singTLS{true, i.ServerName, false, singUTLS{true, "chrome"}, singReality{true, base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), shortID}}}
	b := Bundle{}
	b.Xray, e = marshal(x)
	if e == nil {
		b.RUHop, e = marshal(h)
	}
	if e != nil {
		b.Clear()
		return Bundle{}, ErrConfig
	}
	return b, nil
}

func validUUID(s string) bool {
	if len(s) != 36 || s != strings.ToLower(s) || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	b, e := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return e == nil && len(b) == 16 && b[6]>>4 == 4 && b[8]>>6 == 2
}
func validShortID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 8 && len(s) == 16 && strings.ToLower(s) == s && !bytes.Equal(b, make([]byte, 8))
}

func Generate(i Inputs) (Bundle, error) {
	if e := ValidateInputs(i); e != nil {
		return Bundle{}, e
	}
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return Bundle{}, ErrConfig
	}
	k := key.Bytes()
	defer clear(k)
	var id [16]byte
	var short [8]byte
	if _, e = rand.Read(id[:]); e != nil {
		return Bundle{}, ErrConfig
	}
	if _, e = rand.Read(short[:]); e != nil || bytes.Equal(short[:], make([]byte, 8)) {
		return Bundle{}, ErrConfig
	}
	id[6], id[8] = id[6]&15|64, id[8]&63|128
	h := hex.EncodeToString(id[:])
	uuid := fmt.Sprintf("%s-%s-%s-%s-%s", h[:8], h[8:12], h[12:16], h[16:20], h[20:])
	return assemble(i, uuid, base64.RawURLEncoding.EncodeToString(k), hex.EncodeToString(short[:]))
}

// Reject duplicate and case-alias keys before typed decoding. Depth is bounded
// independently of encoding/json; a generated config needs fewer than 12 levels.
func unique(d *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrConfig
	}
	t, e := d.Token()
	if e != nil {
		return ErrConfig
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
			name, ok := k.(string)
			lower := strings.ToLower(name)
			if e != nil || !ok || seen[lower] {
				return ErrConfig
			}
			seen[lower] = true
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
		return ErrConfig
	}
	end, e := d.Token()
	if e != nil || delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
		return ErrConfig
	}
	return nil
}

func decode(data []byte, v any) error {
	if len(data) == 0 || len(data) > MaxSize || !utf8.Valid(data) {
		return ErrConfig
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if unique(d, 0) != nil {
		return ErrConfig
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrConfig
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return ErrConfig
	}
	return nil
}

// ValidatePair accepts only exact generated bytes with matching secrets and a
// closed primary policy. It performs no network, DB or execution operations.
func ValidatePair(xray, hop []byte) (Summary, error) {
	fail := func() (Summary, error) { return safeSummary(false), ErrConfig }
	var x xrayConfig
	var h ruHop
	if decode(xray, &x) != nil || decode(hop, &h) != nil || len(x.Inbounds) != 1 || len(x.Inbounds[0].Settings.Clients) != 1 || len(x.Inbounds[0].Stream.Reality.ServerNames) != 1 || len(x.Inbounds[0].Stream.Reality.ShortIDs) != 1 || len(x.Routing.Rules) != 3 || len(x.Routing.Rules[1].Source) != 1 {
		return fail()
	}
	r, e := netip.ParsePrefix(x.Routing.Rules[1].Source[0])
	if e != nil || r.Bits() != r.Addr().BitLen() {
		return fail()
	}
	f, e := netip.ParseAddr(h.Server)
	if e != nil || h.ServerPort != 443 {
		return fail()
	}
	reality := x.Inbounds[0].Stream.Reality
	i := Inputs{netip.AddrPortFrom(f, 443).String(), r.Addr().String(), reality.Target, reality.ServerNames[0]}
	generated, e := assemble(i, x.Inbounds[0].Settings.Clients[0].ID, reality.PrivateKey, reality.ShortIDs[0])
	if e != nil {
		return fail()
	}
	defer generated.Clear()
	if !bytes.Equal(generated.Xray, xray) || !bytes.Equal(generated.RUHop, hop) {
		return fail()
	}
	return safeSummary(true), nil
}

// ValidateRUHop accepts only the canonical, closed primary outbound fragment
// produced by this package. It returns the non-secret public endpoint address,
// never a client credential or a claim about its installation/reachability.
// A receiver still requires a protected operator-transferred input file.
func ValidateRUHop(raw []byte) (string, error) {
	var h ruHop
	if decode(raw, &h) != nil {
		return "", ErrConfig
	}
	addr, ok := publicIP(h.Server)
	if !ok || h.Type != "vless" || h.Tag != "foreign-primary" || h.ServerPort != 443 || !validUUID(h.UUID) || h.Flow != "xtls-rprx-vision" || h.PacketEncoding != "xudp" || !h.TLS.Enabled || h.TLS.Insecure || !h.TLS.UTLS.Enabled || h.TLS.UTLS.Fingerprint != "chrome" || !h.TLS.Reality.Enabled || !validShortID(h.TLS.Reality.ShortID) || !serverName(h.TLS.ServerName) {
		return "", ErrConfig
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(h.TLS.Reality.PublicKey)
	defer clear(key)
	if err != nil || len(key) != 32 || len(h.TLS.Reality.PublicKey) != 43 || bytes.Equal(key, make([]byte, 32)) {
		return "", ErrConfig
	}
	canonical, err := marshal(h)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, raw) {
		return "", ErrConfig
	}
	return addr.String(), nil
}
