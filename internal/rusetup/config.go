// Package rusetup prepares a closed RU primary topology. It never enables
// services, changes a network namespace or grants profile readiness.
package rusetup

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/coreinstall"
	"familyvpn.local/platform/internal/foreignsetup"
	"io"
	"net/netip"
	"strings"
	"unicode/utf8"
)

const (
	Namespace      = "vpn-data"
	StageDirectory = "/etc/family-vpn/ru-staging"
	HopInput       = "/etc/family-vpn/ru-import/ru-hop.json"
	MaxSize        = 64 << 10
)

var (
	ErrInput    = errors.New("invalid RU primary input")
	ErrConfig   = errors.New("RU primary configuration rejected")
	ErrStage    = errors.New("RU private stage unavailable or already exists")
	ErrPlatform = errors.New("RU primary staging requires Linux root")
	ErrNative   = errors.New("RU native syntax check unavailable or rejected")
)

type Inputs struct {
	Endpoint        string `json:"ru_endpoint"`
	ForeignEndpoint string `json:"foreign_endpoint"`
	RealityTarget   string `json:"reality_target"`
	ServerName      string `json:"server_name"`
}

func ValidateInputs(i Inputs) error {
	f, err := netip.ParseAddrPort(i.ForeignEndpoint)
	r, re := netip.ParseAddrPort(i.Endpoint)
	t, te := netip.ParseAddrPort(i.RealityTarget)
	if err != nil || re != nil || te != nil || !f.Addr().Is4() || !r.Addr().Is4() || !t.Addr().Is4() || f.Port() != 443 || f.String() != i.ForeignEndpoint || foreignsetup.ValidateInputs(foreignsetup.Inputs{Endpoint: i.Endpoint, RUSource: f.Addr().String(), RealityTarget: i.RealityTarget, ServerName: i.ServerName}) != nil {
		return ErrInput
	}
	return nil
}

type Summary struct {
	ConfigurationValidated  bool   `json:"configuration_validated"`
	ClientBindingConfigured bool   `json:"client_binding_configured"`
	NativeSyntaxValidated   bool   `json:"native_syntax_validated"`
	RuntimeInstalled        bool   `json:"runtime_installed"`
	KernelGuardVerified     bool   `json:"kernel_guard_verified"`
	RoutingVerified         bool   `json:"routing_verified"`
	DNSVerified             bool   `json:"dns_verified"`
	ClientVerified          bool   `json:"client_verified"`
	Ready                   bool   `json:"ready"`
	XrayVersion             string `json:"xray_version"`
	SingBoxVersion          string `json:"sing_box_version"`
}

func summary(valid bool) Summary {
	return Summary{ConfigurationValidated: valid, XrayVersion: coreinstall.XrayVersion, SingBoxVersion: coreinstall.SingBoxVersion}
}

// Binding is non-secret operator configuration, for independently matching the
// network guard plan. These values never attest the currently running network.
type Binding struct {
	RUIPv4, ForeignIPv4, RealityTargetIPv4 string
}

type plan struct {
	SchemaVersion  int    `json:"schema_version"`
	Kind           string `json:"kind"`
	Namespace      string `json:"namespace"`
	Inputs         Inputs `json:"inputs"`
	XrayVersion    string `json:"xray_version"`
	SingBoxVersion string `json:"sing_box_version"`
}

type Bundle struct{ Xray, SingBox, Hop, Plan []byte }

func (Bundle) String() string   { return "private RU primary staging bundle" }
func (Bundle) GoString() string { return "private RU primary staging bundle" }
func (Bundle) MarshalJSON() ([]byte, error) {
	return nil, errors.New("private RU bundle cannot be serialized as a report")
}
func (b *Bundle) Clear() {
	clear(b.Xray)
	clear(b.SingBox)
	clear(b.Hop)
	clear(b.Plan)
	b.Xray, b.SingBox, b.Hop, b.Plan = nil, nil, nil, nil
}

type realityLimit struct {
	AfterBytes    int `json:"afterBytes"`
	BytesPerSec   int `json:"bytesPerSec"`
	BurstBytesSec int `json:"burstBytesPerSec"`
}
type reality struct {
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
type xClient struct {
	ID   string `json:"id"`
	Flow string `json:"flow"`
}
type xSettings struct {
	Clients    []xClient `json:"clients"`
	Decryption string    `json:"decryption"`
}
type xStream struct {
	Network  string  `json:"network"`
	Security string  `json:"security"`
	Reality  reality `json:"realitySettings"`
}
type xInbound struct {
	Tag      string    `json:"tag"`
	Listen   string    `json:"listen"`
	Port     int       `json:"port"`
	Protocol string    `json:"protocol"`
	Settings xSettings `json:"settings"`
	Stream   xStream   `json:"streamSettings"`
}
type socksSettings struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}
type xOutbound struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings"`
}
type xRule struct {
	Type        string   `json:"type"`
	IP          []string `json:"ip,omitempty"`
	InboundTag  []string `json:"inboundTag,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}
type xConfig struct {
	Log struct {
		Level string `json:"loglevel"`
	} `json:"log"`
	Inbounds  []xInbound  `json:"inbounds"`
	Outbounds []xOutbound `json:"outbounds"`
	Routing   struct {
		DomainStrategy string  `json:"domainStrategy"`
		Rules          []xRule `json:"rules"`
	} `json:"routing"`
}
type singInbound struct {
	Type            string `json:"type"`
	Tag             string `json:"tag"`
	Listen          string `json:"listen"`
	ListenPort      int    `json:"listen_port"`
	Network         string `json:"network,omitempty"`
	OverrideAddress string `json:"override_address,omitempty"`
	OverridePort    int    `json:"override_port,omitempty"`
}
type singRule struct {
	IPVersion int      `json:"ip_version,omitempty"`
	IP        []string `json:"ip_cidr,omitempty"`
	Action    string   `json:"action"`
}
type singConfig struct {
	Log struct {
		Disabled bool `json:"disabled"`
	} `json:"log"`
	Inbounds  []singInbound     `json:"inbounds"`
	Outbounds []json.RawMessage `json:"outbounds"`
	Route     struct {
		Rules []singRule `json:"rules"`
		Final string     `json:"final"`
	} `json:"route"`
}

var denied = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "168.63.129.16/32", "::/0"}

func marshal(v any) ([]byte, error) {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return nil, ErrConfig
	}
	return append(b, '\n'), nil
}
func credential(key, short string) bool {
	s, se := hex.DecodeString(short)
	defer clear(s)
	k, ke := base64.RawURLEncoding.Strict().DecodeString(key)
	defer clear(k)
	return se == nil && len(short) == 16 && len(s) == 8 && short == strings.ToLower(short) && !bytes.Equal(s, make([]byte, 8)) && ke == nil && len(key) == 43 && len(k) == 32 && !bytes.Equal(k, make([]byte, 32))
}
func assemble(i Inputs, hop []byte, key, short string) (Bundle, error) {
	f, e := foreignsetup.ValidateRUHop(hop)
	if e != nil || ValidateInputs(i) != nil || !credential(key, short) {
		return Bundle{}, ErrConfig
	}
	fp, _ := netip.ParseAddrPort(i.ForeignEndpoint)
	if f != fp.Addr().String() {
		return Bundle{}, ErrConfig
	}
	rp, _ := netip.ParseAddrPort(i.Endpoint)
	tp, _ := netip.ParseAddrPort(i.RealityTarget)
	dest := append(append([]string{}, denied...), rp.Addr().String()+"/32", f+"/32")
	limit := realityLimit{4096, 1024, 2048}
	// No unowned client UUID is generated. A later trusted vault-bound operation
	// must supply exact validated client bytes before any peer can be admitted.
	x := xConfig{Inbounds: []xInbound{{"ru-primary", "0.0.0.0", 443, "vless", xSettings{[]xClient{}, "none"}, xStream{"tcp", "reality", reality{false, "127.0.0.1:10443", 0, []string{i.ServerName}, key, []string{short}, 60000, limit, limit}}}}, Outbounds: []xOutbound{{"blocked", "blackhole", json.RawMessage(`{}`)}, {"ru-hop", "socks", json.RawMessage(`{"address":"127.0.0.1","port":1080}`)}}}
	x.Log.Level = "none"
	x.Routing.DomainStrategy = "AsIs"
	x.Routing.Rules = []xRule{{Type: "field", IP: dest, OutboundTag: "blocked"}, {Type: "field", InboundTag: []string{"ru-primary"}, OutboundTag: "ru-hop"}}
	s := singConfig{Inbounds: []singInbound{{Type: "socks", Tag: "ru-hop", Listen: "127.0.0.1", ListenPort: 1080}, {Type: "direct", Tag: "ru-camouflage", Listen: "127.0.0.1", ListenPort: 10443, Network: "tcp", OverrideAddress: tp.Addr().String(), OverridePort: 443}}, Outbounds: []json.RawMessage{hop}}
	s.Log.Disabled = true
	s.Route.Final = "foreign-primary"
	s.Route.Rules = []singRule{{IPVersion: 6, Action: "reject"}, {IP: dest, Action: "reject"}}
	p := plan{1, "ru-primary-v1", Namespace, i, coreinstall.XrayVersion, coreinstall.SingBoxVersion}
	b := Bundle{Hop: bytes.Clone(hop)}
	if b.Xray, e = marshal(x); e == nil {
		b.SingBox, e = marshal(s)
	}
	if e == nil {
		b.Plan, e = marshal(p)
	}
	if e != nil {
		b.Clear()
		return Bundle{}, ErrConfig
	}
	return b, nil
}

func Generate(i Inputs, hop []byte) (Bundle, error) {
	if ValidateInputs(i) != nil {
		return Bundle{}, ErrInput
	}
	f, e := foreignsetup.ValidateRUHop(hop)
	fp, _ := netip.ParseAddrPort(i.ForeignEndpoint)
	if e != nil || f != fp.Addr().String() {
		return Bundle{}, ErrConfig
	}
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return Bundle{}, ErrConfig
	}
	k := key.Bytes()
	defer clear(k)
	var short [8]byte
	if _, e = rand.Read(short[:]); e != nil || bytes.Equal(short[:], make([]byte, 8)) {
		return Bundle{}, ErrConfig
	}
	return assemble(i, hop, base64.RawURLEncoding.EncodeToString(k), hex.EncodeToString(short[:]))
}

func unique(d *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrConfig
	}
	t, e := d.Token()
	if e != nil {
		return ErrConfig
	}
	v, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch v {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			s, ok := k.(string)
			lower := strings.ToLower(s)
			if e != nil || !ok || seen[lower] {
				return ErrConfig
			}
			seen[lower] = true
			if unique(d, depth+1) != nil {
				return ErrConfig
			}
		}
	case '[':
		for d.More() {
			if unique(d, depth+1) != nil {
				return ErrConfig
			}
		}
	default:
		return ErrConfig
	}
	end, e := d.Token()
	if e != nil || v == '{' && end != json.Delim('}') || v == '[' && end != json.Delim(']') {
		return ErrConfig
	}
	return nil
}
func decode(b []byte, v any) error {
	if len(b) == 0 || len(b) > MaxSize || !utf8.Valid(b) {
		return ErrConfig
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if unique(d, 0) != nil {
		return ErrConfig
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrConfig
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return ErrConfig
	}
	return nil
}

func ValidateBundle(b Bundle) (Summary, Binding, error) {
	fail := func() (Summary, Binding, error) { return summary(false), Binding{}, ErrConfig }
	var p plan
	var x xConfig
	if decode(b.Plan, &p) != nil || decode(b.Xray, &x) != nil || len(x.Inbounds) != 1 || x.Inbounds[0].Settings.Clients == nil || len(x.Inbounds[0].Settings.Clients) > 1 || len(x.Inbounds[0].Stream.Reality.ShortIDs) != 1 {
		return fail()
	}
	r := x.Inbounds[0].Stream.Reality
	expected, e := assemble(p.Inputs, b.Hop, r.PrivateKey, r.ShortIDs[0])
	if e != nil {
		return fail()
	}
	defer expected.Clear()
	configured := len(x.Inbounds[0].Settings.Clients) == 1
	if configured {
		client := x.Inbounds[0].Settings.Clients[0]
		if !validClientID(client.ID) || client.Flow != "xtls-rprx-vision" {
			return fail()
		}
		var candidate xConfig
		if decode(expected.Xray, &candidate) != nil {
			return fail()
		}
		candidate.Inbounds[0].Settings.Clients = []xClient{client}
		updated, e := marshal(candidate)
		if e != nil {
			return fail()
		}
		clear(expected.Xray)
		expected.Xray = updated
	}
	if !bytes.Equal(b.Xray, expected.Xray) || !bytes.Equal(b.SingBox, expected.SingBox) || !bytes.Equal(b.Plan, expected.Plan) {
		return fail()
	}
	ru, _ := netip.ParseAddrPort(p.Inputs.Endpoint)
	foreign, _ := netip.ParseAddrPort(p.Inputs.ForeignEndpoint)
	target, _ := netip.ParseAddrPort(p.Inputs.RealityTarget)
	out := summary(true)
	out.ClientBindingConfigured = configured
	return out, Binding{ru.Addr().String(), foreign.Addr().String(), target.Addr().String()}, nil
}
