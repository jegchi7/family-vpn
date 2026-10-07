// Package clientconfig validates deliberately small, client-only export subsets.
package clientconfig

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/profilevault"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const VLESSRealityURI = "vless-reality-uri"

var ErrUnsupported = errors.New("unsupported client export format")
var ErrInvalid = errors.New("invalid or unsupported client export contents")
var ErrSource = errors.New("client export source unavailable, oversized or not private")

type Validated struct {
	Protocol, Format string
	credential       [32]byte
}

func (v Validated) GoString() string { return v.String() }
func (v Validated) String() string   { return "validated client export (" + v.Format + ")" }
func (v Validated) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Protocol string `json:"protocol"`
		Format   string `json:"format"`
	}{v.Protocol, v.Format})
}
func SameCredential(a, b Validated) bool {
	if a.Format != b.Format {
		return false
	}
	if a.Format == VLESSRealityURI {
		// Pinned Xray VLESS validator ignores UUID bytes 6/7 on the wire.
		// Preserve exact export bytes, but conservatively reserve all aliases.
		a.credential[6], a.credential[7] = 0, 0
		b.credential[6], b.credential[7] = 0, 0
	}
	return a.credential == b.credential
}
func textValue(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			return false
		}
	}
	return true
}
func hostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	s = strings.TrimSuffix(s, ".")
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Validate never fetches an endpoint, starts a VPN core, or echoes rejected input.
// Original bytes are retained by the caller; no URI reserialization occurs.
func Validate(format string, data []byte) (Validated, error) {
	if format == AWG31Conf {
		return validateAWG31(data)
	}
	empty := Validated{}
	if format != VLESSRealityURI {
		return empty, ErrUnsupported
	}
	if len(data) == 0 || len(data) > profilevault.MaxSize {
		return empty, ErrInvalid
	}
	line := data
	if bytes.HasSuffix(line, []byte("\r\n")) {
		line = line[:len(line)-2]
	} else if bytes.HasSuffix(line, []byte("\n")) {
		line = line[:len(line)-1]
	}
	for _, b := range line {
		if b < 33 || b > 126 {
			return empty, ErrInvalid
		}
	}
	if !bytes.HasPrefix(line, []byte("vless://")) {
		return empty, ErrInvalid
	}
	u, e := url.Parse(string(line))
	if e != nil || u.Scheme != "vless" || u.Opaque != "" || u.User == nil || u.Path != "" || u.RawPath != "" {
		return empty, ErrInvalid
	}
	if _, password := u.User.Password(); password {
		return empty, ErrInvalid
	}
	id := u.User.Username()
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' || u.User.String() != id {
		return empty, ErrInvalid
	}
	identity, e := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if e != nil || len(identity) != 16 || bytes.Equal(identity, make([]byte, 16)) {
		return empty, ErrInvalid
	}
	defer clear(identity)
	host, port, e := net.SplitHostPort(u.Host)
	if e != nil || port == "" || len(port) > 5 {
		return empty, ErrInvalid
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return empty, ErrInvalid
		}
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return empty, ErrInvalid
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		if ip.Zone() != "" || (strings.HasPrefix(u.Host, "[") && !ip.Is6()) {
			return empty, ErrInvalid
		}
	} else if strings.HasPrefix(u.Host, "[") || !hostname(host) {
		return empty, ErrInvalid
	}
	allowed := map[string]bool{"type": true, "security": true, "encryption": true, "flow": true, "fp": true, "pbk": true, "sni": true, "sid": true, "spx": true, "headerType": true}
	values := map[string]string{}
	for _, field := range strings.Split(u.RawQuery, "&") {
		key, value, ok := strings.Cut(field, "=")
		if !ok || !allowed[key] {
			return empty, ErrInvalid
		}
		if _, duplicate := values[key]; duplicate || strings.Contains(value, "+") {
			return empty, ErrInvalid
		}
		decoded, e := url.QueryUnescape(value)
		if e != nil || !textValue(decoded) {
			return empty, ErrInvalid
		}
		values[key] = decoded
	}
	if values["type"] != "tcp" || values["security"] != "reality" || values["flow"] != "xtls-rprx-vision" || values["fp"] != "chrome" || !hostname(values["sni"]) {
		return empty, ErrInvalid
	}
	if _, e := netip.ParseAddr(values["sni"]); e == nil {
		return empty, ErrInvalid
	}
	if encryption, present := values["encryption"]; present && encryption != "none" {
		return empty, ErrInvalid
	}
	if header, present := values["headerType"]; present && header != "none" {
		return empty, ErrInvalid
	}
	pbk, e := base64.RawURLEncoding.Strict().DecodeString(values["pbk"])
	defer clear(pbk)
	if e != nil || len(pbk) != 32 || bytes.Equal(pbk, make([]byte, 32)) {
		return empty, ErrInvalid
	}
	sid, present := values["sid"]
	if !present || len(sid) > 16 || len(sid)%2 != 0 {
		return empty, ErrInvalid
	}
	if _, e = hex.DecodeString(sid); e != nil {
		return empty, ErrInvalid
	}
	if spx, present := values["spx"]; present && spx != "" {
		if len(spx) > 1024 || !strings.HasPrefix(spx, "/") || strings.HasPrefix(spx, "//") {
			return empty, ErrInvalid
		}
		if _, e = url.ParseRequestURI(spx); e != nil {
			return empty, ErrInvalid
		}
	}
	if !textValue(u.Fragment) || utf8.RuneCountInString(u.Fragment) > 128 {
		return empty, ErrInvalid
	}
	for _, c := range u.Fragment {
		if !(unicode.IsLetter(c) || unicode.IsNumber(c) || strings.ContainsRune(" ._()-", c)) {
			return empty, ErrInvalid
		}
	}
	result := Validated{Protocol: "reality", Format: VLESSRealityURI}
	copy(result.credential[:], identity)
	return result, nil
}

// ErrorCode is intentionally independent of input contents and parser library errors.
func ErrorCode(e error) string {
	if errors.Is(e, ErrUnsupported) {
		return "UNSUPPORTED_FORMAT"
	}
	if errors.Is(e, ErrSource) {
		return "INPUT_SOURCE"
	}
	if errors.Is(e, ErrInvalid) {
		return "INVALID_EXPORT"
	}
	return "IMPORT_FAILED"
}

var _ fmt.Stringer = Validated{}
