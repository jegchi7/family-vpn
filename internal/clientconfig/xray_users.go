package clientconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

var ErrXrayUsers = errors.New("invalid or unsupported Xray users readback")

// XrayUsers is a bounded partial comparison, never full runtime readiness.
// The private digest covers the normalized readback; no UUID/email escapes.
type XrayUsers struct {
	digest  [32]byte
	parsed  bool
	summary XrayUsersSummary
}
type XrayUsersSummary struct {
	UserObserved     bool     `json:"user_observed"`
	UserMatches      bool     `json:"user_matches"`
	MismatchedFields []string `json:"mismatched_fields"`
}

func (r XrayUsers) Summary() XrayUsersSummary {
	s := r.summary
	s.MismatchedFields = append([]string{}, s.MismatchedFields...)
	return s
}
func (r XrayUsers) MarshalJSON() ([]byte, error) { return json.Marshal(r.Summary()) }
func (r XrayUsers) String() string               { return "partial Xray users comparison" }
func (r XrayUsers) GoString() string             { return r.String() }
func SameXrayUsers(a, b XrayUsers) bool          { return a.parsed && b.parsed && a.digest == b.digest }

type xrayUser struct {
	ID, Flow, Email, Encryption string
	Level                       uint32
}

// CheckXrayUsers accepts the pinned CLI's expanded TypedMessage JSON, not a
// server config or arbitrary account types. Absence is unobserved: upstream
// enumeration omits unnamed users. UUID aliases are conflicts, not exact match.
func CheckXrayUsers(client, response []byte) (XrayUsers, error) {
	empty := XrayUsers{}
	v, e := Validate(VLESSRealityURI, client)
	if e != nil {
		return empty, e
	}
	if len(response) == 0 || len(response) > 64<<10 || !utf8.Valid(response) {
		return empty, ErrXrayUsers
	}
	d := json.NewDecoder(bytes.NewReader(response))
	d.UseNumber()
	if uniqueJSON(d, 0) != nil {
		return empty, ErrXrayUsers
	}
	if _, e = d.Token(); !errors.Is(e, io.EOF) {
		return empty, ErrXrayUsers
	}
	root, e := exactObject(response, "users")
	if e != nil {
		return empty, ErrXrayUsers
	}
	var users []json.RawMessage
	if json.Unmarshal(root["users"], &users) != nil || users == nil || len(users) > 256 {
		return empty, ErrXrayUsers
	}
	seen := map[string]bool{}
	normalized := []xrayUser{}
	s := XrayUsersSummary{MismatchedFields: []string{}}
	for _, raw := range users {
		u, e := exactObject(raw, "email", "level", "account")
		if e != nil {
			return empty, ErrXrayUsers
		}
		n := xrayUser{}
		if _, ok := u["email"]; ok {
			n.Email, e = stringField(u, "email")
			if e != nil || len(n.Email) > 256 {
				return empty, ErrXrayUsers
			}
		}
		if raw, ok := u["level"]; ok {
			if bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &n.Level) != nil {
				return empty, ErrXrayUsers
			}
		}
		a, e := exactObject(u["account"], "_TypedMessage_", "id", "flow", "encryption")
		if e != nil {
			return empty, ErrXrayUsers
		}
		typ, e := stringField(a, "_TypedMessage_")
		if e != nil || typ != "xray.proxy.vless.Account" {
			return empty, ErrXrayUsers
		}
		id, e := stringField(a, "id")
		if e != nil {
			return empty, ErrXrayUsers
		}
		identity, e := uuidBytes(id)
		if e != nil {
			return empty, ErrXrayUsers
		}
		exact := bytes.Equal(identity, v.credential[:16])
		n.ID = hex.EncodeToString(identity)
		identity[6], identity[7] = 0, 0
		wireID := hex.EncodeToString(identity)
		clear(identity)
		if seen[wireID] {
			return empty, ErrXrayUsers
		}
		seen[wireID] = true
		if _, ok := a["flow"]; ok {
			n.Flow, e = stringField(a, "flow")
			if e != nil || len(n.Flow) > 64 {
				return empty, ErrXrayUsers
			}
		}
		if _, ok := a["encryption"]; ok {
			n.Encryption, e = stringField(a, "encryption")
			if e != nil || n.Encryption != "" && n.Encryption != "none" {
				return empty, ErrXrayUsers
			}
		}
		normalized = append(normalized, n)
		alias := v.credential
		alias[6], alias[7] = 0, 0
		if exact {
			s.UserObserved = true
			if n.Flow != "xtls-rprx-vision" {
				s.MismatchedFields = append(s.MismatchedFields, "flow")
			}
		} else if strings.EqualFold(wireID, hex.EncodeToString(alias[:16])) {
			s.MismatchedFields = append(s.MismatchedFields, "credential_alias")
		}
	}
	if !s.UserObserved && len(s.MismatchedFields) == 0 {
		s.MismatchedFields = append(s.MismatchedFields, "credential_unobserved")
	}
	s.UserMatches = s.UserObserved && len(s.MismatchedFields) == 0
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].ID < normalized[j].ID })
	canonical, e := json.Marshal(normalized)
	if e != nil {
		return empty, ErrXrayUsers
	}
	defer clear(canonical)
	return XrayUsers{sha256.Sum256(canonical), true, s}, nil
}
