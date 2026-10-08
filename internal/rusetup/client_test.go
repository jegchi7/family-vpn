package rusetup

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"testing"
)

// Client bytes are generated only in memory. This helper is not an issuance,
// vault import, profile owner binding, or real client round-trip.
func clientForBundle(t *testing.T, b Bundle) []byte {
	t.Helper()
	var p plan
	var x xConfig
	if decode(b.Plan, &p) != nil || decode(b.Xray, &x) != nil {
		t.Fatal("private test context unavailable")
	}
	r := x.Inbounds[0].Stream.Reality
	k, e := base64.RawURLEncoding.DecodeString(r.PrivateKey)
	defer clear(k)
	if e != nil {
		t.Fatal("private test context unavailable")
	}
	key, e := ecdh.X25519().NewPrivateKey(k)
	if e != nil {
		t.Fatal("private test context unavailable")
	}
	var uuid [16]byte
	if _, e := rand.Read(uuid[:]); e != nil {
		t.Fatal("private test credential unavailable")
	}
	uuid[6], uuid[8] = uuid[6]&15|64, uuid[8]&63|128
	id := hex.EncodeToString(uuid[:])
	clear(uuid[:])
	id = id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:]
	u := url.URL{Scheme: "vless", Host: p.Inputs.Endpoint, User: url.User(id)}
	u.RawQuery = url.Values{"type": {"tcp"}, "security": {"reality"}, "flow": {"xtls-rprx-vision"}, "fp": {"chrome"}, "sni": {p.Inputs.ServerName}, "pbk": {base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())}, "sid": {r.ShortIDs[0]}}.Encode()
	data := []byte(u.String() + "\r\n")
	t.Cleanup(func() { clear(data) })
	return data
}

func TestRUPureValidatedClientBindingMatchesServerAndPreservesInputs(t *testing.T) {
	b := bundleForTest(t)
	client := clientForBundle(t, b)
	before := bytes.Clone(client)
	defer clear(before)
	bound, e := BindValidatedClient(b, client)
	if e != nil {
		t.Fatal("validated matching client rejected")
	}
	defer bound.Clear()
	s, binding, e := ValidateBundle(bound)
	if e != nil || !s.ClientBindingConfigured || !s.ConfigurationValidated || s.Ready || s.ClientVerified || s.RuntimeInstalled || s.NativeSyntaxValidated || binding.RUIPv4 != "8.8.4.4" {
		t.Fatal("private binding produced proof or invalid config")
	}
	var original, x xConfig
	if decode(b.Xray, &original) != nil || decode(bound.Xray, &x) != nil || len(original.Inbounds[0].Settings.Clients) != 0 || len(x.Inbounds[0].Settings.Clients) != 1 || !bytes.Equal(client, before) || !bytes.Equal(b.SingBox, bound.SingBox) || !bytes.Equal(b.Hop, bound.Hop) || !bytes.Equal(b.Plan, bound.Plan) {
		t.Fatal("binding altered unrelated private bytes or source")
	}
	second, e := BindValidatedClient(bound, client)
	if e != nil {
		t.Fatal("same validated credential not idempotent")
	}
	defer second.Clear()
	if !bytes.Equal(second.Xray, bound.Xray) {
		t.Fatal("idempotent private binding changed config")
	}
	if _, e := BindValidatedClient(bound, clientForBundle(t, b)); e == nil {
		t.Fatal("existing credential replaced without writer operation")
	}
}

func TestRUClientBindingRejectsIndependentContextMismatchAndExpansion(t *testing.T) {
	b := bundleForTest(t)
	client := clientForBundle(t, b)
	for _, mutate := range []func(*url.URL){
		func(u *url.URL) { u.Host = "9.9.9.9:443" },
		func(u *url.URL) { q := u.Query(); q.Set("sni", "www.example.com"); u.RawQuery = q.Encode() },
		func(u *url.URL) { q := u.Query(); q.Set("sid", ""); u.RawQuery = q.Encode() },
		func(u *url.URL) {
			q := u.Query()
			q.Set("pbk", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
			u.RawQuery = q.Encode()
		},
		func(u *url.URL) { q := u.Query(); q.Set("management", "true"); u.RawQuery = q.Encode() },
		func(u *url.URL) { q := u.Query(); q.Set("flow", ""); u.RawQuery = q.Encode() },
	} {
		u, e := url.Parse(string(bytes.TrimSuffix(client, []byte("\r\n"))))
		if e != nil {
			t.Fatal("private test context unavailable")
		}
		mutate(u)
		bad := []byte(u.String())
		out, e := BindValidatedClient(b, bad)
		clear(bad)
		out.Clear()
		if e == nil {
			t.Fatal("expanded or mismatched client accepted")
		}
	}
	invalid := b
	invalid.Xray = bytes.Replace(b.Xray, []byte(`"127.0.0.1:10443"`), []byte(`"1.0.0.1:443"`), 1)
	defer clear(invalid.Xray)
	if _, e := BindValidatedClient(invalid, client); e == nil {
		t.Fatal("client binding repaired an invalid server config")
	}
}
