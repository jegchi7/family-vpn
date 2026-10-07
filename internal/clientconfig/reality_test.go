package clientconfig

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/profilevault"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleURI(t testing.TB) []byte {
	t.Helper()
	b := make([]byte, 16)
	rand.Read(b)
	h := hex.EncodeToString(b)
	clear(b)
	id := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return []byte("vless://" + id + "@edge.example.invalid:443?type=tcp&security=reality&flow=xtls-rprx-vision&fp=chrome&sni=cover.example.invalid&pbk=" + base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()) + "&sid=0123&encryption=none&spx=%2Fclient#" + url.PathEscape("Тестовый профиль"))
}
func TestStrictClientURIPreservesAcceptedBytesAndRedactsErrors(t *testing.T) {
	input := sampleURI(t)
	defer clear(input)
	before := bytes.Clone(input)
	defer clear(before)
	validated, e := Validate(VLESSRealityURI, input)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(input, before) || validated.Protocol != "reality" || validated.Format != VLESSRealityURI {
		t.Fatal("validation changed input")
	}
	for _, suffix := range []string{"\n", "\r\n"} {
		if _, e = Validate(VLESSRealityURI, append(bytes.Clone(input), suffix...)); e != nil {
			t.Fatal("file newline", e)
		}
	}
	encoded, e := json.Marshal(validated)
	if e != nil || bytes.Contains(encoded, []byte("credential")) {
		t.Fatal("validation report leaked identity")
	}
	if strings.Contains(fmt.Sprint(validated), "vless://") {
		t.Fatal("String exposed URI")
	}
	uri := string(input)
	u, _ := url.Parse(uri)
	query := u.Query()
	bad := []string{"", uri + "\n" + uri, " " + uri, strings.Replace(uri, "vless://", "ssh://root:", 1), "vpn://" + base64.RawStdEncoding.EncodeToString(input), `{"root_password":"ignored"}`, "-----BEGIN PRIVATE KEY-----\n", uri + "%", strings.Replace(uri, "443?", "0?", 1), strings.Replace(uri, "443?", "65536?", 1), strings.Replace(uri, "443?", "-1?", 1), strings.Replace(uri, "@edge.example.invalid", ":password@edge.example.invalid", 1), strings.Replace(uri, "?type", "/path?type", 1)}
	mutate := func(key, value string) string {
		q := u.Query()
		q.Set(key, value)
		copy := *u
		copy.RawQuery = q.Encode()
		return copy.String()
	}
	bad = append(bad, mutate("sni", "127.0.0.1"), strings.Replace(uri, "@edge.example.invalid", "@[edge.example.invalid]", 1))
	for key, value := range map[string]string{"type": "xhttp", "security": "tls", "encryption": "mlkem768x25519", "flow": "", "fp": "unsafe", "sni": "", "pbk": "broken", "sid": "abc", "privateKey": "secret", "password": "root-secret", "headerType": "http", "pqv": "unsupported", "spx": "https://host.invalid/"} {
		bad = append(bad, mutate(key, value))
	}
	copy := *u
	copy.RawQuery = "type=tcp&" + u.RawQuery
	bad = append(bad, copy.String())
	copy = *u
	copy.RawQuery = strings.Replace(u.RawQuery, "sni=", "%73ni=", 1)
	bad = append(bad, copy.String())
	copy = *u
	copy.RawQuery = strings.Replace(u.RawQuery, "sni=cover.example.invalid", "sni=cover%0Aexample.invalid", 1)
	bad = append(bad, copy.String())
	copy = *u
	copy.RawQuery = strings.Replace(u.RawQuery, "sni=cover.example.invalid", "sni=cover+example.invalid", 1)
	bad = append(bad, copy.String())
	copy = *u
	copy.Fragment = "name\u202e"
	copy.RawFragment = ""
	bad = append(bad, copy.String())
	for _, key := range []string{"type", "security", "flow", "fp", "sni", "pbk", "sid"} {
		q := u.Query()
		q.Del(key)
		copy := *u
		copy.RawQuery = q.Encode()
		bad = append(bad, copy.String())
	}
	for i, text := range bad {
		_, e = Validate(VLESSRealityURI, []byte(text))
		if !errors.Is(e, ErrInvalid) || strings.Contains(e.Error(), text) && text != "" {
			t.Fatal("invalid export accepted or echoed", i)
		}
	}
	if _, e = Validate("awg-conf", input); !errors.Is(e, ErrUnsupported) {
		t.Fatal(e)
	}
	if _, e = Validate(VLESSRealityURI, make([]byte, profilevault.MaxSize+1)); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	// Supported optional defaults and IPv6 do not require any network requests.
	query.Del("encryption")
	query.Set("sid", "")
	query.Set("headerType", "none")
	copy = *u
	copy.Host = "[2001:db8::1]:443"
	copy.RawQuery = query.Encode()
	if _, e = Validate(VLESSRealityURI, []byte(copy.String())); e != nil {
		t.Fatal("documented subset rejected", e)
	}
	alternate := *u
	alternate.Host = "other.example.invalid:8443"
	same, e := Validate(VLESSRealityURI, []byte(alternate.String()))
	if e != nil || !SameCredential(validated, same) {
		t.Fatal("identity changed with host", e)
	}
	different, e := Validate(VLESSRealityURI, sampleURI(t))
	if e != nil || SameCredential(validated, different) {
		t.Fatal("different identity merged", e)
	}
}
func TestPrivateBoundedInput(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	os.Mkdir(dir, 0700)
	path := filepath.Join(dir, "client.txt")
	input := sampleURI(t)
	defer clear(input)
	os.WriteFile(path, input, 0600)
	got, e := ReadInput(path, nil)
	if e != nil || !bytes.Equal(got, input) {
		t.Fatal(e)
	}
	clear(got)
	got, e = ReadInput("-", bytes.NewReader(input))
	if e != nil || !bytes.Equal(got, input) {
		t.Fatal(e)
	}
	clear(got)
	for _, data := range [][]byte{nil, make([]byte, profilevault.MaxSize+1)} {
		if _, e = ReadInput("-", bytes.NewReader(data)); !errors.Is(e, ErrSource) {
			t.Fatal("unbounded input", e)
		}
	}
	alias := filepath.Join(dir, "alias.txt")
	os.Symlink(path, alias)
	if _, e = ReadInput(alias, nil); !errors.Is(e, ErrSource) {
		t.Fatal("symlink input", e)
	}
	os.Chmod(path, 0644)
	if _, e = ReadInput(path, nil); !errors.Is(e, ErrSource) {
		t.Fatal("public input", e)
	}
	os.Chmod(path, 0600)
	os.Chmod(dir, 0755)
	if _, e = ReadInput(path, nil); !errors.Is(e, ErrSource) {
		t.Fatal("public parent", e)
	}
	os.Chmod(dir, 0700)
	if _, e = ReadInput(filepath.Join(dir, "missing.txt"), nil); !errors.Is(e, ErrSource) || strings.Contains(e.Error(), dir) {
		t.Fatal("source path echoed")
	}
}
func FuzzValidateNeverPanics(f *testing.F) {
	f.Add(sampleURI(f))
	f.Add([]byte("vpn://"))
	f.Add([]byte("%"))
	f.Add([]byte{0, 255})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, e := Validate(VLESSRealityURI, b)
		if e != nil && !errors.Is(e, ErrInvalid) {
			t.Fatal("unexpected parser error")
		}
	})
}
