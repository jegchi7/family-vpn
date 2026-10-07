package clientconfig

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func awgSample(t testing.TB) []byte {
	t.Helper()
	key := func() string {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			t.Fatal(e)
		}
		defer clear(b)
		return base64.StdEncoding.EncodeToString(b)
	}
	data := []byte("# Синтетический клиент; ключи генерируются только в памяти\r\n[Interface]\r\nPrivateKey = " + key() + "\r\nAddress = 10.77.0.2/32, fd77::2/128\r\nDNS = 10.77.0.1, fd77::1\r\nMTU = 1280\r\nListenPort = 0\r\nJc = 3\r\nJmin = 40\r\nJmax = 70\r\nS1 = 16\r\nS2 = 16\r\nS3 = 16\r\nS4 = 16\r\nH1 = 1\r\nH2 = 2\r\nH3 = 3\r\nH4 = 4\r\nHeaderProtectionKey = " + key() + "\r\nContentPaddingAddition = 0-64\r\nRekeyAfterTime = 100-130\r\nRekeyTimeout = 4-6\r\nRejectAfterTime = 160-200\r\nKeepaliveTimeout = 8-12\r\nMaxHandshakeAttempts = 15-20\r\nRandomTrailers = on\r\nDisableCookies = off\r\nI1 = <b 0xdeadbeef><r 20><rc 4><rd 5><t>\r\nI2 = <r 8>\r\nI3 = <rc 8>\r\nI4 = <rd 8>\r\nI5 = <b 0x0102>\r\n[Peer]\r\nPublicKey = " + key() + "\r\nPresharedKey = " + key() + "\r\nEndpoint = edge.example.invalid:443\r\nAllowedIPs = 0.0.0.0/0, ::/0\r\nPersistentKeepalive = 20-30\r\nAdvancedSecurity = on\r\n")
	t.Cleanup(func() { clear(data) })
	return data
}

func awgReplace(data []byte, field, value string) []byte {
	lines := strings.Split(string(data), "\r\n")
	for i, line := range lines {
		if strings.HasPrefix(line, field+" = ") {
			lines[i] = field + " = " + value
		}
	}
	return []byte(strings.Join(lines, "\r\n"))
}

func TestAWG31FullFieldsPreservedAndReportsRedacted(t *testing.T) {
	data := awgSample(t)
	before := bytes.Clone(data)
	defer clear(before)
	v, e := Validate(AWG31Conf, data)
	if e != nil || v.Protocol != "awg" || v.Format != AWG31Conf || !bytes.Equal(before, data) {
		t.Fatal("AWG31 rejected or altered input", e)
	}
	b, e := json.Marshal(v)
	if e != nil || string(b) != `{"protocol":"awg","format":"awg-3.1-conf"}` {
		t.Fatal("unsafe validation DTO")
	}
	for _, output := range []string{fmt.Sprint(v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v)} {
		if strings.Contains(output, "credential") || strings.Contains(output, "PrivateKey") {
			t.Fatal("unsafe formatting")
		}
	}
	variants := [][]byte{bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")), bytes.Clone(bytes.TrimSuffix(data, []byte("\r\n"))), awgReplace(data, "Endpoint", "[2001:db8::1]:65535"), awgReplace(data, "AllowedIPs", "0.0.0.0/0"), awgReplace(data, "H4", "400-500"), awgReplace(data, "PersistentKeepalive", "0")}
	for i, input := range variants {
		other, e := Validate(AWG31Conf, input)
		clear(input)
		if e != nil || !SameCredential(v, other) {
			t.Fatalf("accepted variant %d lost identity", i)
		}
	}
	// X25519 clamps these bits; raw private bytes are not the credential identity.
	var raw []byte
	for _, line := range strings.Split(string(data), "\r\n") {
		if strings.HasPrefix(line, "PrivateKey = ") {
			raw, _ = base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "PrivateKey = "))
		}
	}
	raw[0] ^= 7
	raw[31] ^= 128
	changed := awgReplace(data, "PrivateKey", base64.StdEncoding.EncodeToString(raw))
	clear(raw)
	defer clear(changed)
	other, e := Validate(AWG31Conf, changed)
	if e != nil || !SameCredential(v, other) {
		t.Fatal("clamped equivalent private key bypassed uniqueness")
	}
	newKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	changed = awgReplace(data, "PrivateKey", base64.StdEncoding.EncodeToString(newKey.Bytes()))
	defer clear(changed)
	other, e = Validate(AWG31Conf, changed)
	if e != nil || SameCredential(v, other) {
		t.Fatal("distinct credentials conflated")
	}
}

func TestAWG31RejectsAmbiguousManagementAndInvalidParameters(t *testing.T) {
	data := awgSample(t)
	mutations := map[string]string{
		"PrivateKey": "bad", "PublicKey": strings.Repeat("A", 43) + "=", "HeaderProtectionKey": "not-a-key",
		"PresharedKey": "none", "Address": "0.0.0.0/0", "DNS": "dns.example.invalid", "Endpoint": "user:password@host.invalid:443",
		"AllowedIPs": "10.0.0.0/8", "Jc": "65536", "Jmin": "71", "Jmax": "-1", "S1": "11", "S2": "17",
		"H1": "2-4", "H2": "5-1", "H3": "4294967296", "H4": "1-2-3", "MTU": "575",
		"ContentPaddingAddition": "65536", "RekeyAfterTime": "20-10", "RekeyTimeout": "1-2-3", "RejectAfterTime": "-1",
		"KeepaliveTimeout": "1.2", "MaxHandshakeAttempts": "x", "RandomTrailers": "maybe", "DisableCookies": "yes",
		"I1": "<t><t>", "I2": "<r 1001>", "I3": "<cmd anything>", "I4": "<b 0x123>", "I5": "<b 0xgg>",
		"PersistentKeepalive": "65536", "AdvancedSecurity": "off", "ListenPort": "65536",
	}
	for key, value := range mutations {
		input := awgReplace(data, key, value)
		_, e := Validate(AWG31Conf, input)
		clear(input)
		if !errors.Is(e, ErrInvalid) || e.Error() != ErrInvalid.Error() {
			t.Fatalf("unsafe acceptance/error for %s", key)
		}
	}
	text := string(data)
	bad := []string{"", "vpn://opaque", `{"root_password":"management"}`, text + "[Peer]\r\n", text + "[Interface]\r\n", text + "PrivateKey = ignored\r\n", "[Peer]\r\n" + text, strings.Replace(text, "Jc = 3", "Jc = 3\r\njC = 4", 1), strings.Replace(text, "[Peer]", "PostUp = run-command\r\n[Peer]", 1), strings.Replace(text, "[Peer]", "SaveConfig = true\r\n[Peer]", 1), strings.Replace(text, "[Peer]", "Table = off\r\n[Peer]", 1), strings.Replace(text, "[Peer]", "FwMark = 1\r\n[Peer]", 1), text + "Unknown = 1\r\n", text + "\x00", text + "#\u202e", strings.Replace(text, "Jc = 3", "Jc = 3\rJmax = 7", 1), strings.Replace(text, "DNS = 10.77.0.1, fd77::1\r\n", "", 1), strings.Replace(text, "HeaderProtectionKey =", "WrongKey =", 1), strings.Replace(text, "[Peer]", "[Server]", 1)}
	for i, input := range bad {
		if _, e := Validate(AWG31Conf, []byte(input)); !errors.Is(e, ErrInvalid) {
			t.Fatalf("bad structure %d accepted", i)
		}
	}
	for _, value := range []string{"::/0", "0.0.0.0/0, 0.0.0.0/0", "1.2.3.4/0"} {
		if awgFullTunnel(value) {
			t.Fatal("invalid full tunnel accepted")
		}
	}
	for _, endpoint := range []string{"host.invalid:0", "host.invalid:65536", "[host.invalid]:443", "[fe80::1%eth0]:443", "0.0.0.0:443"} {
		if awgEndpoint(endpoint) {
			t.Fatal("invalid endpoint accepted")
		}
	}
	if awgCPS(strings.Repeat("<r 1000>", 5)) || awgCPS(strings.Repeat("<b 0x00>", 129)) {
		t.Fatal("unbounded CPS accepted")
	}
}

func FuzzAWG31DoesNotAlterInput(f *testing.F) {
	f.Add(awgSample(f))
	f.Add([]byte("[Interface]\nPostUp=invalid\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		before := bytes.Clone(data)
		v, e := Validate(AWG31Conf, data)
		if !bytes.Equal(before, data) {
			t.Fatal("parser mutated input")
		}
		if e != nil && !errors.Is(e, ErrInvalid) {
			t.Fatal("unsafe error")
		}
		if e == nil && (v.Protocol != "awg" || v.Format != AWG31Conf) {
			t.Fatal("wrong protocol")
		}
	})
}
