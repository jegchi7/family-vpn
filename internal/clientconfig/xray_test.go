package clientconfig

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func snapshotPair(t *testing.T) ([]byte, map[string]any, string) {
	t.Helper()
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	id := make([]byte, 16)
	rand.Read(id)
	h := hex.EncodeToString(id)
	clear(id)
	uuid := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	client := []byte("vless://" + uuid + "@edge.example.invalid:443?type=tcp&security=reality&fp=chrome&flow=xtls-rprx-vision&sni=cover.example.invalid&pbk=" + base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()) + "&sid=abcd#Test\r\n")
	in := map[string]any{"tag": "clients", "listen": "0.0.0.0", "port": 443, "protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": uuid, "flow": "xtls-rprx-vision"}}}, "streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"privateKey": base64.RawURLEncoding.EncodeToString(key.Bytes()), "serverNames": []string{"cover.example.invalid"}, "shortIds": []string{"abcd"}, "target": "cover.example.invalid:443"}}}
	t.Cleanup(func() { clear(client) })
	return client, in, uuid
}
func encodedSnapshot(t *testing.T, in map[string]any) ([]byte, string) {
	t.Helper()
	b, e := json.Marshal(map[string]any{"inbounds": []any{in}, "outbounds": []any{map[string]any{"tag": "unrelated"}}})
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(b)
	t.Cleanup(func() { clear(b) })
	return b, hex.EncodeToString(sum[:])
}
func TestXraySnapshotFieldsAndSecrecy(t *testing.T) {
	for _, field := range []string{"match", "endpoint", "port", "listen_mapping", "credential", "flow", "public_key", "server_name", "short_id"} {
		t.Run(field, func(t *testing.T) {
			client, in, uuid := snapshotPair(t)
			endpoint := "edge.example.invalid:443"
			settings := in["settings"].(map[string]any)
			peer := settings["clients"].([]any)[0].(map[string]any)
			reality := in["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
			switch field {
			case "endpoint":
				endpoint = "other.example.invalid:443"
			case "port":
				in["port"] = 444
			case "listen_mapping":
				in["listen"] = "192.0.2.1"
			case "credential":
				_, _, otherID := snapshotPair(t)
				peer["id"] = otherID
			case "flow":
				peer["flow"] = ""
			case "public_key":
				key, _ := ecdh.X25519().GenerateKey(rand.Reader)
				reality["privateKey"] = base64.RawURLEncoding.EncodeToString(key.Bytes())
			case "server_name":
				reality["serverNames"] = []string{"other.example.invalid"}
			case "short_id":
				reality["shortIds"] = []string{"00"}
			}
			b, pin := encodedSnapshot(t, in)
			got, e := CheckXraySnapshot(VLESSRealityURI, client, b, "clients", endpoint, pin)
			if e != nil {
				t.Fatal("comparison failed")
			}
			want := []string{}
			if field != "match" {
				want = []string{field}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("incorrect mismatch fields", got)
			}
			report, _ := json.Marshal(got)
			if strings.Contains(string(report), uuid) || strings.Contains(string(report), reality["privateKey"].(string)) {
				t.Fatal("sensitive result")
			}
		})
	}
}
func TestXraySnapshotRejectsAmbiguityAndUnsupported(t *testing.T) {
	client, in, _ := snapshotPair(t)
	base, pin := encodedSnapshot(t, in)
	if _, e := CheckXraySnapshot(VLESSRealityURI, client, base, "clients", "edge.example.invalid:443", strings.Repeat("0", 64)); !errors.Is(e, ErrSnapshotRevision) {
		t.Fatal("snapshot drift accepted")
	}
	for _, data := range [][]byte{[]byte(`{"inbounds":[],"inbounds":[]}`), []byte(`{"inbounds":[],"Inbounds":[]}`), append(append([]byte{}, base...), []byte(` {}`)...), []byte(strings.Repeat("[", 34) + strings.Repeat("]", 34)), []byte("{\"inbounds\":[]\xff}")} {
		h := sha256.Sum256(data)
		if _, e := CheckXraySnapshot(VLESSRealityURI, client, data, "clients", "edge.example.invalid:443", hex.EncodeToString(h[:])); !errors.Is(e, ErrSnapshot) {
			t.Fatal("ambiguous JSON accepted")
		}
	}
	if _, e := CheckXraySnapshot(VLESSRealityURI, client, base, "missing", "edge.example.invalid:443", pin); !errors.Is(e, ErrSnapshot) {
		t.Fatal("unknown inbound accepted")
	}
	for _, variant := range []string{"extension", "transport", "duplicate_peer", "duplicate_tag", "alias", "null_key"} {
		t.Run(variant, func(t *testing.T) {
			client, in, _ := snapshotPair(t)
			stream := in["streamSettings"].(map[string]any)
			reality := stream["realitySettings"].(map[string]any)
			switch variant {
			case "extension":
				reality["minClientVer"] = "1.0.0"
			case "transport":
				stream["network"] = "xhttp"
			case "duplicate_peer":
				s := in["settings"].(map[string]any)
				s["clients"] = append(s["clients"].([]any), s["clients"].([]any)[0])
			case "alias":
				reality["dest"] = reality["target"]
			case "null_key":
				reality["privateKey"] = nil
			}
			b, pin := encodedSnapshot(t, in)
			if variant == "duplicate_tag" {
				b, _ = json.Marshal(map[string]any{"inbounds": []any{in, in}})
				h := sha256.Sum256(b)
				pin = hex.EncodeToString(h[:])
			}
			if _, e := CheckXraySnapshot(VLESSRealityURI, client, b, "clients", "edge.example.invalid:443", pin); !errors.Is(e, ErrSnapshot) {
				t.Fatal("unsupported server subset accepted")
			}
		})
	}
}
func FuzzXraySnapshotJSON(f *testing.F) {
	f.Add([]byte(`{"inbounds":[]}`))
	f.Add([]byte(`{"key":1,"key":2}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			t.Skip()
		}
		d := json.NewDecoder(strings.NewReader(string(b)))
		d.UseNumber()
		_ = uniqueJSON(d, 0)
	})
}
