package profileobserve

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"familyvpn.local/platform/internal/clientconfig"
	"slices"
	"strings"
	"testing"
)

func replaceReadbackField(data []byte, field, value string) []byte {
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, field+" = ") {
			lines[i] = ""
			if value != "" {
				lines[i] = field + " = " + value
			}
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

func TestSelectedPeerRequiresExplicitAWGSecurity(t *testing.T) {
	_, client, server := sample(t)
	other, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"on", "off", ""} {
		modified := replaceReadbackField(server, "AdvancedSecurity", mode)
		// A different peer's enabled flag must not certify the selected peer.
		modified = append(modified, []byte("[Peer]\nPublicKey = "+base64.StdEncoding.EncodeToString(other.PublicKey().Bytes())+"\nAdvancedSecurity = on\nAllowedIPs = 10.88.0.2/32\n")...)
		fields, err := clientconfig.CheckAWGSnapshot(client, modified, "edge.example.invalid:443")
		clear(modified)
		if err != nil || slices.Contains(fields, "advanced_security") != (mode != "on") {
			t.Fatal("selected security evidence lost", mode, err)
		}
	}
	// Unknown peers may use a different mode; they must not mask or alter the
	// target's status. The observer performs no deletion or mutation.
	modified := append(bytes.Clone(server), []byte("[Peer]\nPublicKey = "+base64.StdEncoding.EncodeToString(other.PublicKey().Bytes())+"\nAdvancedSecurity = off\nAllowedIPs = 10.88.0.2/32\n")...)
	defer clear(modified)
	fields, e := clientconfig.CheckAWGSnapshot(client, modified, "edge.example.invalid:443")
	if e != nil || len(fields) != 0 {
		t.Fatal("unrelated peer changed target evidence", e)
	}
}

func TestOmittedAWGBooleanModesCannotMaskEnabledServer(t *testing.T) {
	_, client, server := sample(t)
	for _, field := range []string{"RandomTrailers", "DisableCookies"} {
		for _, tc := range []struct {
			client, server string
			conflict       bool
		}{{"", "", false}, {"", "off", false}, {"off", "", false}, {"on", "on", false}, {"off", "off", false}, {"", "on", true}, {"on", "", true}, {"off", "on", true}, {"on", "off", true}} {
			c := replaceReadbackField(client, field, tc.client)
			s := replaceReadbackField(server, field, tc.server)
			fields, e := clientconfig.CheckAWGSnapshot(c, s, "edge.example.invalid:443")
			clear(c)
			clear(s)
			if e != nil || slices.Contains(fields, strings.ToLower(field)) != tc.conflict {
				t.Fatal("omitted boolean hid conflict", field, tc.client, tc.server, e)
			}
		}
	}
}

func TestShowconfFwMarkFormatIsReadbackOnly(t *testing.T) {
	_, client, server := sample(t)
	for _, mark := range []string{"off", "0", "4294967295", "0x1", "0xca6c", "0xffffffff", "0xABCDEF01"} {
		data := bytes.Replace(server, []byte("[Peer]"), []byte("FwMark = "+mark+"\n[Peer]"), 1)
		before := bytes.Clone(data)
		fields, e := clientconfig.CheckAWGSnapshot(client, data, "edge.example.invalid:443")
		unchanged := bytes.Equal(data, before)
		clear(data)
		clear(before)
		if e != nil || len(fields) != 0 || !unchanged {
			t.Fatal("bounded showconf FwMark rejected or altered", mark, e)
		}
	}
	for _, mark := range []string{"0x", "0x100000000", "0x000000001", "0x-1", "-1", "+1", "0xgg", "0X1", "0x1 2", "4294967296"} {
		data := bytes.Replace(server, []byte("[Peer]"), []byte("FwMark = "+mark+"\n[Peer]"), 1)
		_, e := clientconfig.CheckAWGSnapshot(client, data, "edge.example.invalid:443")
		clear(data)
		if !errors.Is(e, clientconfig.ErrSnapshot) || e.Error() != clientconfig.ErrSnapshot.Error() {
			t.Fatal("malformed mark accepted or echoed", mark)
		}
	}
	data := bytes.Replace(client, []byte("[Peer]"), []byte("FwMark = 0xca6c\n[Peer]"), 1)
	defer clear(data)
	if _, e := clientconfig.Validate(clientconfig.AWG31Conf, data); !errors.Is(e, clientconfig.ErrInvalid) {
		t.Fatal("readback extension expanded client management import")
	}
}
