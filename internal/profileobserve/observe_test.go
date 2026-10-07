package profileobserve

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/profilevault"
	"fmt"
	"strings"
	"testing"
	"time"
)

func sample(t testing.TB) (profilevault.Context, []byte, []byte) {
	t.Helper()
	client, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	server, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	key := make([]byte, 32)
	rand.Read(key)
	defer clear(key)
	enc := base64.StdEncoding.EncodeToString
	shared := "S1 = 16\nS2 = 16\nS3 = 16\nS4 = 16\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nHeaderProtectionKey = " + enc(key) + "\nRandomTrailers = on\nDisableCookies = off\n"
	clientData := []byte("[Interface]\nPrivateKey = " + enc(client.Bytes()) + "\nAddress = 10.77.0.2/32, fd77::2/128\nDNS = 10.77.0.1\nJc = 3\nJmin = 40\nJmax = 70\n" + shared + "[Peer]\nPublicKey = " + enc(server.PublicKey().Bytes()) + "\nEndpoint = edge.example.invalid:443\nAllowedIPs = 0.0.0.0/0, ::/0\n")
	serverData := []byte("[Interface]\nPrivateKey = " + enc(server.Bytes()) + "\nListenPort = 443\n" + shared + "[Peer]\nPublicKey = " + enc(client.PublicKey().Bytes()) + "\nAdvancedSecurity = on\nAllowedIPs = 10.77.0.2/32, fd77::2/128\n")
	t.Cleanup(func() { clear(clientData); clear(serverData) })
	return profilevault.Context{OwnerID: "owner", DeviceID: "device", ProfileID: "profile", Protocol: "awg", Format: clientconfig.AWG31Conf, Generation: 1}, clientData, serverData
}

func TestSnapshotComparisonAndImmutableBinding(t *testing.T) {
	c, client, server := sample(t)
	r, e := Snapshot(c, 2, client, server, "edge.example.invalid:443")
	if e != nil || !r.Summary().PeerMatches || r.Summary().RuntimeObserved || r.Summary().Ready || r.Summary().ClientsVerified {
		t.Fatal("configuration became readiness", e)
	}
	s := r.Summary()
	if e = r.Check(c, 2, client, Target{Endpoint: "edge.example.invalid:443"}, s.MeasuredAt.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	for _, now := range []time.Time{s.MeasuredAt.Add(-time.Nanosecond), s.ExpiresAt, s.ExpiresAt.Add(time.Second)} {
		if !errors.Is(r.Check(c, 2, client, Target{Endpoint: "edge.example.invalid:443"}, now), ErrStale) {
			t.Fatal("accepted stale/future evidence")
		}
	}
	wrong := c
	wrong.OwnerID = "other"
	if !errors.Is(r.Check(wrong, 2, client, Target{Endpoint: "edge.example.invalid:443"}, s.MeasuredAt), ErrStale) || !errors.Is(r.Check(c, 3, client, Target{Endpoint: "edge.example.invalid:443"}, s.MeasuredAt), ErrStale) {
		t.Fatal("binding/revision bypass")
	}
	changed := bytes.Clone(client)
	changed = append(changed, '\n')
	defer clear(changed)
	if !errors.Is(r.Check(c, 2, changed, Target{Endpoint: "edge.example.invalid:443"}, s.MeasuredAt), ErrStale) {
		t.Fatal("changed source accepted")
	}
	encoded, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	for _, output := range []string{string(encoded), fmt.Sprint(r), fmt.Sprintf("%#v", r)} {
		if strings.Contains(output, "PrivateKey") || strings.Contains(output, "digest") || strings.Contains(output, "edge.example.invalid") || strings.Contains(output, c.OwnerID) {
			t.Fatal("observation leaked secrets or bindings")
		}
	}
	// Callers cannot change the underlying mismatch list through a summary view.
	mismatch := bytes.Replace(server, []byte("ListenPort = 443"), []byte("ListenPort = 444"), 1)
	defer clear(mismatch)
	r, e = Snapshot(c, 2, client, mismatch, "edge.example.invalid:443")
	if e != nil {
		t.Fatal(e)
	}
	s = r.Summary()
	s.MismatchedFields[0] = "unsafe"
	if r.Summary().MismatchedFields[0] != "endpoint" {
		t.Fatal("mutable observation")
	}
}

func TestSnapshotRejectsMismatchedPeerKeysAddressesAndExtensions(t *testing.T) {
	c, client, server := sample(t)
	mutations := map[string][]byte{
		"peer_addresses": bytes.Replace(server, []byte("10.77.0.2/32"), []byte("10.77.0.3/32"), 1),
		"s1":             bytes.Replace(server, []byte("S1 = 16"), []byte("S1 = 20"), 1),
		"randomtrailers": bytes.Replace(server, []byte("RandomTrailers = on"), []byte("RandomTrailers = off"), 1),
	}
	for field, data := range mutations {
		r, e := Snapshot(c, 2, client, data, "edge.example.invalid:443")
		clear(data)
		if e != nil || r.Summary().PeerMatches || !strings.Contains(strings.Join(r.Summary().MismatchedFields, ","), field) {
			t.Fatal("mismatch missed", field, e)
		}
	}
	missing := bytes.Split(server, []byte("[Peer]"))[0]
	r, e := Snapshot(c, 2, client, missing, "edge.example.invalid:443")
	if e != nil || r.Summary().PeerMatches || !strings.Contains(strings.Join(r.Summary().MismatchedFields, ","), "peer_missing") {
		t.Fatal("missing peer accepted", e)
	}
	for _, data := range [][]byte{append(bytes.Clone(server), []byte("Unknown = ignored\n")...), append(bytes.Clone(server), []byte("[Peer]\n"+string(bytes.Split(server, []byte("[Peer]\n"))[1]))...), bytes.Replace(server, []byte("[Peer]"), []byte("PostUp = any-command\n[Peer]"), 1), bytes.Replace(server, []byte("S1 = 16"), []byte("S1 = 16\ns1 = 16"), 1)} {
		if _, e = Snapshot(c, 2, client, data, "edge.example.invalid:443"); !errors.Is(e, clientconfig.ErrSnapshot) {
			t.Fatal("ambiguous/unsupported snapshot accepted", e)
		}
		clear(data)
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	conflict := append(bytes.Clone(server), []byte("[Peer]\nPublicKey = "+base64.StdEncoding.EncodeToString(other.PublicKey().Bytes())+"\nAllowedIPs = 10.77.0.0/24\n")...)
	defer clear(conflict)
	r, e = Snapshot(c, 2, client, conflict, "edge.example.invalid:443")
	if e != nil || !strings.Contains(strings.Join(r.Summary().MismatchedFields, ","), "address_conflict") {
		t.Fatal("overlapping peer routes accepted", e)
	}
}

func FuzzAWGSnapshotNeverMutatesOrEchoes(f *testing.F) {
	_, client, server := sample(f)
	f.Add(server)
	f.Add([]byte("[Interface]\nPostUp=invalid\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		before := bytes.Clone(data)
		_, e := clientconfig.CheckAWGSnapshot(client, data, "edge.example.invalid:443")
		if !bytes.Equal(before, data) {
			t.Fatal("input altered")
		}
		if e != nil && !errors.Is(e, clientconfig.ErrSnapshot) {
			t.Fatal("unsafe error")
		}
	})
}
