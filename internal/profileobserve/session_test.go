package profileobserve

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/profilevault"
	"familyvpn.local/platform/internal/runtimeenv"
	"fmt"
	"strings"
	"testing"
	"time"
)

func sessionTarget() Target {
	return Target{Interface: "inventory_awg", Endpoint: "edge.example.invalid:443", ToolSHA256: strings.Repeat("a", 64),
		BootID: "11111111-2222-3333-4444-555555555555", NetNSDevice: 4, NetNSInode: 12345}
}

func sessionFixture(t *testing.T) (profilevault.Context, []byte, Target, [][]byte) {
	t.Helper()
	c, client, _ := sample(t)
	var encodedPrivate string
	for _, line := range strings.Split(string(client), "\n") {
		if strings.HasPrefix(line, "PrivateKey = ") {
			encodedPrivate = strings.TrimPrefix(line, "PrivateKey = ")
		}
	}
	private, e := base64.StdEncoding.DecodeString(encodedPrivate)
	if e != nil {
		t.Fatal("generated key unavailable")
	}
	defer clear(private)
	key, e := ecdh.X25519().NewPrivateKey(private)
	if e != nil {
		t.Fatal("generated key invalid")
	}
	public := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	stamp := fmt.Sprint(time.Now().Add(-5 * time.Second).Unix())
	data := [][]byte{[]byte(public + "\t" + stamp + "\n"), []byte(public + "\t10\t20\n"),
		[]byte(public + "\t" + stamp + "\n"), []byte(public + "\t11\t25\n")}
	t.Cleanup(func() {
		for _, b := range data {
			clear(b)
		}
	})
	return c, client, sessionTarget(), data
}

func sessionEnvironment(target Target) runtimeenv.Scope {
	return runtimeenv.Scope{BootID: target.BootID, NetNSDevice: target.NetNSDevice, NetNSInode: target.NetNSInode}
}

func TestAWGSessionObservationSealedBindingAndCleanup(t *testing.T) {
	c, client, target, data := sessionFixture(t)
	reads, waits := 0, 0
	var readBuffers [][]byte
	r, e := observeSession(context.Background(), c, 2, client, target,
		func(_ context.Context, iface, pin, view string) ([]byte, error) {
			if iface != target.Interface || pin != target.ToolSHA256 || view != []string{"latest-handshakes", "transfer", "latest-handshakes", "transfer"}[reads] {
				t.Fatal("unexpected tool request")
			}
			b := bytes.Clone(data[reads])
			reads++
			readBuffers = append(readBuffers, b)
			return b, nil
		}, func() (runtimeenv.Scope, error) { return sessionEnvironment(target), nil },
		func(_ context.Context, duration time.Duration) error {
			waits++
			if duration != 2*time.Second {
				t.Fatal("unbounded sampling interval")
			}
			return nil
		})
	if e != nil || reads != 4 || waits != 1 {
		t.Fatal("observation contract failed", e)
	}
	s := r.Summary()
	if s.Source != "awg-session-runtime" || !s.RuntimeTargetBound || !s.PeerObserved || !s.HandshakeRecent || !s.ReceivedAdvanced || !s.SentAdvanced || s.Ready || s.ClientsVerified || s.CoreIdentityVerified || s.RevisionVerified || s.DNSRoutingVerified {
		t.Fatal("activity became readiness or lost diagnostics")
	}
	if s.LastHandshake == nil || !s.MeasuredAt.Before(s.ExpiresAt) || s.ExpiresAt.Sub(s.MeasuredAt) > TTL {
		t.Fatal("invalid observation lifetime")
	}
	for _, b := range readBuffers {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatal("runtime readback retained")
		}
	}
	if e = r.Check(c, 2, client, target, s.MeasuredAt); e != nil {
		t.Fatal("binding unavailable", e)
	}
	for _, now := range []time.Time{s.MeasuredAt.Add(-time.Nanosecond), s.ExpiresAt, s.ExpiresAt.Add(time.Second)} {
		if !errors.Is(r.Check(c, 2, client, target, now), ErrStale) {
			t.Fatal("future/expired observation accepted")
		}
	}
	for _, field := range []string{"owner", "device", "profile", "generation", "protocol", "format"} {
		wrong := c
		switch field {
		case "owner":
			wrong.OwnerID = "another"
		case "device":
			wrong.DeviceID = "another"
		case "profile":
			wrong.ProfileID = "another"
		case "generation":
			wrong.Generation++
		case "protocol":
			wrong.Protocol = "reality"
		case "format":
			wrong.Format = "vless-reality-uri"
		}
		if !errors.Is(r.Check(wrong, 2, client, target, s.MeasuredAt), ErrStale) {
			t.Fatal("observation rebound", field)
		}
	}
	for _, field := range []string{"interface", "endpoint", "tool", "boot", "device", "inode"} {
		wrong := target
		switch field {
		case "interface":
			wrong.Interface = "other"
		case "endpoint":
			wrong.Endpoint = "other.example.invalid:443"
		case "tool":
			wrong.ToolSHA256 = strings.Repeat("b", 64)
		case "boot":
			wrong.BootID = "22222222-2222-3333-4444-555555555555"
		case "device":
			wrong.NetNSDevice++
		case "inode":
			wrong.NetNSInode++
		}
		if !errors.Is(r.Check(c, 2, client, wrong, s.MeasuredAt), ErrStale) {
			t.Fatal("runtime target rebound", field)
		}
	}
	changed := append(bytes.Clone(client), '\n')
	defer clear(changed)
	if !errors.Is(r.Check(c, 3, client, target, s.MeasuredAt), ErrStale) || !errors.Is(r.Check(c, 2, changed, target, s.MeasuredAt), ErrStale) {
		t.Fatal("revision/byte binding bypass")
	}
	last := *s.LastHandshake
	*s.LastHandshake = time.Time{}
	if r.Summary().LastHandshake == nil || *r.Summary().LastHandshake != last {
		t.Fatal("summary mutated sealed observation")
	}
	encoded, e := json.Marshal(r)
	if e != nil {
		t.Fatal("summary unavailable")
	}
	public := strings.Split(string(data[0]), "\t")[0]
	for _, out := range []string{string(encoded), fmt.Sprint(r), fmt.Sprintf("%#v", r)} {
		for _, forbidden := range []string{public, target.Interface, target.Endpoint, target.ToolSHA256, target.BootID, c.OwnerID, string(client), "digest", "PrivateKey"} {
			if strings.Contains(out, forbidden) {
				t.Fatal("raw observation/binding disclosed")
			}
		}
	}
	var restored SessionResult
	if !errors.Is(json.Unmarshal(encoded, &restored), ErrObservation) || !errors.Is(restored.Check(c, 2, client, target, s.MeasuredAt), ErrStale) {
		t.Fatal("JSON restored native observation")
	}
}

func TestAWGSessionFailureClearsReadbacksAndRejectsScopeChanges(t *testing.T) {
	for _, failure := range []string{"read", "scope", "wait", "malformed", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			c, client, target, data := sessionFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reads, scopes := 0, 0
			var buffers [][]byte
			r, e := observeSession(ctx, c, 2, client, target,
				func(context.Context, string, string, string) ([]byte, error) {
					b := bytes.Clone(data[reads])
					reads++
					if failure == "malformed" && reads == 4 {
						b = []byte("untrusted raw input")
					}
					buffers = append(buffers, b)
					if failure == "cancel" && reads == 2 {
						cancel()
					}
					if failure == "read" && reads == 2 {
						return b, errors.New("raw private error")
					}
					return b, nil
				}, func() (runtimeenv.Scope, error) {
					scopes++
					actual := sessionEnvironment(target)
					if failure == "scope" && scopes == 3 {
						actual.NetNSInode++
					}
					return actual, nil
				}, func(context.Context, time.Duration) error {
					if failure == "wait" {
						return errors.New("raw wait error")
					}
					return nil
				})
			if e == nil || r.Summary().ObservationID != "" || strings.Contains(e.Error(), "raw") {
				t.Fatal("failed observation retained evidence/error material")
			}
			for _, b := range buffers {
				if !bytes.Equal(b, make([]byte, len(b))) {
					t.Fatal("failed readback retained")
				}
			}
		})
	}
}

func TestAWGSessionRejectsInvalidInputsBeforeRuntimeAndAllowsUnknownPeer(t *testing.T) {
	c, client, target, _ := sessionFixture(t)
	for _, invalid := range []string{"binding", "revision", "target", "client", "cancel"} {
		wrong, revision, selected, plaintext := c, 2, target, client
		ctx, cancel := context.WithCancel(context.Background())
		switch invalid {
		case "binding":
			wrong.Protocol = "reality"
		case "revision":
			revision = 0
		case "target":
			selected.BootID = ""
		case "client":
			plaintext = []byte("untrusted input")
		case "cancel":
			cancel()
		}
		called := false
		_, e := observeSession(ctx, wrong, revision, plaintext, selected,
			func(context.Context, string, string, string) ([]byte, error) { called = true; return nil, nil },
			func() (runtimeenv.Scope, error) { called = true; return sessionEnvironment(target), nil },
			func(context.Context, time.Duration) error { called = true; return nil })
		cancel()
		if e == nil || called {
			t.Fatal("invalid input reached runtime", invalid)
		}
	}
	r, e := observeSession(context.Background(), c, 2, client, target,
		func(context.Context, string, string, string) ([]byte, error) { return nil, nil },
		func() (runtimeenv.Scope, error) { return sessionEnvironment(target), nil },
		func(context.Context, time.Duration) error { return nil })
	s := r.Summary()
	if e != nil || s.PeerObserved || s.LastHandshake != nil || s.HandshakeRecent || s.ReceivedAdvanced || s.SentAdvanced || s.Ready || s.ClientsVerified {
		t.Fatal("absence became connection/revoke/client proof", e)
	}
}

func TestAWGSessionSamplingWaitIsCancellable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if !errors.Is(waitSession(ctx, sessionSampleInterval), ErrRuntime) || time.Since(start) > time.Second {
		t.Fatal("sampling wait ignored cancellation")
	}
}

func TestAWGSessionFreezesExactClientBytesBeforeReads(t *testing.T) {
	c, client, target, data := sessionFixture(t)
	original := bytes.Clone(client)
	defer clear(original)
	reads := 0
	r, e := observeSession(context.Background(), c, 2, client, target,
		func(context.Context, string, string, string) ([]byte, error) {
			if reads == 0 {
				client[0] = '#'
			}
			b := bytes.Clone(data[reads])
			reads++
			return b, nil
		}, func() (runtimeenv.Scope, error) { return sessionEnvironment(target), nil },
		func(context.Context, time.Duration) error { return nil })
	if e != nil || r.Check(c, 2, original, target, r.Summary().MeasuredAt) != nil || !errors.Is(r.Check(c, 2, client, target, r.Summary().MeasuredAt), ErrStale) {
		t.Fatal("caller mutation changed sealed source bytes", e)
	}
}
