package xrayobserve

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/profilevault"
	"familyvpn.local/platform/internal/runtimeenv"
	"familyvpn.local/platform/internal/xrayinventory"
	"fmt"
	"strings"
	"testing"
	"time"
)

func sample(t *testing.T) (profilevault.Context, []byte, []byte) {
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
	client := []byte("vless://" + id + "@edge.example.invalid:443?type=tcp&security=reality&flow=xtls-rprx-vision&fp=chrome&sni=cover.example.invalid&pbk=" + base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()) + "&sid=#Test")
	response, e := json.Marshal(map[string]any{"users": []any{map[string]any{"email": "test@example.invalid", "account": map[string]any{"_TypedMessage_": "xray.proxy.vless.Account", "id": id, "flow": "xtls-rprx-vision"}}}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { clear(client); clear(response) })
	return profilevault.Context{OwnerID: "owner", DeviceID: "device", ProfileID: "profile", Protocol: "reality", Format: clientconfig.VLESSRealityURI, Generation: 1}, client, response
}

func TestInventoryUnavailableOrChangedBeforeBetweenAfterReadbacks(t *testing.T) {
	c, client, response := sample(t)
	target := testTarget()
	for _, at := range []int{1, 2, 3} {
		reads, checks := 0, 0
		var buffers [][]byte
		_, e := observe(context.Background(), c, 2, client, target, func(context.Context, string, string, string) ([]byte, error) {
			reads++
			b := bytes.Clone(response)
			buffers = append(buffers, b)
			return b, nil
		}, testEnvironment(target), func(_ context.Context, actual Target) error {
			checks++
			if actual != target {
				t.Fatal("inventory target changed")
			}
			if checks == at {
				return errors.New("private-manifest-error")
			}
			return nil
		})
		if !errors.Is(e, xrayinventory.ErrInventory) || reads != at-1 || strings.Contains(e.Error(), "private-manifest") {
			t.Fatal("inventory guard bypass", e)
		}
		for _, b := range buffers {
			if !bytes.Equal(b, make([]byte, len(b))) {
				t.Fatal("failed inventory retained readback")
			}
		}
	}
	for _, pin := range []string{"", strings.Repeat("A", 64), "malformed-inventory"} {
		bad := target
		bad.InventorySHA256 = pin
		_, e := observe(context.Background(), c, 2, client, bad, func(context.Context, string, string, string) ([]byte, error) {
			t.Fatal("reader without inventory pin")
			return nil, nil
		}, testEnvironment(target), func(context.Context, Target) error { t.Fatal("loader without pin"); return nil })
		if !errors.Is(e, ErrInput) {
			t.Fatal("missing/malformed inventory accepted", e)
		}
	}
}
func testTarget() Target {
	return Target{Server: "127.0.0.1:10085", Tag: "inventory_inbound", ToolSHA256: strings.Repeat("a", 64), InventorySHA256: strings.Repeat("c", 64), Scope: runtimeenv.Scope{BootID: "11111111-2222-3333-4444-555555555555", NetNSDevice: 4, NetNSInode: 12345}}
}
func testInventory(_ context.Context, target Target) error {
	if !target.Valid() {
		return ErrInput
	}
	return nil
}
func testEnvironment(t Target) func() (runtimeenv.Scope, error) {
	return func() (runtimeenv.Scope, error) { return t.Scope, nil }
}

func TestScopedPartialRuntimeResultCannotBecomeReady(t *testing.T) {
	c, client, response := sample(t)
	target := testTarget()
	var returned [][]byte
	r, e := observe(context.Background(), c, 2, client, target, func(context.Context, string, string, string) ([]byte, error) {
		b := bytes.Clone(response)
		returned = append(returned, b)
		return b, nil
	}, testEnvironment(target), testInventory)
	if e != nil {
		t.Fatal(e)
	}
	s := r.Summary()
	if !s.RuntimeReadback || !s.InventoryBound || !s.ExecutionScopeBound || !s.UserMatches || s.EnumerationComplete || s.CoreIdentityVerified || s.RevisionVerified || s.TransportVerified || s.ClientsVerified || s.Ready {
		t.Fatal("partial became full acceptance")
	}
	for _, b := range returned {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatal("readback retained")
		}
	}
	if e = r.Check(c, 2, client, target, s.MeasuredAt); e != nil {
		t.Fatal(e)
	}
	for _, now := range []time.Time{s.MeasuredAt.Add(-time.Nanosecond), s.ExpiresAt, s.ExpiresAt.Add(time.Second)} {
		if !errors.Is(r.Check(c, 2, client, target, now), ErrStale) {
			t.Fatal("TTL bypass")
		}
	}
	wrong := c
	wrong.OwnerID = "foreign"
	if !errors.Is(r.Check(wrong, 2, client, target, s.MeasuredAt), ErrStale) || !errors.Is(r.Check(c, 3, client, target, s.MeasuredAt), ErrStale) {
		t.Fatal("binding bypass")
	}
	changed := append(bytes.Clone(client), '\n')
	defer clear(changed)
	if !errors.Is(r.Check(c, 2, changed, target, s.MeasuredAt), ErrStale) {
		t.Fatal("exact bytes bypass")
	}
	for _, field := range []string{"server", "tag", "tool", "inventory", "boot", "device", "inode"} {
		other := target
		switch field {
		case "server":
			other.Server = "[::1]:10085"
		case "tag":
			other.Tag = "other"
		case "tool":
			other.ToolSHA256 = strings.Repeat("b", 64)
		case "inventory":
			other.InventorySHA256 = strings.Repeat("d", 64)
		case "boot":
			other.Scope.BootID = "22222222-2222-3333-4444-555555555555"
		case "device":
			other.Scope.NetNSDevice++
		case "inode":
			other.Scope.NetNSInode++
		}
		if !errors.Is(r.Check(c, 2, client, other, s.MeasuredAt), ErrStale) {
			t.Fatal("target rebound", field)
		}
	}
	encoded, _ := json.Marshal(r)
	for _, out := range []string{string(encoded), fmt.Sprintf("%#v", r), fmt.Sprint(r)} {
		for _, bad := range []string{string(client), "test@example.invalid", target.Server, target.Tag, target.ToolSHA256, target.InventorySHA256, target.Scope.BootID, "digest", c.OwnerID} {
			if strings.Contains(out, bad) {
				t.Fatal("secret/source/binding leakage")
			}
		}
	}
	var restored Result
	if !errors.Is(json.Unmarshal(encoded, &restored), ErrInput) {
		t.Fatal("JSON restored evidence")
	}
	s.Ready = true
	s.ExecutionScopeBound = false
	if r.Summary().Ready || !r.Summary().ExecutionScopeBound {
		t.Fatal("mutable summary")
	}
	snapshot, e := Snapshot(c, 2, client, response)
	if e != nil || snapshot.Summary().RuntimeReadback || snapshot.Summary().InventoryBound || snapshot.Summary().ExecutionScopeBound {
		t.Fatal("snapshot became live", e)
	}
	if e = snapshot.Check(c, 2, client, target, snapshot.Summary().MeasuredAt); !errors.Is(e, ErrStale) {
		t.Fatal("snapshot gained native target", e)
	}
}
func TestDoubleReadbackDriftErrorsAndTargetValidation(t *testing.T) {
	c, client, response := sample(t)
	target := testTarget()
	pin := target.ToolSHA256
	for _, server := range []string{"127.0.0.1:10085", "[::1]:10085"} {
		if !ValidTarget(server, "clients", pin) {
			t.Fatal("canonical loopback rejected")
		}
	}
	for _, server := range []string{"localhost:10085", "example.invalid:443", "192.0.2.1:10085", "0.0.0.0:10085", "127.0.0.2:10085", "127.0.0.1:010085", "127.0.0.1:0", "[::ffff:127.0.0.1]:10085", "[::1%eth0]:10085"} {
		if ValidTarget(server, "clients", pin) {
			t.Fatal("unapproved API")
		}
	}
	for _, tc := range []struct{ tag, pin string }{{"-tag", pin}, {"clients space", pin}, {"clients", strings.ToUpper(pin)}, {"clients", strings.Repeat("g", 64)}} {
		if ValidTarget("127.0.0.1:10085", tc.tag, tc.pin) {
			t.Fatal("unsafe target")
		}
	}
	n := 0
	_, e := observe(context.Background(), c, 2, client, target, func(context.Context, string, string, string) ([]byte, error) {
		n++
		if n == 1 {
			return bytes.Clone(response), nil
		}
		return []byte(`{"users":[]}`), nil
	}, testEnvironment(target), testInventory)
	if !errors.Is(e, ErrDrift) {
		t.Fatal("changed users accepted", e)
	}
	_, e = observe(context.Background(), c, 2, client, target, func(context.Context, string, string, string) ([]byte, error) {
		return nil, errors.New("sensitive-response")
	}, testEnvironment(target), testInventory)
	if !errors.Is(e, ErrRuntime) || strings.Contains(e.Error(), "sensitive-response") {
		t.Fatal("raw error", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = observe(ctx, c, 2, client, target, func(context.Context, string, string, string) ([]byte, error) {
		t.Fatal("reader after cancel")
		return nil, nil
	}, func() (runtimeenv.Scope, error) { t.Fatal("scope after cancel"); return runtimeenv.Scope{}, nil }, testInventory)
	if !errors.Is(e, ErrRuntime) {
		t.Fatal("cancel bypass", e)
	}
}
func TestExecutionScopeBeforeBetweenAfterReadsAndCancelledResponse(t *testing.T) {
	c, client, response := sample(t)
	target := testTarget()
	for _, at := range []int{1, 2, 3} {
		for _, kind := range []string{"boot", "device", "inode", "unavailable"} {
			t.Run(fmt.Sprintf("%s/%d", kind, at), func(t *testing.T) {
				calls, reads := 0, 0
				var returned [][]byte
				_, e := observe(context.Background(), c, 2, client, target, func(context.Context, string, string, string) ([]byte, error) {
					reads++
					b := bytes.Clone(response)
					returned = append(returned, b)
					return b, nil
				}, func() (runtimeenv.Scope, error) {
					calls++
					s := target.Scope
					if calls == at {
						switch kind {
						case "boot":
							s.BootID = "22222222-2222-3333-4444-555555555555"
						case "device":
							s.NetNSDevice++
						case "inode":
							s.NetNSInode++
						case "unavailable":
							return s, errors.New("private-inventory")
						}
					}
					return s, nil
				}, testInventory)
				if !errors.Is(e, ErrTarget) || reads != at-1 || strings.Contains(e.Error(), "private-inventory") {
					t.Fatal("scope drift accepted", e)
				}
				for _, b := range returned {
					if !bytes.Equal(b, make([]byte, len(b))) {
						t.Fatal("failed scope retained response")
					}
				}
			})
		}
	}
	for _, at := range []int{1, 2} {
		ctx, cancel := context.WithCancel(context.Background())
		reads := 0
		_, e := observe(ctx, c, 2, client, target, func(context.Context, string, string, string) ([]byte, error) {
			reads++
			if reads == at {
				cancel()
			}
			return bytes.Clone(response), nil
		}, testEnvironment(target), testInventory)
		cancel()
		if !errors.Is(e, ErrRuntime) {
			t.Fatal("cancelled response became proof", e)
		}
	}
	for _, scope := range []runtimeenv.Scope{{}, {BootID: target.Scope.BootID}, {BootID: strings.ToUpper("abcdefab-2222-3333-4444-555555555555"), NetNSDevice: 4, NetNSInode: 12345}, {BootID: target.Scope.BootID, NetNSDevice: 4}} {
		bad := target
		bad.Scope = scope
		_, e := observe(context.Background(), c, 2, client, bad, func(context.Context, string, string, string) ([]byte, error) {
			t.Fatal("unscoped reader called")
			return nil, nil
		}, testEnvironment(target), testInventory)
		if !errors.Is(e, ErrInput) {
			t.Fatal("missing scope accepted", e)
		}
	}
}

func TestCancelledInventoryCannotProduceEvidence(t *testing.T) {
	c, client, response := sample(t)
	target := testTarget()
	for _, at := range []int{1, 2, 3} {
		ctx, cancel := context.WithCancel(context.Background())
		reads, checks := 0, 0
		var buffers [][]byte
		_, e := observe(ctx, c, 2, client, target, func(context.Context, string, string, string) ([]byte, error) {
			reads++
			b := bytes.Clone(response)
			buffers = append(buffers, b)
			return b, nil
		}, testEnvironment(target), func(context.Context, Target) error {
			checks++
			if checks == at {
				cancel()
			}
			return nil
		})
		cancel()
		if !errors.Is(e, ErrRuntime) || reads != at-1 {
			t.Fatal("cancelled inventory accepted", e)
		}
		for _, b := range buffers {
			if !bytes.Equal(b, make([]byte, len(b))) {
				t.Fatal("cancelled inventory retained bytes")
			}
		}
	}
}
