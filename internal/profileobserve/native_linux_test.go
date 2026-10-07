//go:build linux

package profileobserve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testTarget() Target {
	return Target{Interface: "inventory_awg", Endpoint: "edge.example.invalid:443", ToolSHA256: strings.Repeat("a", 64), BootID: "11111111-2222-3333-4444-555555555555", NetNSDevice: 4, NetNSInode: 12345}
}
func targetEnvironment(t Target) runtimeEnvironment {
	return runtimeEnvironment{BootID: t.BootID, NetNSDevice: t.NetNSDevice, NetNSInode: t.NetNSInode}
}

func TestNativeReadContractDriftAndUnavailable(t *testing.T) {
	c, client, server := sample(t)
	target := testTarget()
	env := func() (runtimeEnvironment, error) { return targetEnvironment(target), nil }
	reads := 0
	var buffers [][]byte
	r, e := observe(context.Background(), c, 2, client, target, func(_ context.Context, iface, pin string) ([]byte, error) {
		if iface != target.Interface || pin != target.ToolSHA256 {
			t.Fatal("bad read request")
		}
		reads++
		b := bytes.Clone(server)
		buffers = append(buffers, b)
		return b, nil
	}, env)
	if e != nil || reads != 2 || !r.Summary().RuntimeObserved || !r.Summary().RuntimeTargetBound || !r.Summary().PeerMatches || r.Summary().Ready || r.Summary().ClientsVerified {
		t.Fatal("read contract", e)
	}
	for _, b := range buffers {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatal("raw readback retained")
		}
	}
	if e = r.Check(c, 2, client, target, r.Summary().MeasuredAt.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	for _, change := range []string{"interface", "endpoint", "tool", "boot", "device", "inode"} {
		wrong := target
		switch change {
		case "interface":
			wrong.Interface = "another_awg"
		case "endpoint":
			wrong.Endpoint = "other.invalid:443"
		case "tool":
			wrong.ToolSHA256 = strings.Repeat("b", 64)
		case "boot":
			wrong.BootID = "22222222-2222-3333-4444-555555555555"
		case "device":
			wrong.NetNSDevice++
		case "inode":
			wrong.NetNSInode++
		}
		if !errors.Is(r.Check(c, 2, client, wrong, r.Summary().MeasuredAt), ErrStale) {
			t.Fatal("target rebound", change)
		}
	}
	encoded, _ := json.Marshal(r)
	for _, out := range []string{string(encoded), fmt.Sprint(r), fmt.Sprintf("%#v", r)} {
		for _, bad := range []string{target.Interface, target.Endpoint, target.ToolSHA256, target.BootID, c.OwnerID, string(client)} {
			if strings.Contains(out, bad) {
				t.Fatal("source/binding leakage")
			}
		}
	}
	var restored Result
	if !errors.Is(json.Unmarshal(encoded, &restored), ErrObservation) || !errors.Is(restored.Check(c, 2, client, target, time.Now()), ErrStale) {
		t.Fatal("JSON restored evidence")
	}
	reads = 0
	_, e = observe(context.Background(), c, 2, client, target, func(context.Context, string, string) ([]byte, error) {
		reads++
		b := bytes.Clone(server)
		if reads == 2 {
			b = append(b, '\n')
		}
		return b, nil
	}, env)
	if !errors.Is(e, ErrDrift) {
		t.Fatal("drift accepted", e)
	}
	_, e = observe(context.Background(), c, 2, client, target, func(context.Context, string, string) ([]byte, error) {
		return nil, errors.New("backend-sensitive-text")
	}, env)
	if !errors.Is(e, ErrRuntime) || strings.Contains(e.Error(), "backend-sensitive-text") {
		t.Fatal("raw error exposed")
	}
	for _, name := range []string{"", "--help", "awg0;exec", "awg/0", "0123456789012345"} {
		if validInterface(name) {
			t.Fatal("unsafe interface accepted")
		}
	}
	buf := &boundedOutput{}
	if _, e = buf.Write(make([]byte, 65537)); !errors.Is(e, ErrRuntime) || len(buf.data) != 0 {
		t.Fatal("unbounded stdout")
	}
	if _, e = readNative(context.Background(), "awg0", strings.Repeat("0", 64)); !errors.Is(e, ErrRuntime) {
		t.Fatal("untrusted tool pin accepted")
	}
}

func TestRuntimeScopeCheckedBeforeBetweenAndAfterReads(t *testing.T) {
	c, client, server := sample(t)
	target := testTarget()
	for _, at := range []int{1, 2, 3} {
		for _, kind := range []string{"boot", "device", "inode", "unavailable"} {
			t.Run(fmt.Sprintf("%s/%d", kind, at), func(t *testing.T) {
				calls, reads := 0, 0
				var buffers [][]byte
				_, e := observe(context.Background(), c, 2, client, target, func(context.Context, string, string) ([]byte, error) {
					reads++
					b := bytes.Clone(server)
					buffers = append(buffers, b)
					return b, nil
				}, func() (runtimeEnvironment, error) {
					calls++
					v := targetEnvironment(target)
					if calls == at {
						switch kind {
						case "boot":
							v.BootID = "22222222-2222-3333-4444-555555555555"
						case "device":
							v.NetNSDevice++
						case "inode":
							v.NetNSInode++
						case "unavailable":
							return v, errors.New("private inventory")
						}
					}
					return v, nil
				})
				if !errors.Is(e, ErrTarget) || reads != at-1 || strings.Contains(e.Error(), "private inventory") {
					t.Fatal("environment scope accepted", e)
				}
				for _, b := range buffers {
					if !bytes.Equal(b, make([]byte, len(b))) {
						t.Fatal("readback not cleared on scope failure")
					}
				}
			})
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e := observe(ctx, c, 2, client, target, func(context.Context, string, string) ([]byte, error) {
		t.Fatal("reader called after cancel")
		return nil, nil
	}, func() (runtimeEnvironment, error) {
		t.Fatal("scope called after cancel")
		return runtimeEnvironment{}, nil
	})
	if !errors.Is(e, ErrRuntime) {
		t.Fatal("cancellation ignored", e)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	_, e = observe(ctx, c, 2, client, target, func(context.Context, string, string) ([]byte, error) { cancel(); return bytes.Clone(server), nil }, func() (runtimeEnvironment, error) { return targetEnvironment(target), nil })
	if !errors.Is(e, ErrRuntime) {
		t.Fatal("cancelled response became proof", e)
	}
	snapshot, e := Snapshot(c, 2, client, server, target.Endpoint)
	if e != nil || snapshot.Summary().RuntimeTargetBound || !errors.Is(snapshot.Check(c, 2, client, target, time.Now()), ErrStale) {
		t.Fatal("snapshot labelled as native target", e)
	}
}

func TestTargetValidationBeforeNativeReader(t *testing.T) {
	c, client, _ := sample(t)
	good := testTarget()
	if !good.Valid() {
		t.Fatal("valid inventory rejected")
	}
	cases := []Target{}
	for _, pin := range []string{"", "pin", strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		v := good
		v.ToolSHA256 = pin
		cases = append(cases, v)
	}
	for _, ep := range []string{"", "host.invalid:0", "http://host.invalid:443", "host.invalid:443\n", "[::%bad]:443"} {
		v := good
		v.Endpoint = ep
		cases = append(cases, v)
	}
	for _, boot := range []string{"", strings.ToUpper("abcdefab-2222-3333-4444-555555555555"), "00000000-0000-0000-0000-000000000000", "11111111-2222-3333-4444-555555555555\n"} {
		v := good
		v.BootID = boot
		cases = append(cases, v)
	}
	v := good
	v.NetNSDevice = 0
	cases = append(cases, v)
	v = good
	v.NetNSInode = 0
	cases = append(cases, v)
	v = good
	v.Interface = "--help"
	cases = append(cases, v)
	for _, v := range cases {
		if v.Valid() {
			t.Fatal("invalid inventory accepted")
		}
		_, e := observe(context.Background(), c, 2, client, v, func(context.Context, string, string) ([]byte, error) {
			t.Fatal("reader before validation")
			return nil, nil
		}, func() (runtimeEnvironment, error) {
			t.Fatal("scope before validation")
			return runtimeEnvironment{}, nil
		})
		if !errors.Is(e, ErrTarget) {
			t.Fatal("invalid target error", e)
		}
	}
}

func TestCurrentThreadEnvironmentReadOnly(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	a, e := currentEnvironment()
	if e != nil {
		t.Fatal("local proc environment unavailable", e)
	}
	b, e := currentEnvironment()
	if e != nil || a != b || !validBootID(a.BootID) {
		t.Fatal("unstable current environment", e)
	}
	st, e := os.Stat("/proc/thread-self/ns/net")
	if e != nil {
		t.Fatal(e)
	}
	ns := st.Sys().(*syscall.Stat_t)
	if a.NetNSDevice != uint64(ns.Dev) || a.NetNSInode != ns.Ino {
		t.Fatal("not current thread namespace")
	}
	c, client, _ := sample(t)
	target := testTarget()
	target.BootID, target.NetNSDevice, target.NetNSInode = a.BootID, a.NetNSDevice, a.NetNSInode+1
	if _, e = Observe(context.Background(), c, 2, client, target); !errors.Is(e, ErrTarget) {
		t.Fatal("native entry did not reject wrong namespace before tool", e)
	}
}
