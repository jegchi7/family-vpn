//go:build linux

package agenttransport

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/agentprotocol"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

func transportEnv() agentprotocol.Envelope {
	return agentprotocol.Envelope{SchemaVersion: 1, OperationID: "op", Type: agentprotocol.Ensure, TargetID: "profile", Payload: agentprotocol.Payload{Generation: 1}}
}
func testServer(t *testing.T, uid uint32, h Handler) string {
	t.Helper()
	dir, e := os.MkdirTemp("", "fva-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "agent.sock")
	s, e := Listen(path, uid, h)
	if e != nil {
		if errors.Is(e, syscall.EPERM) && os.Getenv("FVPN_REQUIRE_UNIX") == "" {
			t.Skip("sandbox denies AF_UNIX sockets; must run Linux transport acceptance separately")
		}
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	t.Cleanup(func() { cancel(); s.Close(); <-done })
	return path
}
func TestPeerUIDAndStrictSocketBody(t *testing.T) {
	var calls atomic.Int32
	h := func(ctx context.Context, e agentprotocol.Envelope) (agentprotocol.Result, error) {
		calls.Add(1)
		return agentprotocol.Result{OperationID: e.OperationID, State: "succeeded", ResultCode: "applied", ObservedRevision: 1}, nil
	}
	path := testServer(t, uint32(os.Geteuid()), h)
	r, e := Call(context.Background(), path, transportEnv())
	if e != nil || r.State != "succeeded" {
		t.Fatal(r, e)
	}
	denied := testServer(t, uint32(os.Geteuid()+1), h)
	if _, e = Call(context.Background(), denied, transportEnv()); e == nil {
		t.Fatal("unauthorized peer UID allowed")
	}
	if calls.Load() != 1 {
		t.Fatal("denied UID reached handler")
	}
	b, _ := json.Marshal(transportEnv())
	bad := strings.Replace(string(b), `"payload":`, `"command":"anything","payload":`, 1)
	for _, body := range []string{bad, string(b) + strings.Repeat(" ", agentprotocol.MaxBody)} {
		c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if e != nil {
			t.Fatal(e)
		}
		_, _ = c.Write([]byte(body))
		_ = c.CloseWrite()
		out, _ := io.ReadAll(c)
		c.Close()
		if !strings.Contains(string(out), "invalid_intent") {
			t.Fatal("invalid socket body accepted")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("invalid body reached handler")
	}
	if _, e = Listen(path, uint32(os.Geteuid()), h); e == nil {
		t.Fatal("existing socket replaced")
	}
	alias := filepath.Join(filepath.Dir(path), "alias")
	if e = os.Symlink(filepath.Dir(path), alias); e != nil {
		t.Fatal(e)
	}
	if _, e = Listen(filepath.Join(alias, "another.sock"), uint32(os.Geteuid()), h); e == nil {
		t.Fatal("symlink parent accepted")
	}
}
