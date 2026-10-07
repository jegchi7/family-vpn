//go:build linux

package reconciler

import (
	"context"
	"database/sql"
	"errors"
	"familyvpn.local/platform/internal/agentprotocol"
	"familyvpn.local/platform/internal/agenttransport"
	"familyvpn.local/platform/internal/store"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSocketApplyLostResponseThenReconcile(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "private", "control.db")
	c, e := store.OpenControl(ctx, path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if e = c.InitIntentNode(ctx, "ru"); e != nil {
		t.Fatal(e)
	}
	agent, e := store.OpenExistingControl(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer agent.Close()
	dir, e := os.MkdirTemp("", "fvr-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "agent.sock")
	s, e := agenttransport.Listen(socket, uint32(os.Geteuid()), func(ctx context.Context, env agentprotocol.Envelope) (agentprotocol.Result, error) {
		return agent.FakeAgent(ctx, "ru", env)
	})
	if e != nil {
		if errors.Is(e, syscall.EPERM) && os.Getenv("FVPN_REQUIRE_UNIX") == "" {
			t.Skip("sandbox denies AF_UNIX sockets; in-process test covers queue only")
		}
		t.Fatal(e)
	}
	run, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- s.Serve(run) }()
	defer func() { cancel(); s.Close(); <-done }()
	env := agentprotocol.Envelope{SchemaVersion: 1, OperationID: "lost-response", TargetID: "profile", Type: agentprotocol.Ensure, Payload: agentprotocol.Payload{Generation: 1}}
	if _, e = c.EnqueueIntent(ctx, "operator", "one-request", "ru", env); e != nil {
		t.Fatal(e)
	}
	call := func(ctx context.Context, env agentprotocol.Envelope) (agentprotocol.Result, error) {
		return agenttransport.Call(ctx, socket, env)
	}
	o, e := Step(ctx, c, "ru", func(ctx context.Context, env agentprotocol.Envelope) (agentprotocol.Result, error) {
		r, e := call(ctx, env)
		if e != nil {
			return r, e
		}
		return r, io.ErrUnexpectedEOF
	})
	if !errors.Is(e, io.ErrUnexpectedEOF) || o.State != "reconciling" || o.NextAttemptAt == "" {
		t.Fatal(o, e)
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec("UPDATE intent_queue SET lease_deadline=0,next_attempt_at=0"); e != nil {
		t.Fatal(e)
	} // fault-injection only
	restarted, e := store.OpenExistingControl(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.Close()
	o, e = Step(ctx, restarted, "ru", call)
	if e != nil || o.State != "succeeded" || o.Attempts != 2 || o.Checkpoint != "observed" {
		t.Fatal(o, e)
	}
	var count, revision int
	if e = db.QueryRow("SELECT count(*) FROM fake_applied").Scan(&count); e != nil {
		t.Fatal(e)
	}
	if e = db.QueryRow("SELECT revision FROM intent_nodes").Scan(&revision); e != nil {
		t.Fatal(e)
	}
	if count != 1 || revision != 1 {
		t.Fatal("duplicate mutation")
	}
	// A fabricated success without runtime evidence cannot complete the next operation.
	env.OperationID = "forged"
	env.ExpectedRevision = 1
	env.TargetID = "other"
	if _, e = c.EnqueueIntent(ctx, "operator", "second-request", "ru", env); e != nil {
		t.Fatal(e)
	}
	if _, e = Step(ctx, c, "ru", func(ctx context.Context, env agentprotocol.Envelope) (agentprotocol.Result, error) {
		return agentprotocol.Result{OperationID: env.OperationID, State: "succeeded", ResultCode: "applied", ObservedRevision: 2}, nil
	}); !errors.Is(e, store.ErrConflict) {
		t.Fatal("false completion", e)
	}
}
