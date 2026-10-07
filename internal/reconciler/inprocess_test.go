package reconciler

import (
	"context"
	"database/sql"
	"errors"
	"familyvpn.local/platform/internal/agentprotocol"
	"familyvpn.local/platform/internal/store"
	"io"
	"path/filepath"
	"testing"
)

func TestInProcessLostResponseAndForgedSuccess(t *testing.T) {
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
	env := agentprotocol.Envelope{SchemaVersion: 1, OperationID: "lost", TargetID: "profile", Type: agentprotocol.Ensure, Payload: agentprotocol.Payload{Generation: 1}}
	if _, e = c.EnqueueIntent(ctx, "operator", "request", "ru", env); e != nil {
		t.Fatal(e)
	}
	call := func(ctx context.Context, env agentprotocol.Envelope) (agentprotocol.Result, error) {
		return agent.FakeAgent(ctx, "ru", env)
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
	}
	restarted, e := store.OpenExistingControl(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.Close()
	o, e = Step(ctx, restarted, "ru", call)
	if e != nil || o.State != "succeeded" || o.Attempts != 2 || o.Checkpoint != "observed" || o.ObservedRevision == nil || *o.ObservedRevision != 1 {
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
