package reconciler

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/agentprotocol"
	"familyvpn.local/platform/internal/store"
	"io"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func workerStand(t *testing.T) (*store.ControlStore, string, agentprotocol.Envelope) {
	t.Helper()
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "private", "control.db")
	c, e := store.OpenControl(ctx, p, false)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	if e = c.InitIntentNode(ctx, "ru"); e != nil {
		t.Fatal(e)
	}
	env := agentprotocol.Envelope{SchemaVersion: 1, OperationID: "operation", TargetID: "profile", Type: agentprotocol.Ensure, Payload: agentprotocol.Payload{Generation: 1}}
	if _, e = c.EnqueueIntent(ctx, "operator", "request", "ru", env); e != nil {
		t.Fatal(e)
	}
	return c, p, env
}
func TestScheduledRetryObservesBeforeApplyingAfterLostResponse(t *testing.T) {
	c, path, _ := workerStand(t)
	ctx := context.Background()
	now := time.Now()
	clock := func() time.Time { return now }
	var applies, reads int
	call := func(ctx context.Context, env agentprotocol.Envelope) (agentprotocol.Result, error) {
		if env.Type == agentprotocol.Read {
			reads++
		} else {
			applies++
		}
		r, e := c.FakeAgent(ctx, "ru", env)
		if e != nil {
			return r, e
		}
		if env.Type != agentprotocol.Read {
			return r, io.ErrUnexpectedEOF
		}
		return r, nil
	}
	delayed, e := step(ctx, c, "ru", call, clock)
	if !errors.Is(e, io.ErrUnexpectedEOF) || delayed.NextAttemptAt == "" {
		t.Fatal(delayed, e)
	}
	restarted, e := store.OpenExistingControl(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.Close()
	if _, e = step(ctx, restarted, "ru", call, clock); !errors.Is(e, store.ErrRetryLater) {
		t.Fatal(e)
	}
	now, _ = time.Parse(time.RFC3339Nano, delayed.NextAttemptAt)
	o, e := step(ctx, restarted, "ru", call, clock)
	if e != nil || o.State != "succeeded" || o.NextAttemptAt != "" || o.ConsecutiveFailures != 0 || o.LastErrorCode != "" || applies != 1 || reads != 1 {
		t.Fatal(o, e, applies, reads)
	}
}
func TestForegroundWorkersSerializeAndShutdown(t *testing.T) {
	c, path, _ := workerStand(t)
	other, e := store.OpenExistingControl(context.Background(), path)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var applied atomic.Int32
	call := func(ctx context.Context, env agentprotocol.Envelope) (agentprotocol.Result, error) {
		if env.Type != agentprotocol.Read {
			applied.Add(1)
		}
		return c.FakeAgent(ctx, "ru", env)
	}
	report := func(o store.IntentOperation) {
		if o.State == "succeeded" {
			cancel()
		}
	}
	done := make(chan error, 2)
	for _, db := range []*store.ControlStore{c, other} {
		go func(db *store.ControlStore) {
			done <- Run(ctx, db, "ru", call, WorkerOptions{PollInterval: 100 * time.Millisecond, Report: report})
		}(db)
	}
	for i := 0; i < 2; i++ {
		select {
		case e := <-done:
			if e != nil {
				t.Fatal(e)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("worker failed to stop")
		}
	}
	if applied.Load() != 1 {
		t.Fatal("parallel apply", applied.Load())
	}
	o, e := c.Intent(context.Background(), "operation")
	if e != nil || o.State != "succeeded" {
		t.Fatal(o, e)
	}
}
func TestWorkerUnavailableAgentIsDurableAndDoesNotLeakError(t *testing.T) {
	c, _, _ := workerStand(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	var report store.IntentOperation
	e := Run(ctx, c, "ru", func(ctx context.Context, env agentprotocol.Envelope) (agentprotocol.Result, error) {
		calls.Add(1)
		return agentprotocol.Result{}, errors.New("private raw backend details")
	}, WorkerOptions{PollInterval: 100 * time.Millisecond, Report: func(o store.IntentOperation) { report = o; cancel() }})
	if e != nil || calls.Load() != 1 || report.State != "reconciling" || report.NextAttemptAt == "" || report.LastErrorCode != "agent_unavailable" {
		t.Fatal(report, e)
	}
	b, _ := json.Marshal(report)
	if strings.Contains(string(b), "private raw") || strings.Contains(string(b), "envelope") {
		t.Fatal("unsafe error payload")
	}
}
func TestCancelledCallStillJournalsUncertainty(t *testing.T) {
	c, _, _ := workerStand(t)
	ctx, cancel := context.WithCancel(context.Background())
	o, e := Step(ctx, c, "ru", func(ctx context.Context, env agentprotocol.Envelope) (agentprotocol.Result, error) {
		cancel()
		return agentprotocol.Result{}, context.Canceled
	})
	if !errors.Is(e, context.Canceled) || o.State != "reconciling" || o.NextAttemptAt == "" {
		t.Fatal(o, e)
	}
	persisted, e := c.Intent(context.Background(), o.ID)
	if e != nil || persisted.State != "reconciling" {
		t.Fatal(persisted, e)
	}
}
