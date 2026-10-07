package store

import (
	"context"
	"errors"
	"familyvpn.local/platform/internal/agentprotocol"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func queueStand(t *testing.T) (*ControlStore, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "private", "control.db")
	c, e := OpenControl(context.Background(), p, false)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	if e = c.InitIntentNode(context.Background(), "ru"); e != nil {
		t.Fatal(e)
	}
	return c, p
}
func envelope(id, target, kind string, revision int64) agentprotocol.Envelope {
	return agentprotocol.Envelope{SchemaVersion: 1, OperationID: id, TargetID: target, Type: kind, ExpectedRevision: revision, Payload: agentprotocol.Payload{Generation: 1}}
}
func enqueue(t *testing.T, c *ControlStore, e agentprotocol.Envelope) {
	t.Helper()
	if _, err := c.EnqueueIntent(context.Background(), "operator", e.OperationID, "ru", e); err != nil {
		t.Fatal(err)
	}
}
func apply(t *testing.T, c *ControlStore, o IntentOperation) {
	t.Helper()
	ctx := context.Background()
	if e := c.CheckpointIntent(ctx, o.ID, o.Attempts, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e := c.FakeAgent(ctx, "ru", o.Envelope); e != nil {
		t.Fatal(e)
	}
}
func TestQueueConcurrentIdempotencyAndNodeSerialization(t *testing.T) {
	c, p := queueStand(t)
	ctx := context.Background()
	other, e := OpenExistingControl(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	env := envelope("first", "profile", agentprotocol.Ensure, 0)
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	ids := make(chan string, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			db := c
			if i%2 == 1 {
				db = other
			}
			copy := env
			copy.OperationID = string(rune('a' + i))
			o, e := db.EnqueueIntent(ctx, "operator", "one-request", "ru", copy)
			errs <- e
			ids <- o.ID
		}(i)
	}
	wg.Wait()
	close(errs)
	close(ids)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var id string
	for got := range ids {
		if id == "" {
			id = got
		}
		if got != id {
			t.Fatal("duplicate operation")
		}
	}
	changed := env
	changed.TargetID = "different"
	if _, e = c.EnqueueIntent(ctx, "operator", "one-request", "ru", changed); !errors.Is(e, ErrIdempotency) {
		t.Fatal(e)
	}
	claims := make(chan error, 2)
	for _, db := range []*ControlStore{c, other} {
		wg.Add(1)
		go func(db *ControlStore) {
			defer wg.Done()
			_, e := db.ClaimIntent(ctx, "ru", time.Now(), 5*time.Second)
			claims <- e
		}(db)
	}
	wg.Wait()
	close(claims)
	success, busy := 0, 0
	for e := range claims {
		if e == nil {
			success++
		} else if errors.Is(e, ErrLease) {
			busy++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || busy != 1 {
		t.Fatal("concurrent node execution")
	}
	if _, e = c.EnqueueIntent(ctx, "operator", "same-request-other-node", "missing", env); !errors.Is(e, ErrNotFound) {
		t.Fatal(e)
	}
}
func TestCrashReconcileRequiresObservationAndFencesOldAttempt(t *testing.T) {
	c, p := queueStand(t)
	ctx := context.Background()
	env := envelope("crash", "profile", agentprotocol.Ensure, 0)
	enqueue(t, c, env)
	first, e := c.ClaimIntent(ctx, "ru", time.Now(), 5*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.CompleteFakeIntent(ctx, first.ID, first.Attempts, time.Now()); !errors.Is(e, ErrConflict) {
		t.Fatal("unobserved success", e)
	}
	apply(t, c, first) // Simulate runtime commit then response/process loss before queue completion.
	if _, e = c.db.ExecContext(ctx, "UPDATE intent_queue SET lease_deadline=0 WHERE operation_id=?", first.ID); e != nil {
		t.Fatal(e)
	}
	restarted, e := OpenExistingControl(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.Close()
	recovered, e := restarted.ClaimIntent(ctx, "ru", time.Now(), 5*time.Second)
	if e != nil || recovered.State != "reconciling" {
		t.Fatal(recovered, e)
	}
	if e = c.CompleteFakeIntent(ctx, first.ID, first.Attempts, time.Now()); !errors.Is(e, ErrLease) {
		t.Fatal("old attempt was not fenced", e)
	}
	read := env
	read.Type = agentprotocol.Read
	r, e := restarted.FakeAgent(ctx, "ru", read)
	if e != nil || r.State != "succeeded" || r.ObservedRevision != 1 {
		t.Fatal(r, e)
	}
	if e = restarted.CompleteFakeIntent(ctx, recovered.ID, recovered.Attempts, time.Now()); e != nil {
		t.Fatal(e)
	}
	// Replay old runtime request returns the durable result without another mutation.
	r, e = restarted.FakeAgent(ctx, "ru", env)
	if e != nil || r.ObservedRevision != 1 {
		t.Fatal(r, e)
	}
	var n int
	restarted.db.QueryRowContext(ctx, "SELECT count(*) FROM fake_applied").Scan(&n)
	if n != 1 {
		t.Fatal("duplicate apply")
	}
	stale := envelope("stale", "another", agentprotocol.Ensure, 0)
	if _, e = restarted.EnqueueIntent(ctx, "operator", "stale", "ru", stale); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	// Original idempotency key still resolves after the node revision changed.
	o, e := restarted.EnqueueIntent(ctx, "operator", "crash", "ru", env)
	if e != nil || o.State != "succeeded" {
		t.Fatal(o, e)
	}
}
func TestExpiredBeforeApplyAndRevokePriority(t *testing.T) {
	c, _ := queueStand(t)
	ctx := context.Background()
	env := envelope("ensure", "profile", agentprotocol.Ensure, 0)
	enqueue(t, c, env)
	old := time.Now().Add(-10 * time.Second)
	o, e := c.ClaimIntent(ctx, "ru", old, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.CheckpointIntent(ctx, o.ID, o.Attempts, old); e != nil {
		t.Fatal(e)
	}
	if _, e = c.FakeAgent(ctx, "ru", env); !errors.Is(e, ErrLease) {
		t.Fatal("expired apply accepted", e)
	}
	r, e := c.ClaimIntent(ctx, "ru", time.Now(), 5*time.Second)
	if e != nil || r.State != "reconciling" {
		t.Fatal(r, e)
	}
	apply(t, c, r)
	if e = c.CompleteFakeIntent(ctx, r.ID, r.Attempts, time.Now()); e != nil {
		t.Fatal(e)
	}
	// A running apply finishes first; revoke is selected ahead of a queued issuance.
	enqueue(t, c, envelope("later", "other", agentprotocol.Ensure, 1))
	enqueue(t, c, envelope("revoke", "profile", agentprotocol.Revoke, 1))
	next, e := c.ClaimIntent(ctx, "ru", time.Now(), 5*time.Second)
	if e != nil || next.ID != "revoke" {
		t.Fatal(next, e)
	}
	apply(t, c, next)
	if e = c.CompleteFakeIntent(ctx, next.ID, next.Attempts, time.Now()); e != nil {
		t.Fatal(e)
	}
	var active int
	if e = c.db.QueryRowContext(ctx, "SELECT active FROM fake_peers WHERE profile_id='profile'").Scan(&active); e != nil || active != 0 {
		t.Fatal("peer restored", e)
	}
	blocked := envelope("restore", "profile", agentprotocol.Ensure, 2)
	if _, e = c.EnqueueIntent(ctx, "operator", "restore", "ru", blocked); !errors.Is(e, ErrConflict) {
		t.Fatal("tombstone ignored", e)
	}
	queued, e := c.ClaimIntent(ctx, "ru", time.Now(), 5*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	apply(t, c, queued)
	if e = c.CompleteFakeIntent(ctx, queued.ID, queued.Attempts, time.Now()); e != nil {
		t.Fatal(e)
	}
	result, e := c.Intent(ctx, queued.ID)
	if e != nil || result.ResultCode != "revision_conflict" || result.State != "failed" {
		t.Fatal(result, e)
	}
	if _, e = c.db.ExecContext(ctx, "DELETE FROM intent_revocations"); e == nil {
		t.Fatal("mutable tombstone")
	}
}
func TestRevokeSuppressesQueuedEnsureAndSurvivesRevisionChange(t *testing.T) {
	c, _ := queueStand(t)
	ctx := context.Background()
	enqueue(t, c, envelope("running", "unrelated", agentprotocol.Ensure, 0))
	running, e := c.ClaimIntent(ctx, "ru", time.Now(), 5*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	enqueue(t, c, envelope("ensure", "profile", agentprotocol.Ensure, 0))
	enqueue(t, c, envelope("revoke", "profile", agentprotocol.Revoke, 0))
	apply(t, c, running)
	if e = c.CompleteFakeIntent(ctx, running.ID, running.Attempts, time.Now()); e != nil {
		t.Fatal(e)
	}
	revoke, e := c.ClaimIntent(ctx, "ru", time.Now(), 5*time.Second)
	if e != nil || revoke.ID != "revoke" {
		t.Fatal(revoke, e)
	}
	apply(t, c, revoke)
	if e = c.CompleteFakeIntent(ctx, revoke.ID, revoke.Attempts, time.Now()); e != nil {
		t.Fatal(e)
	}
	ensure, e := c.ClaimIntent(ctx, "ru", time.Now(), 5*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	apply(t, c, ensure)
	if e = c.CompleteFakeIntent(ctx, ensure.ID, ensure.Attempts, time.Now()); e != nil {
		t.Fatal(e)
	}
	o, e := c.Intent(ctx, ensure.ID)
	if e != nil || o.State != "failed" || o.ResultCode != "revoked" {
		t.Fatal(o, e)
	}
}
func TestAgentRefusesUnqueuedOrAlteredIntent(t *testing.T) {
	c, _ := queueStand(t)
	ctx := context.Background()
	env := envelope("queued", "profile", agentprotocol.Ensure, 0)
	if _, e := c.FakeAgent(ctx, "ru", env); !errors.Is(e, ErrNotFound) {
		t.Fatal(e)
	}
	enqueue(t, c, env)
	o, e := c.ClaimIntent(ctx, "ru", time.Now(), 5*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.CheckpointIntent(ctx, o.ID, o.Attempts, time.Now()); e != nil {
		t.Fatal(e)
	}
	env.TargetID = "altered"
	if _, e = c.FakeAgent(ctx, "ru", env); !errors.Is(e, agentprotocol.ErrInvalid) {
		t.Fatal(e)
	}
}

func TestIntentBootstrapDoesNotAdoptDemoOrExistingControl(t *testing.T) {
	ctx := context.Background()
	for _, demo := range []bool{false, true} {
		c, e := OpenControl(ctx, filepath.Join(t.TempDir(), "private", "control.db"), false)
		if e != nil {
			t.Fatal(e)
		}
		if demo {
			e = c.SeedDemo(ctx)
		} else {
			e = c.RecordRevocation(ctx, "existing-profile", 1, "existing")
		}
		if e != nil {
			c.Close()
			t.Fatal(e)
		}
		if e = c.InitIntentNode(ctx, "ru"); !errors.Is(e, agentprotocol.ErrInvalid) {
			c.Close()
			t.Fatal("adopted non-stand DB", e)
		}
		c.Close()
	}
	c, _ := queueStand(t)
	if e := c.InitIntentNode(ctx, "foreign"); e != nil {
		t.Fatal(e)
	}
	enqueue(t, c, envelope("ru-op", "profile", agentprotocol.Ensure, 0))
	env := envelope("foreign-op", "profile", agentprotocol.Ensure, 0)
	if _, e := c.EnqueueIntent(ctx, "operator", "foreign-request", "foreign", env); e != nil {
		t.Fatal(e)
	}
	if _, e := c.ClaimIntent(ctx, "ru", time.Now(), 5*time.Second); e != nil {
		t.Fatal(e)
	}
	if _, e := c.ClaimIntent(ctx, "foreign", time.Now(), 5*time.Second); e != nil {
		t.Fatal("independent node blocked", e)
	}
	if _, e := c.EnqueueIntent(ctx, "operator", "ru-op", "foreign", env); !errors.Is(e, ErrIdempotency) {
		t.Fatal("node excluded from request hash", e)
	}
}
