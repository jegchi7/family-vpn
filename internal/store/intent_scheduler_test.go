package store

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/agentprotocol"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestRetryBackoffPersistsAndFencesReleasedLease(t *testing.T) {
	c, path := queueStand(t)
	ctx := context.Background()
	enqueue(t, c, envelope("retry", "profile", agentprotocol.Ensure, 0))
	now := time.Now()
	o, e := c.ClaimIntent(ctx, "ru", now, 10*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	delayed, e := c.DeferIntent(ctx, o.ID, o.Attempts, now, "agent_unavailable")
	if e != nil || delayed.State != "reconciling" || delayed.ConsecutiveFailures != 1 {
		t.Fatal(delayed, e)
	}
	if _, e = c.ClaimIntent(ctx, "ru", now.Add(time.Second), 10*time.Second); !errors.Is(e, ErrRetryLater) {
		t.Fatal("ignored durable delay", e)
	}
	if _, e = c.DeferIntent(ctx, o.ID, o.Attempts, now, "agent_unavailable"); !errors.Is(e, ErrLease) {
		t.Fatal("old worker rescheduled", e)
	}
	if _, e = c.CancelIntent(ctx, "operator", "ru", o.ID); !errors.Is(e, ErrConflict) {
		t.Fatal("cancelled uncertain work", e)
	}
	reopened, e := OpenExistingControl(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	for failure := 2; failure <= 8; failure++ {
		next, e := time.Parse(time.RFC3339Nano, delayed.NextAttemptAt)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = reopened.ClaimIntent(ctx, "ru", next.Add(-time.Millisecond), 10*time.Second); !errors.Is(e, ErrRetryLater) {
			t.Fatal(e)
		}
		o, e = reopened.ClaimIntent(ctx, "ru", next, 10*time.Second)
		if e != nil || o.State != "reconciling" {
			t.Fatal(o, e)
		}
		delayed, e = reopened.DeferIntent(ctx, o.ID, o.Attempts, next, "agent_unavailable")
		if e != nil {
			t.Fatal(e)
		}
		due, e := time.Parse(time.RFC3339Nano, delayed.NextAttemptAt)
		if e != nil {
			t.Fatal(e)
		}
		want := time.Duration(1<<failure) * time.Second
		if want > time.Minute {
			want = time.Minute
		}
		if due.Sub(next) != want {
			t.Fatal("wrong exponential delay", due.Sub(next), want)
		}
	}
	// Unresolved work retains node serialization even when a revoke has priority.
	enqueue(t, c, envelope("revoke", "other", agentprotocol.Revoke, 0))
	due, _ := time.Parse(time.RFC3339Nano, delayed.NextAttemptAt)
	o, e = c.ClaimIntent(ctx, "ru", due, 10*time.Second)
	if e != nil || o.ID != "retry" {
		t.Fatal("new mutation bypassed uncertain operation", o, e)
	}
	if _, e = c.DeferIntent(ctx, o.ID, o.Attempts, due, "raw arbitrary error"); !errors.Is(e, agentprotocol.ErrInvalid) {
		t.Fatal("stored arbitrary error", e)
	}
}
func TestCancellationOwnershipReplayAndRevokeProtection(t *testing.T) {
	c, _ := queueStand(t)
	ctx := context.Background()
	env := envelope("cancel", "profile", agentprotocol.Ensure, 0)
	enqueue(t, c, env)
	if _, e := c.CancelIntent(ctx, "someone-else", "ru", env.OperationID); !errors.Is(e, ErrNotFound) {
		t.Fatal(e)
	}
	if _, e := c.CancelIntent(ctx, "operator", "foreign", env.OperationID); !errors.Is(e, ErrNotFound) {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		o, e := c.CancelIntent(ctx, "operator", "ru", env.OperationID)
		if e != nil || o.State != "cancelled" || o.Attempts != 0 || o.ResultCode != "cancelled_before_apply" {
			t.Fatal(o, e)
		}
	}
	o, e := c.EnqueueIntent(ctx, "operator", env.OperationID, "ru", env)
	if e != nil || o.State != "cancelled" {
		t.Fatal("retry resurrected cancellation", o, e)
	}
	if _, e = c.ClaimIntent(ctx, "ru", time.Now(), 10*time.Second); !errors.Is(e, ErrNotFound) {
		t.Fatal(e)
	}
	enqueue(t, c, envelope("revocation", "revoked-profile", agentprotocol.Revoke, 0))
	if _, e = c.CancelIntent(ctx, "operator", "ru", "revocation"); !errors.Is(e, ErrConflict) {
		t.Fatal("revoke cancellation allowed", e)
	}
	restore := envelope("restore", "revoked-profile", agentprotocol.Ensure, 0)
	if _, e = c.EnqueueIntent(ctx, "operator", "restore", "ru", restore); !errors.Is(e, ErrConflict) {
		t.Fatal("tombstone forgotten", e)
	}
}
func TestCancelVersusClaimAcrossDBHandles(t *testing.T) {
	ctx := context.Background()
	for i := 0; i < 8; i++ {
		c, path := queueStand(t)
		other, e := OpenExistingControl(ctx, path)
		if e != nil {
			t.Fatal(e)
		}
		enqueue(t, c, envelope("race", "profile", agentprotocol.Ensure, 0))
		start := make(chan struct{})
		var claimErr, cancelErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; _, claimErr = c.ClaimIntent(ctx, "ru", time.Now(), 10*time.Second) }()
		go func() { defer wg.Done(); <-start; _, cancelErr = other.CancelIntent(ctx, "operator", "ru", "race") }()
		close(start)
		wg.Wait()
		other.Close()
		if claimErr == nil {
			if !errors.Is(cancelErr, ErrConflict) {
				t.Fatal("cancel beat active claim", cancelErr)
			}
		} else if cancelErr == nil {
			if !errors.Is(claimErr, ErrNotFound) {
				t.Fatal("claimed cancelled operation", claimErr)
			}
		} else {
			t.Fatal(claimErr, cancelErr)
		}
	}
}
func TestBoundedOperationPagesDoNotExposeEnvelope(t *testing.T) {
	c, _ := queueStand(t)
	ctx := context.Background()
	for _, id := range []string{"z", "a", "m"} {
		enqueue(t, c, envelope(id, "profile-"+id, agentprotocol.Ensure, 0))
	}
	if _, e := c.CancelIntent(ctx, "operator", "ru", "a"); e != nil {
		t.Fatal(e)
	}
	if e := c.InitIntentNode(ctx, "foreign"); e != nil {
		t.Fatal(e)
	}
	if _, e := c.EnqueueIntent(ctx, "operator", "other-node", "foreign", envelope("foreign-operation", "profile", agentprotocol.Ensure, 0)); e != nil {
		t.Fatal(e)
	}
	p, e := c.ListIntents(ctx, "ru", "queued", 0, 1)
	if e != nil || len(p.Items) != 1 || p.Items[0].ID != "z" || p.NextCursor == 0 {
		t.Fatal(p, e)
	}
	second, e := c.ListIntents(ctx, "ru", "queued", p.NextCursor, 1)
	if e != nil || len(second.Items) != 1 || second.Items[0].ID != "m" || second.NextCursor != 0 {
		t.Fatal(second, e)
	}
	b, _ := json.Marshal(p)
	var dto map[string]json.RawMessage
	json.Unmarshal(b, &dto)
	var items []map[string]json.RawMessage
	json.Unmarshal(dto["items"], &items)
	allowed := map[string]bool{"operation_id": true, "node_id": true, "state": true, "result_code": true, "attempts": true, "checkpoint": true, "observed_revision": true, "next_attempt_at": true, "consecutive_failures": true, "last_error_code": true}
	for key := range items[0] {
		if !allowed[key] {
			t.Fatal("unsafe metadata field", key)
		}
	}
	for _, limit := range []int{0, 101} {
		if _, e = c.ListIntents(ctx, "ru", "", 0, limit); !errors.Is(e, agentprotocol.ErrInvalid) {
			t.Fatal(e)
		}
	}
	if _, e = c.ListIntents(ctx, "ru", "arbitrary", 0, 25); !errors.Is(e, agentprotocol.ErrInvalid) {
		t.Fatal(e)
	}
	if _, e = c.ListIntents(ctx, "ru", "", -1, 25); !errors.Is(e, agentprotocol.ErrInvalid) {
		t.Fatal(e)
	}
}
func TestSchedulerMigrationPreservesV3PendingIntent(t *testing.T) {
	c, path := queueStand(t)
	ctx := context.Background()
	enqueue(t, c, envelope("upgrade", "profile", agentprotocol.Ensure, 0))
	// Reconstruct pre-scheduler schema3 using only test DDL; migration1..3 hashes stay intact.
	for _, col := range []string{"next_attempt_at", "consecutive_failures", "last_error_code"} {
		if _, e := c.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE intent_queue DROP COLUMN %s", col)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := c.db.ExecContext(ctx, "DELETE FROM schema_migrations WHERE version=4"); e != nil {
		t.Fatal(e)
	}
	if _, e := c.db.ExecContext(ctx, "PRAGMA user_version=3"); e != nil {
		t.Fatal(e)
	}
	c.Close()
	if db, e := OpenExistingControl(ctx, path); e == nil {
		db.Close()
		t.Fatal("implicit runtime migration")
	}
	upgraded, e := OpenControl(ctx, path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer upgraded.Close()
	o, e := upgraded.Intent(ctx, "upgrade")
	if e != nil || o.State != "queued" || o.ConsecutiveFailures != 0 || o.NextAttemptAt != "" || o.LastErrorCode != "" {
		t.Fatal(o, e)
	}
}
