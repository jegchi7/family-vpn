package store

import (
	"context"
	"database/sql"
	"errors"
	"familyvpn.local/platform/internal/agentprotocol"
	"time"
)

// Backoff is bounded, persistent via next_attempt_at. Uncertain work never becomes failed/successful on retry count alone.
func retryDelay(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	if failures >= 6 {
		return time.Minute
	}
	return time.Duration(1<<failures) * time.Second
}
func (c *ControlStore) DeferIntent(ctx context.Context, id string, attempt int, now time.Time, code string) (IntentOperation, error) {
	if !agentprotocol.ValidID(id) || (code != "agent_unavailable" && code != "observation_unconfirmed") {
		return IntentOperation{}, agentprotocol.ErrInvalid
	}
	tx, e := c.intentTx(ctx)
	if e != nil {
		return IntentOperation{}, e
	}
	defer tx.Rollback()
	if e = leaseValid(ctx, tx, id, attempt, now); e != nil {
		return IntentOperation{}, e
	}
	var failures int
	if e = tx.QueryRowContext(ctx, "SELECT consecutive_failures FROM intent_queue WHERE operation_id=?", id).Scan(&failures); e != nil {
		return IntentOperation{}, e
	}
	if failures < 30 {
		failures++
	}
	if _, e = tx.ExecContext(ctx, "UPDATE operations SET state='reconciling',lease_until=NULL WHERE id=?", id); e != nil {
		return IntentOperation{}, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE intent_queue SET lease_deadline=0,next_attempt_at=?,consecutive_failures=?,last_error_code=? WHERE operation_id=?", now.Add(retryDelay(failures)).UnixMilli(), failures, code, id); e != nil {
		return IntentOperation{}, e
	}
	o, e := scanIntent(tx.QueryRowContext(ctx, intentSelect+"WHERE o.id=?", id))
	if e != nil {
		return o, e
	}
	return o, tx.Commit()
}

// Cancellation is idempotent and actor/node scoped. Revocation tombstones are irreversible.
func (c *ControlStore) CancelIntent(ctx context.Context, actor, node, id string) (IntentOperation, error) {
	if !agentprotocol.ValidID(actor) || !agentprotocol.ValidID(node) || !agentprotocol.ValidID(id) {
		return IntentOperation{}, agentprotocol.ErrInvalid
	}
	tx, e := c.intentTx(ctx)
	if e != nil {
		return IntentOperation{}, e
	}
	defer tx.Rollback()
	o, e := scanIntent(tx.QueryRowContext(ctx, intentSelect+"WHERE o.id=? AND o.actor_id=? AND q.node_id=?", id, actor, node))
	if e != nil {
		return o, e
	}
	if o.State == "cancelled" {
		return o, nil
	}
	if o.State != "queued" || o.Attempts != 0 || o.Checkpoint != "intent" || o.ObservedRevision != nil || o.Envelope.Type != agentprotocol.Ensure {
		return IntentOperation{}, ErrConflict
	}
	if _, e = tx.ExecContext(ctx, "UPDATE operations SET state='cancelled',result_code='cancelled_before_apply',finished_at=? WHERE id=?", time.Now().UTC().Format(time.RFC3339Nano), id); e != nil {
		return o, e
	}
	if e = tx.Commit(); e != nil {
		return o, e
	}
	return c.Intent(ctx, id)
}

type IntentPage struct {
	Items      []IntentOperation `json:"items"`
	NextCursor int64             `json:"next_cursor,omitempty"`
}

// Trusted CLI metadata, keyset pagination; actor/key/hash/JSON envelope never serialized.
func (c *ControlStore) ListIntents(ctx context.Context, node, state string, after int64, limit int) (IntentPage, error) {
	p := IntentPage{Items: []IntentOperation{}}
	if !agentprotocol.ValidID(node) || after < 0 || after > 1<<52 || limit < 1 || limit > 100 {
		return p, agentprotocol.ErrInvalid
	}
	switch state {
	case "", "queued", "running", "reconciling", "succeeded", "failed", "cancelled":
	default:
		return p, agentprotocol.ErrInvalid
	}
	rows, e := c.db.QueryContext(ctx, intentSelect+"WHERE q.node_id=? AND q.sequence>? AND (?='' OR o.state=?) ORDER BY q.sequence LIMIT ?", node, after, state, state, limit+1)
	if e != nil {
		return p, e
	}
	defer rows.Close()
	for rows.Next() {
		o, e := scanIntent(rows)
		if e != nil {
			return p, e
		}
		p.Items = append(p.Items, o)
	}
	if e = rows.Err(); e != nil {
		return p, e
	}
	rows.Close()
	if len(p.Items) > limit {
		p.Items = p.Items[:limit]
		e = c.db.QueryRowContext(ctx, "SELECT sequence FROM intent_queue WHERE operation_id=?", p.Items[limit-1].ID).Scan(&p.NextCursor)
		if errors.Is(e, sql.ErrNoRows) {
			return p, ErrNotFound
		}
		if e != nil {
			return p, e
		}
	}
	return p, nil
}
