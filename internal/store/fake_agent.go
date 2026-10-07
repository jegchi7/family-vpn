package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"familyvpn.local/platform/internal/agentprotocol"
)

// FakeAgent executes ONLY synthetic metadata. Runtime/queue share a DB in this stand;
// this deliberately does not model production privilege separation or network atomicity.
func (c *ControlStore) FakeAgent(ctx context.Context, node string, env agentprotocol.Envelope) (agentprotocol.Result, error) {
	r := agentprotocol.Result{OperationID: env.OperationID, State: "pending", ResultCode: "not_observed"}
	if env.Validate() != nil {
		return r, agentprotocol.ErrInvalid
	}
	tx, e := c.intentTx(ctx)
	if e != nil {
		return r, e
	}
	defer tx.Rollback()
	o, e := scanIntent(tx.QueryRowContext(ctx, intentSelect+"WHERE o.id=?", env.OperationID))
	if e != nil {
		return r, e
	}
	compare := env
	if env.Type == agentprotocol.Read {
		compare.Type = o.Envelope.Type
	}
	if o.NodeID != node || compare != o.Envelope {
		return r, agentprotocol.ErrInvalid
	}
	e = tx.QueryRowContext(ctx, "SELECT revision FROM intent_nodes WHERE node_id=?", node).Scan(&r.ObservedRevision)
	if e != nil {
		return r, e
	}
	var hash string
	if e = tx.QueryRowContext(ctx, "SELECT request_hash FROM operations WHERE id=?", o.ID).Scan(&hash); e != nil {
		return r, e
	}
	var code string
	var observed int64
	e = tx.QueryRowContext(ctx, "SELECT result_code,observed_revision FROM fake_applied WHERE operation_id=? AND request_hash=?", o.ID, hash).Scan(&code, &observed)
	if e == nil {
		r.State = "succeeded"
		if code != "applied" {
			r.State = "failed"
		}
		r.ResultCode = code
		r.ObservedRevision = observed
		return r, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return r, e
	}
	if env.Type == agentprotocol.Read {
		return r, nil
	}
	if e = leaseValid(ctx, tx, o.ID, o.Attempts, time.Now()); e != nil {
		return r, e
	}
	if o.Checkpoint != "before_apply" {
		return r, ErrConflict
	}
	code = "applied"
	var revoked int
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM intent_revocations WHERE node_id=? AND profile_id=? AND generation=?", node, env.TargetID, env.Payload.Generation).Scan(&revoked); e != nil {
		return r, e
	}
	if env.Type == agentprotocol.Ensure && revoked > 0 {
		code = "revoked"
	} else if env.Type == agentprotocol.Ensure && env.ExpectedRevision != r.ObservedRevision {
		code = "revision_conflict"
	}
	if code == "applied" {
		active := 1
		if env.Type == agentprotocol.Revoke {
			active = 0
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO fake_peers VALUES(?,?,?,?) ON CONFLICT(node_id,profile_id,generation) DO UPDATE SET active=excluded.active", node, env.TargetID, env.Payload.Generation, active); e != nil {
			return r, e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE intent_nodes SET revision=revision+1 WHERE node_id=?", node); e != nil {
			return r, e
		}
		r.ObservedRevision++
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO fake_applied VALUES(?,?,?,?,?)", o.ID, node, hash, r.ObservedRevision, code); e != nil {
		return r, e
	}
	if e = tx.Commit(); e != nil {
		return r, e
	}
	r.State = "succeeded"
	if code != "applied" {
		r.State = "failed"
	}
	r.ResultCode = code
	return r, nil
}
