package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"familyvpn.local/platform/internal/agentprotocol"
)

var ErrIdempotency = errors.New("idempotency conflict")
var ErrLease = errors.New("lease lost")
var ErrRetryLater = errors.New("retry scheduled")

func (c *ControlStore) AssertIntentStand(ctx context.Context, node string) error {
	var n int
	if !agentprotocol.ValidID(node) {
		return agentprotocol.ErrInvalid
	}
	e := c.db.QueryRowContext(ctx, `SELECT count(*) FROM intent_nodes WHERE node_id=? AND EXISTS(SELECT 1 FROM app_metadata WHERE key='dataset' AND value='fake-intents-v1')`, node).Scan(&n)
	if e != nil {
		return e
	}
	if n != 1 {
		return agentprotocol.ErrInvalid
	}
	return nil
}

type IntentOperation struct {
	ID                  string                 `json:"operation_id"`
	NodeID              string                 `json:"node_id"`
	State               string                 `json:"state"`
	ResultCode          string                 `json:"result_code"`
	Attempts            int                    `json:"attempts"`
	Checkpoint          string                 `json:"checkpoint"`
	ObservedRevision    *int64                 `json:"observed_revision,omitempty"`
	NextAttemptAt       string                 `json:"next_attempt_at,omitempty"`
	ConsecutiveFailures int                    `json:"consecutive_failures"`
	LastErrorCode       string                 `json:"last_error_code,omitempty"`
	Envelope            agentprotocol.Envelope `json:"-"`
}

func (c *ControlStore) intentTx(ctx context.Context) (*sql.Tx, error) {
	tx, e := c.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	// Acquire SQLite write lock before read/check: serializes distinct DB handles.
	if _, e = tx.ExecContext(ctx, "UPDATE intent_nodes SET revision=revision WHERE 0"); e != nil {
		tx.Rollback()
		return nil, e
	}
	return tx, nil
}

// Explicit trusted bootstrap; HTTP never calls this or opens control DB.
func (c *ControlStore) InitIntentNode(ctx context.Context, node string) error {
	if !agentprotocol.ValidID(node) {
		return agentprotocol.ErrInvalid
	}
	tx, e := c.intentTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var marker string
	e = tx.QueryRowContext(ctx, "SELECT value FROM app_metadata WHERE key='dataset'").Scan(&marker)
	if errors.Is(e, sql.ErrNoRows) {
		var count int
		if e = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM nodes)+(SELECT count(*) FROM revisions)+(SELECT count(*) FROM operations)+(SELECT count(*) FROM revocations)+(SELECT count(*) FROM audit_events)+(SELECT count(*) FROM app_metadata)`).Scan(&count); e != nil {
			return e
		}
		if count != 0 {
			return agentprotocol.ErrInvalid
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO app_metadata VALUES('dataset','fake-intents-v1')"); e != nil {
			return e
		}
	} else if e != nil {
		return e
	} else if marker != "fake-intents-v1" {
		return agentprotocol.ErrInvalid
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO nodes(id,role) VALUES(?,'ru') ON CONFLICT(id) DO NOTHING", node); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO intent_nodes(node_id) VALUES(?) ON CONFLICT(node_id) DO NOTHING", node); e != nil {
		return e
	}
	return tx.Commit()
}
func intentHash(e agentprotocol.Envelope) (string, string) {
	b, _ := json.Marshal(e)
	copy := e
	copy.OperationID = ""
	content, _ := json.Marshal(copy)
	sum := sha256.Sum256(content)
	return string(b), hex.EncodeToString(sum[:])
}
func scanIntent(row interface{ Scan(...any) error }) (IntentOperation, error) {
	var o IntentOperation
	var envelope string
	var observed sql.NullInt64
	var next int64
	e := row.Scan(&o.ID, &o.NodeID, &o.State, &o.ResultCode, &o.Attempts, &o.Checkpoint, &envelope, &observed, &next, &o.ConsecutiveFailures, &o.LastErrorCode)
	if errors.Is(e, sql.ErrNoRows) {
		return o, ErrNotFound
	}
	if e != nil {
		return o, e
	}
	if json.Unmarshal([]byte(envelope), &o.Envelope) != nil || o.Envelope.Validate() != nil {
		return o, ErrSchema
	}
	if observed.Valid {
		o.ObservedRevision = &observed.Int64
	}
	if next > 0 {
		o.NextAttemptAt = time.UnixMilli(next).UTC().Format(time.RFC3339Nano)
	}
	return o, nil
}

const intentSelect = `SELECT o.id,q.node_id,o.state,COALESCE(o.result_code,''),o.attempts,q.checkpoint,q.envelope_json,(SELECT observed_revision FROM fake_applied f WHERE f.operation_id=o.id AND f.request_hash=o.request_hash AND f.node_id=q.node_id),q.next_attempt_at,q.consecutive_failures,q.last_error_code FROM operations o JOIN intent_queue q ON q.operation_id=o.id `

func (c *ControlStore) Intent(ctx context.Context, id string) (IntentOperation, error) {
	return scanIntent(c.db.QueryRowContext(ctx, intentSelect+"WHERE o.id=?", id))
}

// Enqueue is a trusted intent boundary, not a public request deserializer. Actor/node are fixed by its caller.
func (c *ControlStore) EnqueueIntent(ctx context.Context, actor, key, node string, env agentprotocol.Envelope) (IntentOperation, error) {
	if !agentprotocol.ValidID(actor) || !agentprotocol.ValidID(key) || !agentprotocol.ValidID(node) || env.Validate() != nil || env.Type == agentprotocol.Read {
		return IntentOperation{}, agentprotocol.ErrInvalid
	}
	body, hash := intentHash(env)
	sum := sha256.Sum256([]byte(node + ":" + hash))
	hash = hex.EncodeToString(sum[:])
	tx, e := c.intentTx(ctx)
	if e != nil {
		return IntentOperation{}, e
	}
	defer tx.Rollback()
	var existing, previous string
	e = tx.QueryRowContext(ctx, "SELECT id,request_hash FROM operations WHERE actor_id=? AND idempotency_key=?", actor, key).Scan(&existing, &previous)
	if e == nil {
		if hash != previous {
			return IntentOperation{}, ErrIdempotency
		}
		o, e := scanIntent(tx.QueryRowContext(ctx, intentSelect+"WHERE o.id=?", existing))
		return o, e
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return IntentOperation{}, e
	}
	var revision int64
	e = tx.QueryRowContext(ctx, "SELECT revision FROM intent_nodes WHERE node_id=?", node).Scan(&revision)
	if errors.Is(e, sql.ErrNoRows) {
		return IntentOperation{}, ErrNotFound
	}
	if e != nil {
		return IntentOperation{}, e
	}
	if revision != env.ExpectedRevision {
		return IntentOperation{}, ErrConflict
	}
	if env.Type == agentprotocol.Ensure {
		var n int
		e = tx.QueryRowContext(ctx, "SELECT count(*) FROM intent_revocations WHERE node_id=? AND profile_id=? AND generation=?", node, env.TargetID, env.Payload.Generation).Scan(&n)
		if e != nil {
			return IntentOperation{}, e
		}
		if n > 0 {
			return IntentOperation{}, ErrConflict
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, e = tx.ExecContext(ctx, "INSERT INTO operations(id,actor_id,type,target_id,idempotency_key,request_hash,state,created_at) VALUES(?,?,?,?,?,?,'queued',?)", env.OperationID, actor, env.Type, env.TargetID, key, hash, now); e != nil {
		return IntentOperation{}, e
	}
	priority := 0
	if env.Type == agentprotocol.Revoke {
		priority = 1
		if _, e = tx.ExecContext(ctx, "INSERT INTO intent_revocations VALUES(?,?,?) ON CONFLICT DO NOTHING", node, env.TargetID, env.Payload.Generation); e != nil {
			return IntentOperation{}, e
		}
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO intent_queue(operation_id,node_id,envelope_json,expected_sequence,priority,sequence) VALUES(?,?,?,?,?,(SELECT COALESCE(MAX(sequence),0)+1 FROM intent_queue))`, env.OperationID, node, body, env.ExpectedRevision, priority); e != nil {
		return IntentOperation{}, e
	}
	if e = tx.Commit(); e != nil {
		return IntentOperation{}, e
	}
	return c.Intent(ctx, env.OperationID)
}

// Claim serializes each node. Expired work MUST reconcile before newer work can run.
func (c *ControlStore) ClaimIntent(ctx context.Context, node string, now time.Time, lease time.Duration) (IntentOperation, error) {
	if !agentprotocol.ValidID(node) || lease < time.Second || lease > time.Minute {
		return IntentOperation{}, agentprotocol.ErrInvalid
	}
	tx, e := c.intentTx(ctx)
	if e != nil {
		return IntentOperation{}, e
	}
	defer tx.Rollback()
	var id string
	var deadline, next int64
	e = tx.QueryRowContext(ctx, `SELECT o.id,q.lease_deadline,q.next_attempt_at FROM operations o JOIN intent_queue q ON o.id=q.operation_id WHERE q.node_id=? AND o.state IN ('running','reconciling') ORDER BY q.sequence LIMIT 1`, node).Scan(&id, &deadline, &next)
	state := "running"
	if e == nil {
		if deadline > now.UnixMilli() {
			return IntentOperation{}, ErrLease
		}
		if next > now.UnixMilli() {
			return IntentOperation{}, ErrRetryLater
		}
		state = "reconciling"
	} else if errors.Is(e, sql.ErrNoRows) {
		e = tx.QueryRowContext(ctx, `SELECT o.id FROM operations o JOIN intent_queue q ON o.id=q.operation_id WHERE q.node_id=? AND o.state='queued' ORDER BY q.priority DESC,q.sequence LIMIT 1`, node).Scan(&id)
		if errors.Is(e, sql.ErrNoRows) {
			return IntentOperation{}, ErrNotFound
		}
		if e != nil {
			return IntentOperation{}, e
		}
	} else {
		return IntentOperation{}, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE operations SET state=?,attempts=attempts+1,lease_until=? WHERE id=?", state, now.Add(lease).UTC().Format(time.RFC3339Nano), id); e != nil {
		return IntentOperation{}, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE intent_queue SET lease_deadline=?,next_attempt_at=0 WHERE operation_id=?", now.Add(lease).UnixMilli(), id); e != nil {
		return IntentOperation{}, e
	}
	o, e := scanIntent(tx.QueryRowContext(ctx, intentSelect+"WHERE o.id=?", id))
	if e != nil {
		return o, e
	}
	return o, tx.Commit()
}
func leaseValid(ctx context.Context, tx *sql.Tx, id string, attempt int, now time.Time) error {
	var n int
	e := tx.QueryRowContext(ctx, `SELECT count(*) FROM operations o JOIN intent_queue q ON o.id=q.operation_id WHERE o.id=? AND o.attempts=? AND o.state IN ('running','reconciling') AND q.lease_deadline>?`, id, attempt, now.UnixMilli()).Scan(&n)
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrLease
	}
	return nil
}
func (c *ControlStore) CheckpointIntent(ctx context.Context, id string, attempt int, now time.Time) error {
	tx, e := c.intentTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = leaseValid(ctx, tx, id, attempt, now); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE intent_queue SET checkpoint='before_apply' WHERE operation_id=?", id); e != nil {
		return e
	}
	return tx.Commit()
}

// CompleteFakeIntent verifies durable observed state itself; an arbitrary success response is insufficient.
func (c *ControlStore) CompleteFakeIntent(ctx context.Context, id string, attempt int, now time.Time) error {
	tx, e := c.intentTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = leaseValid(ctx, tx, id, attempt, now); e != nil {
		return e
	}
	var code string
	var revision, current int64
	e = tx.QueryRowContext(ctx, `SELECT f.result_code,f.observed_revision,n.revision FROM fake_applied f JOIN operations o ON o.id=f.operation_id AND o.request_hash=f.request_hash JOIN intent_queue q ON q.operation_id=o.id AND q.node_id=f.node_id JOIN intent_nodes n ON n.node_id=f.node_id WHERE o.id=?`, id).Scan(&code, &revision, &current)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrConflict
	}
	if e != nil {
		return e
	}
	if revision != current {
		return ErrConflict
	}
	state := "succeeded"
	if code != "applied" {
		state = "failed"
	}
	if _, e = tx.ExecContext(ctx, "UPDATE operations SET state=?,result_code=?,finished_at=?,lease_until=NULL WHERE id=?", state, code, now.UTC().Format(time.RFC3339Nano), id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE intent_queue SET checkpoint='observed',lease_deadline=NULL,next_attempt_at=0,consecutive_failures=0,last_error_code='' WHERE operation_id=?", id); e != nil {
		return e
	}
	return tx.Commit()
}
