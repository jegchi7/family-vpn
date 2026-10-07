// Package reconciler runs the synthetic stand; it never opens portal/profile secrets.
package reconciler

import (
	"context"
	"familyvpn.local/platform/internal/agentprotocol"
	"familyvpn.local/platform/internal/store"
	"time"
)

type Call func(context.Context, agentprotocol.Envelope) (agentprotocol.Result, error)

// Step leaves uncertain outcomes under lease for later observed-state reconciliation.
func Step(ctx context.Context, c *store.ControlStore, node string, call Call) (store.IntentOperation, error) {
	return step(ctx, c, node, call, time.Now)
}
func step(ctx context.Context, c *store.ControlStore, node string, call Call, clock func() time.Time) (store.IntentOperation, error) {
	if call == nil {
		return store.IntentOperation{}, agentprotocol.ErrInvalid
	}
	o, e := c.ClaimIntent(ctx, node, clock(), 10*time.Second)
	if e != nil {
		return o, e
	}
	deferWork := func(reason error, code string) (store.IntentOperation, error) {
		// HTTP/worker cancellation does not cancel a persisted operation. Bound only its retry journal write.
		journal, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		delayed, e := c.DeferIntent(journal, o.ID, o.Attempts, clock(), code)
		if e != nil {
			return o, e
		}
		return delayed, reason
	}
	if o.State == "reconciling" {
		read := o.Envelope
		read.Type = agentprotocol.Read
		r, e := call(ctx, read)
		if e != nil {
			return deferWork(e, "agent_unavailable")
		}
		if r.State == "succeeded" || r.State == "failed" {
			if e = c.CompleteFakeIntent(ctx, o.ID, o.Attempts, clock()); e != nil {
				return deferWork(e, "observation_unconfirmed")
			}
			return c.Intent(ctx, o.ID)
		}
		if r.State != "pending" {
			return deferWork(store.ErrConflict, "observation_unconfirmed")
		}
	}
	if e = c.CheckpointIntent(ctx, o.ID, o.Attempts, clock()); e != nil {
		return o, e
	}
	r, e := call(ctx, o.Envelope)
	if e != nil {
		return deferWork(e, "agent_unavailable")
	}
	if r.State != "succeeded" && r.State != "failed" {
		return deferWork(store.ErrConflict, "observation_unconfirmed")
	}
	if e = c.CompleteFakeIntent(ctx, o.ID, o.Attempts, clock()); e != nil {
		return deferWork(e, "observation_unconfirmed")
	}
	return c.Intent(ctx, o.ID)
}
