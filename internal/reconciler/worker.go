package reconciler

import (
	"context"
	"errors"
	"familyvpn.local/platform/internal/agentprotocol"
	"familyvpn.local/platform/internal/store"
	"time"
)

type WorkerOptions struct {
	PollInterval time.Duration
	Report       func(store.IntentOperation)
}

// Run is foreground, one node per worker. Parallel workers are serialized by durable claims.
func Run(ctx context.Context, c *store.ControlStore, node string, call Call, options WorkerOptions) error {
	poll := options.PollInterval
	if poll == 0 {
		poll = 500 * time.Millisecond
	}
	if c == nil || call == nil || poll < 100*time.Millisecond || poll > 5*time.Second || !agentprotocol.ValidID(node) {
		return agentprotocol.ErrInvalid
	}
	if e := c.AssertIntentStand(ctx, node); e != nil {
		if ctx.Err() != nil {
			return nil
		}
		return e
	}
	for {
		if ctx.Err() != nil {
			return nil
		}
		bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
		o, e := Step(bounded, c, node, call)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		switch {
		case e == nil:
			if options.Report != nil {
				options.Report(o)
			}
		case o.ID != "" && o.State == "reconciling" && o.NextAttemptAt != "":
			if options.Report != nil {
				options.Report(o)
			}
		case errors.Is(e, store.ErrNotFound) && o.ID == "", errors.Is(e, store.ErrLease), errors.Is(e, store.ErrRetryLater):
		default:
			return e
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
