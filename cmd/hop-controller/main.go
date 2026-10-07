// This entry point still performs no hop selection; opt-in mode exercises the intent queue.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/agentprotocol"
	"familyvpn.local/platform/internal/agenttransport"
	"familyvpn.local/platform/internal/reconciler"
	"familyvpn.local/platform/internal/store"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if e := run(); e != nil {
		code := "stand_unavailable"
		switch {
		case errors.Is(e, store.ErrConflict):
			code = "revision_conflict"
		case errors.Is(e, store.ErrIdempotency):
			code = "idempotency_conflict"
		case errors.Is(e, store.ErrLease):
			code = "node_busy"
		case errors.Is(e, store.ErrRetryLater):
			code = "retry_scheduled"
		case errors.Is(e, store.ErrNotFound):
			code = "not_found"
		case errors.Is(e, agentprotocol.ErrInvalid):
			code = "invalid_intent"
		}
		fmt.Fprintln(os.Stderr, code)
		os.Exit(2)
	}
}
func run() error {
	stand := flag.Bool("fake-stand", false, "required: synthetic metadata only")
	command := flag.String("command", "", "init, enqueue, status, list, cancel, step or worker")
	db := flag.String("control-db", "var/control-stand/control.db", "private stand database")
	socket := flag.String("socket", "", "absolute node-agent socket path")
	node := flag.String("node", "stand-ru", "fixed node ID")
	key := flag.String("idempotency-key", "", "opaque non-secret request ID")
	id := flag.String("operation-id", "", "status operation ID")
	after := flag.Int64("after", 0, "list sequence cursor")
	limit := flag.Int("limit", 25, "list page size, 1..100")
	state := flag.String("state", "", "optional list state filter")
	poll := flag.Int("poll-ms", 500, "worker poll interval, 100..5000 milliseconds")
	flag.Parse()
	if !*stand || flag.NArg() != 0 || !agentprotocol.ValidID(*node) {
		return agentprotocol.ErrInvalid
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var c *store.ControlStore
	var e error
	if *command == "init" {
		c, e = store.OpenControl(ctx, *db, false)
	} else {
		c, e = store.OpenExistingControl(ctx, *db)
	}
	if e != nil {
		return e
	}
	defer c.Close()
	if *command != "init" {
		if e = c.AssertIntentStand(ctx, *node); e != nil {
			return e
		}
	}
	var result any
	switch *command {
	case "init":
		if e = c.InitIntentNode(ctx, *node); e != nil {
			return e
		}
		result = map[string]any{"state": "synthetic_stand_initialized", "schema_version": 4}
	case "enqueue":
		env, e := agentprotocol.Decode(os.Stdin)
		if e != nil {
			return e
		}
		result, e = c.EnqueueIntent(ctx, "stand-operator", *key, *node, env)
		if e != nil {
			return e
		}
	case "status":
		if !agentprotocol.ValidID(*id) {
			return agentprotocol.ErrInvalid
		}
		result, e = c.Intent(ctx, *id)
		if e != nil {
			return e
		}
	case "list":
		result, e = c.ListIntents(ctx, *node, *state, *after, *limit)
		if e != nil {
			return e
		}
	case "cancel":
		result, e = c.CancelIntent(ctx, "stand-operator", *node, *id)
		if e != nil {
			return e
		}
	case "worker":
		if *poll < 100 || *poll > 5000 {
			return agentprotocol.ErrInvalid
		}
		return reconciler.Run(ctx, c, *node, func(ctx context.Context, env agentprotocol.Envelope) (agentprotocol.Result, error) {
			return agenttransport.Call(ctx, *socket, env)
		}, reconciler.WorkerOptions{PollInterval: time.Duration(*poll) * time.Millisecond, Report: func(o store.IntentOperation) { _ = json.NewEncoder(os.Stdout).Encode(o) }})
	case "step":
		result, e = reconciler.Step(ctx, c, *node, func(ctx context.Context, env agentprotocol.Envelope) (agentprotocol.Result, error) {
			return agenttransport.Call(ctx, *socket, env)
		})
		if e != nil {
			return e
		}
	default:
		return agentprotocol.ErrInvalid
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
