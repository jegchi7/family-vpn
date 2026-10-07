package main

import (
	"context"
	"familyvpn.local/platform/internal/agentprotocol"
	"familyvpn.local/platform/internal/agenttransport"
	"familyvpn.local/platform/internal/store"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "node-agent: stand refused or unavailable")
		os.Exit(2)
	}
}
func run() error {
	stand := flag.Bool("fake-stand", false, "required: synthetic metadata only, no VPN changes")
	db := flag.String("control-db", "var/control-stand/control.db", "existing private stand database")
	socket := flag.String("socket", "", "absolute socket path in existing owner-private directory")
	uid := flag.Int64("allow-uid", -1, "explicit controller UID; verified by SO_PEERCRED")
	node := flag.String("node", "stand-ru", "fixed node ID")
	flag.Parse()
	if !*stand || flag.NArg() != 0 || *uid < 0 || *uid > 1<<32-1 || !agentprotocol.ValidID(*node) {
		return agentprotocol.ErrInvalid
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	c, e := store.OpenExistingControl(ctx, *db)
	if e != nil {
		return e
	}
	defer c.Close()
	if e = c.AssertIntentStand(ctx, *node); e != nil {
		return e
	}
	server, e := agenttransport.Listen(*socket, uint32(*uid), func(ctx context.Context, env agentprotocol.Envelope) (agentprotocol.Result, error) {
		return c.FakeAgent(ctx, *node, env)
	})
	if e != nil {
		return e
	}
	defer server.Close()
	fmt.Println("node-agent: synthetic stand ready; VPN runtime unchanged")
	return server.Serve(ctx)
}
