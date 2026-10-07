//go:build !linux

package agenttransport

import (
	"context"
	"errors"
	"familyvpn.local/platform/internal/agentprotocol"
)

type Handler func(context.Context, agentprotocol.Envelope) (agentprotocol.Result, error)
type Server struct{}

func Listen(string, uint32, Handler) (*Server, error) {
	return nil, errors.New("agent stand requires Linux SO_PEERCRED")
}
func (*Server) Serve(context.Context) error { return errors.New("unsupported platform") }
func (*Server) Close() error                { return nil }
func Call(context.Context, string, agentprotocol.Envelope) (agentprotocol.Result, error) {
	return agentprotocol.Result{}, errors.New("unsupported platform")
}
