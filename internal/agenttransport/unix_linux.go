//go:build linux

// Package agenttransport provides Linux SO_PEERCRED authorization for the fake stand.
package agenttransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"familyvpn.local/platform/internal/agentprotocol"
)

type Handler func(context.Context, agentprotocol.Envelope) (agentprotocol.Result, error)
type Server struct {
	listener *net.UnixListener
	allowed  uint32
	handler  Handler
	wg       sync.WaitGroup
	gate     chan struct{}
	path     string
	own      os.FileInfo
}

func Listen(path string, allowed uint32, handler Handler) (*Server, error) {
	if handler == nil || !filepath.IsAbs(path) {
		return nil, agentprotocol.ErrInvalid
	}
	parent := filepath.Dir(path)
	resolved, e := filepath.EvalSymlinks(parent)
	if e != nil || resolved != parent {
		return nil, errors.New("private socket directory required")
	}
	info, e := os.Stat(parent)
	if e != nil || info.Mode().Perm() != 0700 {
		return nil, errors.New("private socket directory required")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("socket directory owner mismatch")
	}
	// Never remove a pre-existing file/socket; restart cleanup is explicit.
	if _, e = os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
		return nil, errors.New("socket path already exists")
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return nil, e
	}
	l.SetUnlinkOnClose(false)
	if e = os.Chmod(path, 0600); e != nil {
		l.Close()
		os.Remove(path)
		return nil, e
	}
	own, e := os.Lstat(path)
	if e != nil {
		l.Close()
		return nil, e
	}
	return &Server{listener: l, allowed: allowed, handler: handler, gate: make(chan struct{}, 8), path: path, own: own}, nil
}
func (s *Server) Serve(ctx context.Context) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			s.listener.Close()
		case <-done:
		}
	}()
	defer s.wg.Wait()
	for {
		c, e := s.listener.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case s.gate <- struct{}{}:
			s.wg.Add(1)
			go func() { defer s.wg.Done(); defer func() { <-s.gate }(); s.serveConn(ctx, c) }()
		default:
			c.Close()
		}
	}
}
func (s *Server) Close() error {
	e := s.listener.Close()
	info, err := os.Lstat(s.path)
	if err == nil && os.SameFile(info, s.own) {
		_ = os.Remove(s.path)
	}
	return e
}
func (s *Server) serveConn(ctx context.Context, c *net.UnixConn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	raw, e := c.SyscallConn()
	if e != nil {
		return
	}
	var cred *syscall.Ucred
	var inner error
	e = raw.Control(func(fd uintptr) {
		cred, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if e != nil || inner != nil || cred == nil || cred.Uid != s.allowed {
		return
	}
	env, e := agentprotocol.Decode(c)
	if e != nil {
		write(c, agentprotocol.Result{State: "rejected", ResultCode: "invalid_intent"})
		return
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	r, e := s.handler(call, env)
	if e != nil {
		r = agentprotocol.Result{OperationID: env.OperationID, State: "rejected", ResultCode: "not_applied"}
	}
	write(c, r)
}
func write(w io.Writer, r agentprotocol.Result) { _ = json.NewEncoder(w).Encode(r) }

// One envelope per connection; write half-close frames the bounded message.
func Call(ctx context.Context, path string, env agentprotocol.Envelope) (agentprotocol.Result, error) {
	var r agentprotocol.Result
	if env.Validate() != nil {
		return r, agentprotocol.ErrInvalid
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, e := d.DialContext(ctx, "unix", path)
	if e != nil {
		return r, e
	}
	defer conn.Close()
	c, ok := conn.(*net.UnixConn)
	if !ok {
		return r, agentprotocol.ErrInvalid
	}
	deadline := time.Now().Add(3 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	_ = c.SetDeadline(deadline)
	b, _ := json.Marshal(env)
	if _, e = c.Write(b); e != nil {
		return r, e
	}
	if e = c.CloseWrite(); e != nil {
		return r, e
	}
	b, e = io.ReadAll(io.LimitReader(c, agentprotocol.MaxBody+1))
	if e != nil || len(b) > agentprotocol.MaxBody {
		return r, agentprotocol.ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil {
		return r, agentprotocol.ErrInvalid
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return r, agentprotocol.ErrInvalid
	}
	if r.OperationID != env.OperationID || r.ObservedRevision < 0 {
		return r, agentprotocol.ErrInvalid
	}
	if r.State != "pending" && r.State != "succeeded" && r.State != "failed" && r.State != "rejected" {
		return r, agentprotocol.ErrInvalid
	}
	switch r.ResultCode {
	case "applied", "not_observed", "revoked", "revision_conflict", "not_applied":
	default:
		return r, agentprotocol.ErrInvalid
	}
	return r, nil
}
