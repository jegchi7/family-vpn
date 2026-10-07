package main

import (
	"bytes"
	"context"
	"encoding/json"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/store"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestReadinessCLIReadOnlyNonzeroBlockedAndNoBypass(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	ctx := context.Background()
	p, e := store.OpenPortal(ctx, filepath.Join(root, "portal", "state.db"), false)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	p.InitializeLocalAuth(ctx)
	s, _ := auth.New(p, nil, 0, 0)
	token, e := s.IssueInvite(ctx, "alice", "Alice", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	u, e := s.Accept(ctx, "127.0.0.1", token, auth.RandomToken())
	if e != nil {
		t.Fatal(e)
	}
	d, e := p.RequestDevice(ctx, u.ID, domain.DeviceRequest{RequestID: "readiness-request-0001", Name: "Laptop", OS: "windows"})
	if e != nil {
		t.Fatal(e)
	}
	targets, e := p.ProfileImportTargets(ctx, "alice", d.ID)
	if e != nil || len(targets) != 2 {
		t.Fatal(e)
	}
	target := targets[0]
	args := []string{"--root", root, "--owner-id", u.ID, "--device-id", d.ID, "--profile-id", target.ProfileID, "--generation", strconv.Itoa(target.Generation), "--expected-revision", strconv.Itoa(target.DeviceRevision)}
	out := new(bytes.Buffer)
	e = runProfileReadiness(args, out)
	var report struct {
		Status string                       `json:"status"`
		Ready  bool                         `json:"ready"`
		Report store.ProfileReadinessReport `json:"report"`
	}
	if e == nil || json.Unmarshal(out.Bytes(), &report) != nil || report.Status != "blocked" || report.Ready || !report.Report.ReadOnly || report.Report.Ready || len(report.Report.Blockers) == 0 {
		t.Fatal("unsafe CLI readiness outcome")
	}
	for _, extra := range [][]string{{"--apply"}, {"--client-verified", "private-sensitive-text"}, {"--profile-key", "private-sensitive-text"}, {"--ready"}, {"--snapshot", "private-sensitive-text"}, {"private-sensitive-text"}} {
		out.Reset()
		e = runProfileReadiness(append(append([]string{}, args...), extra...), out)
		if e == nil || !strings.Contains(out.String(), "INVALID_TARGET") || strings.Contains(out.String(), "private-sensitive-text") || strings.Contains(e.Error(), "private-sensitive-text") {
			t.Fatal("bypass flag or secret echoed")
		}
	}
	missing := filepath.Join(t.TempDir(), "not-created")
	args[1] = missing
	out.Reset()
	if e = runProfileReadiness(args, out); e == nil {
		t.Fatal("missing DB accepted")
	}
	if _, e = os.Stat(missing); !os.IsNotExist(e) {
		t.Fatal("read-only report initialized state")
	}
}
