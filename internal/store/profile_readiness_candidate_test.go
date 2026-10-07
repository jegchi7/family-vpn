package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/profileobserve"
	"familyvpn.local/platform/internal/profilevault"
	"fmt"
	"strings"
	"testing"
	"time"
)

func readinessCandidateFixture(t *testing.T) (*PortalStore, *profilevault.Vault, profilevault.Context, []byte, profileobserve.Result, string) {
	t.Helper()
	p, s, _, path := authStore(t)
	u, _ := enroll(t, s, "alice")
	v := profileTestKey(t)
	if e := p.InitializeProfileVault(ctx, v); e != nil {
		t.Fatal(e)
	}
	d, e := p.RequestDevice(ctx, u.ID, deviceInput())
	if e != nil {
		t.Fatal(e)
	}
	c := awgImportContext(u.ID, d)
	client, snapshot := observationPayload(t)
	if _, e = p.ImportClientProfile(ctx, v, c, 1, client, true); e != nil {
		t.Fatal(e)
	}
	r, e := profileobserve.Snapshot(c, 2, client, snapshot, "edge.example.invalid:443")
	if e != nil {
		t.Fatal(e)
	}
	return p, v, c, client, r, path
}

func replaceReadinessSecret(t *testing.T, p *PortalStore, v *profilevault.Vault, c profilevault.Context, plain []byte) {
	t.Helper()
	e, err := v.Seal(c, plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.db.Exec("UPDATE profiles SET nonce=?,ciphertext=?,key_id=? WHERE id=?", e.Nonce, e.Ciphertext, e.KeyID, c.ProfileID); err != nil {
		t.Fatal(err)
	}
}

func TestAWGReadinessCandidateReadOnlyOpaqueAndBlocked(t *testing.T) {
	p, v, c, client, observation, path := readinessCandidateFixture(t)
	ro, e := OpenPortal(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	var before int
	p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&before)
	var ciphertext []byte
	p.db.QueryRow("SELECT ciphertext FROM profiles WHERE id=?", c.ProfileID).Scan(&ciphertext)
	candidate, e := ro.PrepareAWGReadiness(ctx, v, c, 2, profileobserve.Target{Endpoint: "edge.example.invalid:443"}, observation)
	if e != nil {
		t.Fatal(e)
	}
	r := candidate.Summary()
	if !r.SecretVerified || r.Ready || r.ClientsVerified || r.RuntimeMatches || r.WriterFenced || r.StateChanged || r.NetworkChanged || strings.Join(r.Blockers, ",") != "snapshot_not_runtime,client_acceptance_missing,readiness_transition_unavailable" {
		t.Fatal("snapshot or verified ciphertext authorized ready")
	}
	r.Ready = true
	r.Blockers[0] = "client_acceptance_missing"
	if candidate.Summary().Ready || candidate.Summary().Blockers[0] != "snapshot_not_runtime" {
		t.Fatal("mutable candidate")
	}
	encoded, e := json.Marshal(candidate)
	if e != nil {
		t.Fatal(e)
	}
	for _, output := range []string{string(encoded), fmt.Sprint(candidate), fmt.Sprintf("%#v", candidate), fmt.Sprintf("%+v", candidate)} {
		for _, forbidden := range []string{c.OwnerID, c.DeviceID, c.ProfileID, "PrivateKey", "HeaderProtectionKey", "digest", "edge.example.invalid", string(client)} {
			if strings.Contains(output, forbidden) {
				t.Fatal("candidate leaked binding or material")
			}
		}
	}
	var restored AWGReadinessCandidate
	if !errors.Is(json.Unmarshal(encoded, &restored), profilevault.ErrInput) {
		t.Fatal("diagnostic JSON restored authority")
	}
	if _, e = p.RecheckAWGReadiness(ctx, v, restored, profileobserve.Target{Endpoint: "edge.example.invalid:443"}); !errors.Is(e, profilevault.ErrInput) {
		t.Fatal("empty candidate accepted", e)
	}
	r, e = p.RecheckAWGReadiness(ctx, v, candidate, profileobserve.Target{Endpoint: "edge.example.invalid:443"})
	if e != nil || !r.WriterFenced || !r.SecretVerified || r.Ready || r.ClientsVerified || r.RuntimeMatches || r.StateChanged || r.NetworkChanged {
		t.Fatal("fenced recheck changed access", e)
	}
	var after int
	p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&after)
	var current []byte
	p.db.QueryRow("SELECT ciphertext FROM profiles WHERE id=?", c.ProfileID).Scan(&current)
	var state string
	var revision int
	var installed *string
	p.db.QueryRow("SELECT d.revision,p.state,p.installed_revision FROM profiles p JOIN devices d ON d.id=p.device_id WHERE p.id=?", c.ProfileID).Scan(&revision, &state, &installed)
	if before != after || !bytes.Equal(ciphertext, current) || state != "pending" || revision != 2 || installed != nil {
		t.Fatal("prepare/recheck mutated state")
	}
	if _, e = p.ReadReadyProfileSecret(ctx, v, c.OwnerID, c.ProfileID); !errors.Is(e, domain.ErrDeviceState) {
		t.Fatal("candidate published profile", e)
	}
	metadata, e := ro.ProfileReadiness(ctx, ReadinessTarget{c.OwnerID, c.DeviceID, c.ProfileID, 1, 2})
	if e != nil || metadata.SecretVerified || metadata.Ready {
		t.Fatal("candidate changed keyless diagnostics", e)
	}
}

func TestAWGReadinessCandidateRevalidatesEveryCurrentGuard(t *testing.T) {
	for _, kind := range []string{"rename", "revoked", "disabled", "generation", "profile_revoked", "installed", "corrupt", "bytes", "invalid_format", "rotation", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			p, v, c, client, observation, _ := readinessCandidateFixture(t)
			candidate, e := p.PrepareAWGReadiness(ctx, v, c, 2, profileobserve.Target{Endpoint: "edge.example.invalid:443"}, observation)
			if e != nil {
				t.Fatal(e)
			}
			want := ErrConflict
			switch kind {
			case "rename":
				_, e = p.RenameDevice(ctx, c.OwnerID, c.DeviceID, "Renamed", 2)
			case "revoked":
				_, e = p.db.Exec("UPDATE devices SET state='revoked' WHERE id=?", c.DeviceID)
				want = domain.ErrDeviceState
			case "profile_revoked":
				_, e = p.db.Exec("UPDATE profiles SET state='revoked' WHERE id=?", c.ProfileID)
				want = domain.ErrDeviceState
			case "disabled":
				_, e = p.db.Exec("UPDATE users SET state='disabled' WHERE id=?", c.OwnerID)
				want = ErrNotFound
			case "generation":
				_, e = p.db.Exec("UPDATE devices SET generation=generation+1 WHERE id=?", c.DeviceID)
			case "installed":
				_, e = p.db.Exec("UPDATE profiles SET installed_revision='unexpected' WHERE id=?", c.ProfileID)
				want = domain.ErrDeviceState
			case "corrupt":
				_, e = p.db.Exec("UPDATE profiles SET ciphertext=zeroblob(length(ciphertext)) WHERE id=?", c.ProfileID)
				want = profilevault.ErrEnvelope
			case "bytes":
				changed := append(bytes.Clone(client), '\n')
				defer clear(changed)
				replaceReadinessSecret(t, p, v, c, changed)
				want = profileobserve.ErrStale
			case "invalid_format":
				changed := append(bytes.Clone(client), []byte("Unknown = rejected\n")...)
				defer clear(changed)
				replaceReadinessSecret(t, p, v, c, changed)
				want = clientconfig.ErrInvalid
			case "rotation":
				_, e = p.RotateProfileVault(ctx, v, profileTestKey(t))
				want = profilevault.ErrKey
			case "duplicate":
				d, err := p.RequestDevice(ctx, c.OwnerID, deviceInput())
				if err != nil {
					t.Fatal(err)
				}
				// Trusted staging bypasses importer uniqueness; readiness must repeat it.
				_, e = p.StageProfileSecret(ctx, v, awgImportContext(c.OwnerID, d), 1, client)
				want = ErrClientCredentialConflict
			}
			if e != nil {
				t.Fatal("test mutation failed", e)
			}
			var before int
			p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&before)
			if _, e = p.RecheckAWGReadiness(ctx, v, candidate, profileobserve.Target{Endpoint: "edge.example.invalid:443"}); !errors.Is(e, want) {
				t.Fatal("stale preparation accepted", e)
			}
			var after int
			p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&after)
			if before != after {
				t.Fatal("failed check wrote audit")
			}
			if kind == "installed" {
				if _, e = p.LoadPendingAWGObservation(ctx, v, c, 2); !errors.Is(e, domain.ErrDeviceState) {
					t.Fatal("inconsistent installed profile loaded as pending", e)
				}
				if e = p.RecordProfileObservation(ctx, v, c, 2, profileobserve.Target{Endpoint: "edge.example.invalid:443"}, observation); !errors.Is(e, domain.ErrDeviceState) {
					t.Fatal("inconsistent installed profile recorded as pending", e)
				}
			}
		})
	}
}

func TestAWGReadinessCandidateConflictAndKeyRotationRemainBlocked(t *testing.T) {
	p, v, c, client, _, _ := readinessCandidateFixture(t)
	_, snapshot := observationPayload(t)
	// Different generated server/client keys produce a genuine comparator conflict.
	observation, e := profileobserve.Snapshot(c, 2, client, snapshot, "edge.example.invalid:443")
	if e != nil || observation.Summary().PeerMatches {
		t.Fatal("conflict fixture", e)
	}
	candidate, e := p.PrepareAWGReadiness(ctx, v, c, 2, profileobserve.Target{Endpoint: "edge.example.invalid:443"}, observation)
	if e != nil || !strings.Contains(strings.Join(candidate.Summary().Blockers, ","), "observation_conflict") {
		t.Fatal("comparison conflict hidden", e)
	}
	newKey := profileTestKey(t)
	if _, e = p.RotateProfileVault(ctx, v, newKey); e != nil {
		t.Fatal(e)
	}
	r, e := p.RecheckAWGReadiness(ctx, newKey, candidate, profileobserve.Target{Endpoint: "edge.example.invalid:443"})
	if e != nil || !r.SecretVerified || r.Ready || r.RuntimeMatches || !strings.Contains(strings.Join(r.Blockers, ","), "observation_conflict") {
		t.Fatal("re-encryption changed bytes or bypassed conflict", e)
	}
}

func TestAWGReadinessCandidateRejectsForeignAndLedgerOnlyEvidence(t *testing.T) {
	p, v, c, _, observation, _ := readinessCandidateFixture(t)
	wrong := c
	wrong.OwnerID = "foreign-owner"
	if _, e := p.PrepareAWGReadiness(ctx, v, wrong, 2, profileobserve.Target{Endpoint: "edge.example.invalid:443"}, observation); !errors.Is(e, ErrNotFound) {
		t.Fatal("foreign target", e)
	}
	if e := p.RecordProfileObservation(ctx, v, c, 2, profileobserve.Target{Endpoint: "edge.example.invalid:443"}, observation); e != nil {
		t.Fatal(e)
	}
	// Corrupt historical metadata cannot turn a zero sealed result into proof.
	if _, e := p.db.Exec("UPDATE profile_observations SET source='awg-runtime'"); e != nil {
		t.Fatal(e)
	}
	if _, e := p.PrepareAWGReadiness(ctx, v, c, 2, profileobserve.Target{Endpoint: "edge.example.invalid:443"}, profileobserve.Result{}); !errors.Is(e, profileobserve.ErrStale) {
		t.Fatal("ledger row became authority", e)
	}
	if _, e := p.PrepareAWGReadiness(ctx, v, c, 3, profileobserve.Target{Endpoint: "edge.example.invalid:443"}, observation); !errors.Is(e, ErrConflict) {
		t.Fatal("revision rebound", e)
	}
}

func TestAWGReadinessRecheckWaitsForOtherWriterThenRejectsRevision(t *testing.T) {
	p, v, c, _, observation, path := readinessCandidateFixture(t)
	candidate, e := p.PrepareAWGReadiness(ctx, v, c, 2, profileobserve.Target{Endpoint: "edge.example.invalid:443"}, observation)
	if e != nil {
		t.Fatal(e)
	}
	second, e := OpenExistingPortal(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	tx, e := p.profileWriteTx(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "UPDATE devices SET revision=revision+1 WHERE id=?", c.DeviceID); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		_, err := second.RecheckAWGReadiness(ctx, v, candidate, profileobserve.Target{Endpoint: "edge.example.invalid:443"})
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatal("check escaped writer fence", err)
	case <-time.After(100 * time.Millisecond):
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-done:
		if !errors.Is(e, ErrConflict) {
			t.Fatal("committed newer revision ignored", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("recheck did not release")
	}
}

func TestAWGInventoryScopeCannotRebindSnapshotCandidateOrLedger(t *testing.T) {
	p, v, c, _, observation, _ := readinessCandidateFixture(t)
	expected := profileobserve.Target{Endpoint: "edge.example.invalid:443"}
	candidate, e := p.PrepareAWGReadiness(ctx, v, c, 2, expected, observation)
	if e != nil {
		t.Fatal(e)
	}
	var beforeAudit, beforeRows int
	p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&beforeAudit)
	p.db.QueryRow("SELECT count(*) FROM profile_observations").Scan(&beforeRows)
	for _, wrong := range []profileobserve.Target{{}, {Endpoint: "other.invalid:443"}, {Endpoint: expected.Endpoint, Interface: "awg0"}, {Endpoint: expected.Endpoint, ToolSHA256: strings.Repeat("a", 64)}, {Endpoint: expected.Endpoint, BootID: "11111111-2222-3333-4444-555555555555"}, {Endpoint: expected.Endpoint, NetNSDevice: 4}, {Endpoint: expected.Endpoint, NetNSInode: 12345}} {
		if e = p.RecordProfileObservation(ctx, v, c, 2, wrong, observation); !errors.Is(e, profileobserve.ErrStale) {
			t.Fatal("record accepted foreign inventory", e)
		}
		if _, e = p.PrepareAWGReadiness(ctx, v, c, 2, wrong, observation); !errors.Is(e, profileobserve.ErrStale) {
			t.Fatal("prepare rebound inventory", e)
		}
		if _, e = p.RecheckAWGReadiness(ctx, v, candidate, wrong); !errors.Is(e, profileobserve.ErrStale) {
			t.Fatal("recheck rebound inventory", e)
		}
	}
	r, e := p.RecheckAWGReadiness(ctx, v, candidate, expected)
	if e != nil || r.RuntimeTargetBound || r.RuntimeMatches || r.Ready || r.ClientsVerified {
		t.Fatal("configuration target became runtime", e)
	}
	var afterAudit, afterRows int
	p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&afterAudit)
	p.db.QueryRow("SELECT count(*) FROM profile_observations").Scan(&afterRows)
	if beforeAudit != afterAudit || beforeRows != afterRows {
		t.Fatal("scope failure wrote metadata/audit")
	}
	if _, e = p.ReadReadyProfileSecret(ctx, v, c.OwnerID, c.ProfileID); !errors.Is(e, domain.ErrDeviceState) {
		t.Fatal("scope check published profile", e)
	}
}
