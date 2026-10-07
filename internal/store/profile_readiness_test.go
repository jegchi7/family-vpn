package store

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/profileobserve"
	"strings"
	"testing"
	"time"
)

func readinessFixture(t *testing.T, imported bool) (*PortalStore, *PortalStore, ReadinessTarget, []byte) {
	t.Helper()
	p, s, _, path := authStore(t)
	u, _ := enroll(t, s, "alice")
	d, e := p.RequestDevice(ctx, u.ID, deviceInput())
	if e != nil {
		t.Fatal(e)
	}
	c := awgImportContext(u.ID, d)
	revision := 1
	var client []byte
	if imported {
		v := profileTestKey(t)
		if e = p.InitializeProfileVault(ctx, v); e != nil {
			t.Fatal(e)
		}
		client, _ = observationPayload(t)
		if _, e = p.ImportClientProfile(ctx, v, c, 1, client, true); e != nil {
			t.Fatal(e)
		}
		revision = 2
	}
	ro, e := OpenPortal(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ro.Close() })
	return p, ro, ReadinessTarget{u.ID, d.ID, c.ProfileID, 1, revision}, client
}

// Synthetic ledger rows exercise read-model classification only; they are not
// native evidence and cannot be used to publish access through this API.
func readinessRow(t *testing.T, p *PortalStore, target ReadinessTarget, source string, matched bool, fields string, at time.Time) string {
	t.Helper()
	b := make([]byte, 16)
	rand.Read(b)
	id := hex.EncodeToString(b)
	_, e := p.db.Exec(`INSERT INTO profile_observations(id,profile_id,owner_id,generation,device_revision,source,peer_matches,mismatched_fields,measured_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, id, target.ProfileID, target.OwnerID, target.Generation, target.ExpectedRevision, source, matched, fields, stamp(at), stamp(at.Add(profileobserve.TTL)))
	if e != nil {
		t.Fatal(e)
	}
	return id
}

func TestReadinessFreshnessBindingAndNoPermission(t *testing.T) {
	p, ro, target, client := readinessFixture(t, true)
	now := time.Date(2026, 10, 5, 10, 0, 0, 500000000, time.UTC)
	var beforeAudit int
	p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&beforeAudit)
	cases := []struct {
		name, source, fields, status, blocker string
		matched                               bool
		at                                    time.Time
		revision                              int
		fresh                                 bool
	}{
		{"missing", "", "", "", "observation_missing", false, now, 2, false},
		{"native match", "awg-runtime", "[]", "fresh_match", "", true, now, 2, true},
		{"snapshot match", "awg-snapshot", "[]", "configuration_only", "snapshot_not_runtime", true, now, 2, false},
		{"native conflict", "awg-runtime", "[\"peer_addresses\"]", "conflict", "observation_conflict", false, now, 2, false},
		{"future", "awg-runtime", "[]", "future", "observation_time_invalid", true, now.Add(time.Nanosecond), 2, false},
		{"expiry boundary", "awg-runtime", "[]", "expired", "observation_expired", true, now.Add(-profileobserve.TTL), 2, false},
		{"old revision", "awg-runtime", "[]", "stale_binding", "observation_binding_stale", true, now, 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p.db.Exec("DELETE FROM profile_observations")
			if tc.source != "" {
				old := target
				old.ExpectedRevision = tc.revision
				readinessRow(t, p, old, tc.source, tc.matched, tc.fields, tc.at)
			}
			r, e := ro.profileReadinessAt(ctx, target, now)
			if e != nil || r.Ready || r.SecretVerified || r.ClientsVerified || r.RuntimeTargetVerified || r.NetworkChanged || !r.ReadOnly || r.StoredRuntimeReadbackFresh != tc.fresh {
				t.Fatal("unsafe report", e)
			}
			if tc.source == "" {
				if r.Observation != nil {
					t.Fatal("invented observation")
				}
			} else if r.Observation == nil || r.Observation.Status != tc.status {
				t.Fatal("incorrect observation classification")
			}
			joined := strings.Join(r.Blockers, ",")
			for _, b := range []string{"runtime_target_verification_required", "secret_verification_required", "client_acceptance_missing", "readiness_transition_unavailable", tc.blocker} {
				if b != "" && !strings.Contains(joined, b) {
					t.Fatal("blocker omitted", b)
				}
			}
			out, _ := json.Marshal(r)
			if bytes.Contains(out, client) {
				t.Fatal("client plaintext leaked")
			}
			var afterAudit, revision int
			var state string
			var installed *string
			p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&afterAudit)
			p.db.QueryRow("SELECT d.revision,p.state,p.installed_revision FROM devices d JOIN profiles p ON d.id=p.device_id WHERE p.id=?", target.ProfileID).Scan(&revision, &state, &installed)
			if beforeAudit != afterAudit || revision != 2 || state != "pending" || installed != nil {
				t.Fatal("read-model changed state")
			}
		})
	}
	if _, e := ro.db.Exec("INSERT INTO audit_events(id,actor,action,object_ref,outcome,time) VALUES('readiness-read-only','test','test','test','test','test')"); e == nil {
		t.Fatal("report handle writable")
	}
}

func TestReadinessLatestConflictAndFractionalOrder(t *testing.T) {
	p, ro, target, _ := readinessFixture(t, true)
	at := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	readinessRow(t, p, target, "awg-runtime", true, "[]", at)
	latest := readinessRow(t, p, target, "awg-runtime", false, "[\"peer_missing\"]", at.Add(100*time.Millisecond))
	r, e := ro.profileReadinessAt(ctx, target, at.Add(time.Second))
	if e != nil || r.Observation.ID != latest || r.Observation.Status != "conflict" || r.StoredRuntimeReadbackFresh {
		t.Fatal("older matching observation hid latest conflict", e)
	}
	// A later record never revives after expiry by falling back to another row.
	r, e = ro.profileReadinessAt(ctx, target, at.Add(61*time.Second))
	if e != nil || r.Observation.ID != latest || r.Observation.Status != "expired" {
		t.Fatal("expired latest row bypassed", e)
	}
}

func TestReadinessRenameInvalidatesHistoricalObservation(t *testing.T) {
	p, ro, target, _ := readinessFixture(t, true)
	now := time.Now().UTC()
	readinessRow(t, p, target, "awg-runtime", true, "[]", now)
	if _, e := p.RenameDevice(ctx, target.OwnerID, target.DeviceID, "Renamed", 2); e != nil {
		t.Fatal(e)
	}
	if _, e := ro.profileReadinessAt(ctx, target, now); !errors.Is(e, ErrConflict) {
		t.Fatal("old expected revision accepted", e)
	}
	target.ExpectedRevision = 3
	r, e := ro.profileReadinessAt(ctx, target, now)
	if e != nil || r.Observation.Status != "stale_binding" || r.StoredRuntimeReadbackFresh || r.Ready {
		t.Fatal("rename reused historical match", e)
	}
}

func TestReadinessCurrentTargetAndCorruptMetadata(t *testing.T) {
	p, ro, target, _ := readinessFixture(t, true)
	now := time.Now().UTC()
	id := readinessRow(t, p, target, "awg-runtime", true, "[]", now)
	for _, wrong := range []ReadinessTarget{{auth.RandomToken(), target.DeviceID, target.ProfileID, 1, 2}, {target.OwnerID, auth.RandomToken(), target.ProfileID, 1, 2}, {target.OwnerID, target.DeviceID, auth.RandomToken(), 1, 2}} {
		if _, e := ro.profileReadinessAt(ctx, wrong, now); !errors.Is(e, ErrNotFound) {
			t.Fatal("foreign target leaked", e)
		}
	}
	for _, wrong := range []ReadinessTarget{{target.OwnerID, target.DeviceID, target.ProfileID, 2, 2}, {target.OwnerID, target.DeviceID, target.ProfileID, 1, 1}} {
		if _, e := ro.profileReadinessAt(ctx, wrong, now); !errors.Is(e, ErrConflict) {
			t.Fatal("stale target accepted", e)
		}
	}
	for _, tc := range []struct{ column, value string }{{"mismatched_fields", "[\"private-secret-value\"]"}, {"mismatched_fields", "null"}, {"mismatched_fields", "[\"peer_missing\",\"peer_missing\"]"}, {"measured_at", "invalid-private-text"}, {"expires_at", stamp(now.Add(time.Hour))}} {
		p.db.Exec("UPDATE profile_observations SET "+tc.column+"=? WHERE id=?", tc.value, id)
		if _, e := ro.profileReadinessAt(ctx, target, now); !errors.Is(e, profileobserve.ErrObservation) || strings.Contains(e.Error(), tc.value) {
			t.Fatal("corrupt metadata accepted or echoed", e)
		}
		p.db.Exec("UPDATE profile_observations SET mismatched_fields='[]',measured_at=?,expires_at=? WHERE id=?", stamp(now), stamp(now.Add(profileobserve.TTL)), id)
	}
	other := target
	other.OwnerID = auth.RandomToken()
	// Owner is an FK; use a real second user for a foreign ledger row.
	p.db.Exec("INSERT INTO users(id,login,display_name,role,state,created_at) VALUES(?,'bob','Bob','user','active',?)", other.OwnerID, stamp(now))
	foreign := readinessRow(t, p, other, "awg-runtime", true, "[]", now.Add(time.Second))
	r, e := ro.profileReadinessAt(ctx, target, now.Add(2*time.Second))
	if e != nil || r.Observation.ID == foreign {
		t.Fatal("foreign ledger record selected", e)
	}
	p.db.Exec("UPDATE users SET state='disabled' WHERE id=?", target.OwnerID)
	if _, e = ro.profileReadinessAt(ctx, target, now); !errors.Is(e, ErrNotFound) {
		t.Fatal("disabled owner read", e)
	}
	p.db.Exec("UPDATE users SET state='active',role='admin' WHERE id=?", target.OwnerID)
	if _, e = ro.profileReadinessAt(ctx, target, now); !errors.Is(e, ErrNotFound) {
		t.Fatal("admin owner read", e)
	}
}

func TestReadinessMissingImportOtherProtocolAndRevoked(t *testing.T) {
	p, ro, target, _ := readinessFixture(t, false)
	now := time.Now().UTC()
	r, e := ro.profileReadinessAt(ctx, target, now)
	if e != nil || r.StoredExport || !strings.Contains(strings.Join(r.Blockers, ","), "client_import_missing") {
		t.Fatal("missing import", e)
	}
	p.db.QueryRow("SELECT id FROM profiles WHERE device_id=? AND protocol='reality'", target.DeviceID).Scan(&target.ProfileID)
	r, e = ro.profileReadinessAt(ctx, target, now)
	if e != nil || !strings.Contains(strings.Join(r.Blockers, ","), "runtime_observer_unavailable") {
		t.Fatal("unsupported runtime scope", e)
	}
	p.db.Exec("UPDATE devices SET state='revoked' WHERE id=?", target.DeviceID)
	p.db.Exec("UPDATE profiles SET state='revoked' WHERE id=?", target.ProfileID)
	r, e = ro.profileReadinessAt(ctx, target, now)
	if e != nil || r.Ready || !strings.Contains(strings.Join(r.Blockers, ","), "profile_state_blocked") || !strings.Contains(strings.Join(r.Blockers, ","), "device_state_blocked") {
		t.Fatal("revoked target admitted", e)
	}
}
