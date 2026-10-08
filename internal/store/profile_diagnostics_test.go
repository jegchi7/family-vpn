package store

import (
	"bytes"
	"encoding/json"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/profileobserve"
	"strings"
	"testing"
	"time"
)

func portalDiagnostic(t *testing.T, p *PortalStore, target ReadinessTarget, at time.Time) *domain.ProfileDiagnostics {
	t.Helper()
	devices, err := p.devicesForOwnerAt(ctx, target.OwnerID, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range devices {
		if device.ID == target.DeviceID {
			for _, profile := range device.Profiles {
				if profile.ID == target.ProfileID {
					if profile.Diagnostics == nil {
						t.Fatal("missing projection")
					}
					return profile.Diagnostics
				}
			}
		}
	}
	t.Fatal("missing current profile")
	return nil
}

func TestProfileDiagnosticsLatestFreshnessAndSafeProjection(t *testing.T) {
	p, ro, target, client := readinessFixture(t, true)
	defer clear(client)
	now := time.Date(2026, 10, 8, 12, 0, 0, 500000000, time.UTC)
	var beforeAudit int
	if err := p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&beforeAudit); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, source, fields, configuration, publicSource string
		matched                                           bool
		at                                                time.Time
		generation, revision                              int
	}{
		{"missing", "", "", "stored", "none", false, now, 1, 2},
		{"snapshot config", "awg-snapshot", "[]", "matched", "snapshot", true, now, 1, 2},
		{"native config", "awg-runtime", "[]", "matched", "native_readback", true, now, 1, 2},
		{"conflict", "awg-runtime", "[\"peer_missing\"]", "conflict", "native_readback", false, now, 1, 2},
		{"future nanosecond", "awg-runtime", "[]", "stale", "native_readback", true, now.Add(time.Nanosecond), 1, 2},
		{"expiry boundary", "awg-runtime", "[]", "expired", "native_readback", true, now.Add(-profileobserve.TTL), 1, 2},
		{"revision stale", "awg-runtime", "[]", "stale", "native_readback", true, now, 1, 1},
		{"generation stale", "awg-runtime", "[]", "stale", "native_readback", true, now, 2, 2},
		{"malformed fields", "awg-runtime", "[\"unexpected-sensitive-field\"]", "stored", "none", false, now, 1, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := p.db.Exec("DELETE FROM profile_observations"); err != nil {
				t.Fatal(err)
			}
			var id string
			if tc.source != "" {
				row := target
				row.Generation, row.ExpectedRevision = tc.generation, tc.revision
				id = readinessRow(t, p, row, tc.source, tc.matched, tc.fields, tc.at)
			}
			d := portalDiagnostic(t, ro, target, now)
			if d.Configuration != tc.configuration || d.Source != tc.publicSource || d.Connection != "unknown" || d.ClientVerification != "unchecked" {
				t.Fatal("unsafe classification", d)
			}
			if d.Source == "none" && (d.CheckedAt != "" || d.ExpiresAt != "") || d.Source != "none" && (d.CheckedAt != stamp(tc.at) || d.ExpiresAt != stamp(tc.at.Add(profileobserve.TTL))) {
				t.Fatal("invalid timestamp projection")
			}
			encoded, _ := json.Marshal(d)
			for _, value := range [][]byte{client, []byte("peer_missing"), []byte("unexpected-sensitive-field"), []byte("awg-runtime"), []byte("generation"), []byte("revision"), []byte("ready"), []byte("key_id"), []byte("mismatched_fields")} {
				if len(value) > 0 && bytes.Contains(encoded, value) {
					t.Fatal("raw metadata in projection")
				}
			}
			if id != "" && bytes.Contains(encoded, []byte(id)) {
				t.Fatal("observation identifier leaked")
			}
			var afterAudit, revision int
			var profileState string
			var installed *string
			p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&afterAudit)
			p.db.QueryRow("SELECT d.revision,p.state,p.installed_revision FROM devices d JOIN profiles p ON d.id=p.device_id WHERE p.id=?", target.ProfileID).Scan(&revision, &profileState, &installed)
			if afterAudit != beforeAudit || revision != 2 || profileState != "pending" || installed != nil {
				t.Fatal("read changed readiness/audit")
			}
		})
	}
}

func TestProfileDiagnosticsNewerFailureNeverFallsBack(t *testing.T) {
	p, ro, target, client := readinessFixture(t, true)
	defer clear(client)
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	readinessRow(t, p, target, "awg-runtime", true, "[]", at)
	latest := readinessRow(t, p, target, "awg-runtime", false, "[\"peer_missing\"]", at.Add(time.Nanosecond))
	if d := portalDiagnostic(t, ro, target, at.Add(time.Second)); d.Configuration != "conflict" || d.CheckedAt != stamp(at.Add(time.Nanosecond)) {
		t.Fatal("fractional latest conflict hidden")
	}
	if d := portalDiagnostic(t, ro, target, at.Add(time.Minute+time.Second)); d.Configuration != "expired" {
		t.Fatal("expired latest row hidden")
	}
	// Unknown temporal ordering cannot justify selecting an older match.
	for _, measured := range []string{"0000-invalid-time", "2026-10-08T12:00:00+00:00"} {
		if _, err := p.db.Exec("UPDATE profile_observations SET measured_at=? WHERE id=?", measured, latest); err != nil {
			t.Fatal(err)
		}
		if d := portalDiagnostic(t, ro, target, at.Add(time.Second)); d.Configuration != "stored" || d.Source != "none" || d.CheckedAt != "" {
			t.Fatal("invalid latest time hidden or echoed")
		}
	}
	if _, err := p.db.Exec("UPDATE profile_observations SET measured_at=?,expires_at=? WHERE id=?", stamp(at.Add(time.Nanosecond)), stamp(at.Add(profileobserve.TTL+time.Nanosecond)), latest); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
		t.Fatal(err)
	}
	defer p.db.Exec("PRAGMA ignore_check_constraints=OFF")
	if _, err := p.db.Exec("UPDATE profile_observations SET source='unexpected-sensitive-source' WHERE id=?", latest); err != nil {
		t.Fatal(err)
	}
	if d := portalDiagnostic(t, ro, target, at.Add(time.Second)); d.Configuration != "stored" || d.Source != "none" {
		t.Fatal("unknown latest source hidden or echoed")
	}
	if _, err := p.db.Exec("UPDATE profile_observations SET source='awg-runtime',id=? WHERE id=?", strings.Repeat("x", 32), latest); err != nil {
		t.Fatal(err)
	}
	if d := portalDiagnostic(t, ro, target, at.Add(time.Second)); d.Configuration != "stored" || d.Source != "none" {
		t.Fatal("invalid latest observation identifier accepted")
	}
}

func TestProfileDiagnosticsOwnershipRenameAndManagementReadSnapshot(t *testing.T) {
	p, ro, target, client := readinessFixture(t, true)
	defer clear(client)
	now := time.Now().UTC()
	readinessRow(t, p, target, "awg-runtime", false, "[\"peer_missing\"]", now)
	other := auth.RandomToken()
	if _, err := p.db.Exec("INSERT INTO users(id,login,display_name,role,state,created_at) VALUES(?,'another','Another','user','active',?)", other, stamp(now)); err != nil {
		t.Fatal(err)
	}
	foreignTarget := target
	foreignTarget.OwnerID = other
	readinessRow(t, p, foreignTarget, "awg-runtime", true, "[]", now.Add(time.Second))
	if d := portalDiagnostic(t, ro, target, now.Add(2*time.Second)); d.Configuration != "conflict" {
		t.Fatal("other owner observation selected")
	}
	devices, err := ro.devicesForOwnerAt(ctx, other, now)
	if err != nil || len(devices) != 0 {
		t.Fatal("other owner device leaked", err)
	}
	page, err := ro.adminDevicesAt(ctx, domain.PageRequest{Limit: 1}, "pending", now.Add(2*time.Second))
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != target.DeviceID {
		t.Fatal("management read failed", err)
	}
	found := false
	for _, profile := range page.Items[0].Profiles {
		if profile.ID == target.ProfileID {
			found = true
			if profile.Diagnostics == nil || *profile.Diagnostics != *portalDiagnostic(t, ro, target, now.Add(2*time.Second)) {
				t.Fatal("user/admin projections differ")
			}
		}
	}
	if !found {
		t.Fatal("admin profile absent")
	}
	updated, err := p.RenameDevice(ctx, target.OwnerID, target.DeviceID, "Renamed", 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range updated.Profiles {
		if profile.ID == target.ProfileID && (profile.Diagnostics == nil || profile.Diagnostics.Configuration != "stale") {
			t.Fatal("rename response reused old match")
		}
	}
	if d := portalDiagnostic(t, ro, target, now); d.Configuration != "stale" {
		t.Fatal("revision change did not invalidate projection")
	}
	if _, err := ro.db.Exec("UPDATE devices SET revision=999 WHERE id=?", target.DeviceID); err == nil {
		t.Fatal("management handle writable")
	}
}

func TestProfileDiagnosticsMalformedTemporalHistorySuppressesPositive(t *testing.T) {
	p, ro, target, client := readinessFixture(t, true)
	defer clear(client)
	at := time.Date(2026, 10, 8, 12, 0, 0, 500000000, time.UTC)
	// Force the positive row to win a normalized-time tie unless invalid
	// temporal metadata is ranked first. Observation IDs are not credentials.
	positive := readinessRow(t, p, target, "awg-runtime", true, "[]", at)
	if _, err := p.db.Exec("UPDATE profile_observations SET id=? WHERE id=?", strings.Repeat("f", 32), positive); err != nil {
		t.Fatal(err)
	}
	latest := readinessRow(t, p, target, "awg-runtime", false, "[\"peer_missing\"]", at.Add(time.Nanosecond))
	if _, err := p.db.Exec("UPDATE profile_observations SET id=? WHERE id=?", strings.Repeat("0", 32), latest); err != nil {
		t.Fatal(err)
	}
	latest = strings.Repeat("0", 32)
	for _, tc := range []struct{ column, value string }{
		{"measured_at", "2026-10-08T12:00:00.0Z"},
		{"measured_at", "2026-10-08T12:00:00.000Z"},
		{"measured_at", "2026-10-08T12:00:00.500000000Z"},
		{"measured_at", "2026-10-08T11:00:00.1xZ"},
		{"measured_at", "2026-02-30T12:00:00Z"},
		{"measured_at", "2026-10-07T24:00:00Z"},
		{"expires_at", "2026-10-08T12:01:00.0Z"},
		{"expires_at", "2026-02-30T12:01:00Z"},
	} {
		t.Run(tc.column+"/"+tc.value, func(t *testing.T) {
			// The malformed row starts older than the positive. Either timestamp
			// becomes unorderable; no historical positive can hide corruption.
			if _, err := p.db.Exec("UPDATE profile_observations SET measured_at=?,expires_at=? WHERE id=?", stamp(at.Add(-time.Second)), stamp(at.Add(-time.Second+profileobserve.TTL)), latest); err != nil {
				t.Fatal(err)
			}
			if _, err := p.db.Exec("UPDATE profile_observations SET "+tc.column+"=? WHERE id=?", tc.value, latest); err != nil {
				t.Fatal(err)
			}
			d := portalDiagnostic(t, ro, target, at.Add(time.Second))
			if d.Configuration != "stored" || d.Source != "none" || d.CheckedAt != "" || d.ExpiresAt != "" || d.Connection != "unknown" || d.ClientVerification != "unchecked" {
				t.Fatal("malformed temporal history hidden or exposed")
			}
		})
	}
}

func TestProfileDiagnosticsNoImportUnsupportedAndRevoked(t *testing.T) {
	p, ro, target, _ := readinessFixture(t, false)
	now := time.Now().UTC()
	if d := portalDiagnostic(t, ro, target, now); d.Configuration != "unchecked" || d.Source != "none" {
		t.Fatal("unimported profile checked")
	}
	p, ro, target, client := readinessFixture(t, true)
	defer clear(client)
	readinessRow(t, p, target, "awg-runtime", true, "[]", now)
	for _, query := range []string{"UPDATE devices SET state='revoked' WHERE id=?", "UPDATE users SET state='disabled' WHERE id=?"} {
		id := target.DeviceID
		if query == "UPDATE users SET state='disabled' WHERE id=?" {
			id = target.OwnerID
		}
		if _, err := p.db.Exec(query, id); err != nil {
			t.Fatal(err)
		}
		if d := portalDiagnostic(t, ro, target, now); d.Configuration != "stale" {
			t.Fatal("revoked/disabled target reused match")
		}
		p.db.Exec("UPDATE devices SET state='pending' WHERE id=?", target.DeviceID)
	}
	if _, err := p.db.Exec("UPDATE profiles SET format='txt' WHERE id=?", target.ProfileID); err != nil {
		t.Fatal(err)
	}
	if d := portalDiagnostic(t, ro, target, now); d.Configuration != "stored" || d.Source != "none" {
		t.Fatal("unsupported format matched")
	}
}
