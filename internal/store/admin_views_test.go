package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/domain"
	"testing"
	"time"
)

func TestAdminViewsReadOnlyPaginationAndSecretBoundary(t *testing.T) {
	p, s, now, path := authStore(t)
	*now = time.Now().UTC()
	a, password := enroll(t, s, "alice")
	enroll(t, s, "bob")
	invite, e := s.IssueInvite(ctx, "carol", "Carol", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	d, e := p.RequestDevice(ctx, a.ID, deviceInput())
	if e != nil {
		t.Fatal(e)
	}
	v := profileTestKey(t)
	p.InitializeProfileVault(ctx, v)
	payload := importPayload(t)
	if _, e = p.ImportClientProfile(ctx, v, importContext(a.ID, d), 1, payload, true); e != nil {
		t.Fatal(e)
	}
	ro, e := OpenPortal(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	var before int
	p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&before)
	seen := map[string]bool{}
	cursor := ""
	for i := 0; i < 4; i++ {
		page, e := ro.AdminUsers(ctx, domain.PageRequest{Limit: 1, After: cursor})
		if e != nil || len(page.Items) != 1 {
			t.Fatal("users pagination", e)
		}
		if seen[page.Items[0].ID] {
			t.Fatal("duplicate user")
		}
		seen[page.Items[0].ID] = true
		b, _ := json.Marshal(page)
		for _, secret := range []string{password, invite, a.Token} {
			if bytes.Contains(b, []byte(secret)) {
				t.Fatal("credential in admin users")
			}
		}
		if page.Items[0].Login == "carol" && page.Items[0].Invitation != "available" {
			t.Fatal("incorrect invitation status")
		}
		if page.Items[0].Login == "alice" && page.Items[0].UsedSlots != 1 {
			t.Fatal("wrong quota")
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	if len(seen) != 3 {
		t.Fatal("missing users")
	}
	devices, e := ro.AdminDevices(ctx, domain.PageRequest{Limit: 1}, "pending")
	if e != nil || len(devices.Items) != 1 || devices.Items[0].Revision != 2 || len(devices.Items[0].Profiles) != 2 {
		t.Fatal("device queue", e)
	}
	stored := 0
	for _, profile := range devices.Items[0].Profiles {
		if profile.Stored {
			stored++
		}
	}
	if stored != 1 {
		t.Fatal("incorrect stored indicator")
	}
	encoded, _ := json.Marshal(devices)
	if bytes.Contains(encoded, payload) || bytes.Contains(encoded, []byte(v.ID())) {
		t.Fatal("vault data in admin metadata")
	}
	secret := auth.RandomToken()
	if _, e = p.db.Exec("INSERT INTO audit_events(id,actor,action,object_ref,outcome,request_id,operation_id,time) VALUES(?,?,?,?,?,?,?,?)", auth.RandomToken(), secret, secret, secret, secret, secret, secret, stamp(time.Now().Add(time.Hour))); e != nil {
		t.Fatal(e)
	}
	audit, e := ro.AdminAudit(ctx, domain.PageRequest{Limit: 100})
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ = json.Marshal(audit)
	if bytes.Contains(encoded, []byte(secret)) {
		t.Fatal("untrusted audit payload escaped")
	}
	if audit.Items[0].Action != "other" || audit.Items[0].ActorKind != "unknown" || audit.Items[0].ObjectID != "" || audit.Items[0].Outcome != "unknown" {
		t.Fatal("unknown audit classification")
	}
	seen = map[string]bool{}
	cursor = ""
	for i := 0; i < 100; i++ {
		page, e := ro.AdminAudit(ctx, domain.PageRequest{Limit: 1, After: cursor})
		if e != nil || len(page.Items) != 1 {
			t.Fatal("audit pagination", e)
		}
		if seen[page.Items[0].ID] {
			t.Fatal("duplicate audit")
		}
		seen[page.Items[0].ID] = true
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	if len(seen) != len(audit.Items) {
		t.Fatal("audit rows skipped")
	}
	var after int
	p.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&after)
	if after != before+1 {
		t.Fatal("read views mutated audit")
	}
	for _, request := range []domain.PageRequest{{Limit: 0}, {Limit: 101}, {Limit: 1, After: "invalid"}} {
		if _, e = ro.AdminUsers(ctx, request); !errors.Is(e, auth.ErrInput) {
			t.Fatal("invalid page accepted")
		}
	}
	if _, e = ro.AdminDevices(ctx, domain.PageRequest{Limit: 1}, "arbitrary"); !errors.Is(e, auth.ErrInput) {
		t.Fatal("invalid state accepted")
	}
	if _, e = ro.AdminAudit(ctx, domain.PageRequest{Limit: 1, After: "bad"}); !errors.Is(e, auth.ErrInput) {
		t.Fatal("invalid audit cursor accepted")
	}
}
func TestAdminAuditFractionalAndEqualTimestamps(t *testing.T) {
	p, _, _, _ := authStore(t)
	base := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	ids := []string{auth.RandomToken(), auth.RandomToken(), auth.RandomToken()}
	for i, nano := range []int{0, 1, 1} {
		if _, e := p.db.Exec("INSERT INTO audit_events(id,actor,action,object_ref,outcome,time) VALUES(?,'trusted-cli','profile-vault.initialize','client-profiles','success',?)", ids[i], stamp(base.Add(time.Duration(nano)))); e != nil {
			t.Fatal(e)
		}
	}
	page, e := p.AdminAudit(ctx, domain.PageRequest{Limit: 1})
	if e != nil {
		t.Fatal(e)
	}
	if page.Items[0].ID == ids[0] {
		t.Fatal("whole second sorted before later fraction")
	}
	second, e := p.AdminAudit(ctx, domain.PageRequest{Limit: 1, After: page.NextCursor})
	if e != nil || second.Items[0].ID == page.Items[0].ID || second.Items[0].ID == ids[0] {
		t.Fatal("equal-time cursor", e)
	}
	third, e := p.AdminAudit(ctx, domain.PageRequest{Limit: 1, After: second.NextCursor})
	if e != nil || third.Items[0].ID != ids[0] {
		t.Fatal("fractional cursor skipped earlier second", e)
	}
}

func adminUserAt(t *testing.T, p *PortalStore, login string, at time.Time) domain.AdminUser {
	t.Helper()
	page, e := p.adminUsersAt(ctx, domain.PageRequest{Limit: 100}, at)
	if e != nil {
		t.Fatal(e)
	}
	for _, u := range page.Items {
		if u.Login == login {
			return u
		}
	}
	t.Fatal("admin view omitted user")
	return domain.AdminUser{}
}

func TestAdminUsersTokenRevocationAndConsumption(t *testing.T) {
	p, s, now, path := authStore(t)
	enroll(t, s, "alice")
	if _, e := s.IssueInvite(ctx, "bob", "Bob", time.Hour); e != nil {
		t.Fatal(e)
	}
	ro, e := OpenPortal(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	if u := adminUserAt(t, ro, "bob", *now); u.Invitation != "available" {
		t.Fatal("fresh invitation unavailable")
	}
	if _, e = s.ReissueInvite(ctx, "bob", time.Minute); e != nil {
		t.Fatal(e)
	}
	if _, e = s.IssueRecovery(ctx, "alice", time.Hour); e != nil {
		t.Fatal(e)
	}
	if _, e = s.IssueRecovery(ctx, "alice", time.Minute); e != nil {
		t.Fatal(e)
	}
	if u := adminUserAt(t, ro, "alice", *now); !u.RecoveryPending {
		t.Fatal("fresh replacement recovery unavailable")
	}
	*now = now.Add(2 * time.Minute)
	if u := adminUserAt(t, ro, "bob", *now); u.Invitation != "expired" {
		t.Fatal("revoked old invitation hides replacement expiry")
	}
	if u := adminUserAt(t, ro, "alice", *now); u.RecoveryPending {
		t.Fatal("revoked old recovery hides replacement expiry")
	}
	invite, e := s.ReissueInvite(ctx, "bob", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Accept(ctx, "127.0.0.1", invite, auth.RandomToken()); e != nil {
		t.Fatal(e)
	}
	if u := adminUserAt(t, ro, "bob", *now); u.Invitation != "used" {
		t.Fatal("revoked invitation hides completed enrollment")
	}
	recovery, e := s.IssueRecovery(ctx, "alice", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Recover(ctx, "127.0.0.1", recovery, auth.RandomToken()); e != nil {
		t.Fatal(e)
	}
	if u := adminUserAt(t, ro, "alice", *now); u.RecoveryPending {
		t.Fatal("revoked recovery remains pending after completion")
	}
	if _, e = s.IssueInvite(ctx, "carol", "Carol", time.Hour); e != nil {
		t.Fatal(e)
	}
	if _, e = p.db.Exec("UPDATE one_time_tokens SET revoked_at=? WHERE user_id=(SELECT id FROM users WHERE login='carol')", stamp(*now)); e != nil {
		t.Fatal(e)
	}
	if u := adminUserAt(t, ro, "carol", *now); u.Invitation != "none" {
		t.Fatal("revoked-only invitation represented as usable or consumed")
	}
}

func TestAdminUsersTokenExpiryFractionAndBoundary(t *testing.T) {
	_, s, now, path := authStore(t)
	enroll(t, s, "alice")
	if _, e := s.IssueInvite(ctx, "bob", "Bob", 900*time.Millisecond); e != nil {
		t.Fatal(e)
	}
	if _, e := s.IssueRecovery(ctx, "alice", 900*time.Millisecond); e != nil {
		t.Fatal(e)
	}
	ro, e := OpenPortal(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	for _, tc := range []struct {
		name      string
		elapsed   time.Duration
		available bool
	}{
		{"whole second before later fraction", 0, true},
		{"shorter fraction before expiry", 100 * time.Millisecond, true},
		{"millisecond before expiry", 899 * time.Millisecond, true},
		{"exact fractional expiry", 900 * time.Millisecond, false},
		{"millisecond after expiry", 901 * time.Millisecond, false},
		{"whole second after fraction", time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := now.Add(tc.elapsed)
			invite := adminUserAt(t, ro, "bob", at)
			want := "expired"
			if tc.available {
				want = "available"
			}
			if invite.Invitation != want {
				t.Fatalf("invitation status %q, want %q", invite.Invitation, want)
			}
			if recovery := adminUserAt(t, ro, "alice", at); recovery.RecoveryPending != tc.available {
				t.Fatal("recovery expiry status differs from invitation expiry")
			}
		})
	}
}

func TestAdminAuditCancelledDeviceAndLegacyAction(t *testing.T) {
	p, s, _, path := authStore(t)
	u, _ := enroll(t, s, "alice")
	d, e := p.RequestDevice(ctx, u.ID, deviceInput())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.CancelDeviceRequest(ctx, u.ID, d.ID, d.Revision); e != nil {
		t.Fatal(e)
	}
	var currentID string
	if e = p.db.QueryRow("SELECT id FROM audit_events WHERE action='device.request.cancel' AND object_ref=?", d.ID).Scan(&currentID); e != nil {
		t.Fatal("real cancellation did not record expected audit action", e)
	}
	legacyID := auth.RandomToken()
	if _, e = p.db.Exec("INSERT INTO audit_events(id,actor,action,object_ref,outcome,time) VALUES(?,?,'device.cancel',?,'success',?)", legacyID, u.ID, d.ID, stamp(time.Now())); e != nil {
		t.Fatal(e)
	}
	unknownID := auth.RandomToken()
	if _, e = p.db.Exec("INSERT INTO audit_events(id,actor,action,object_ref,outcome,time) VALUES(?,?,'device.request.cancel.extra',?,'success',?)", unknownID, u.ID, d.ID, stamp(time.Now())); e != nil {
		t.Fatal(e)
	}
	ro, e := OpenPortal(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	page, e := ro.AdminAudit(ctx, domain.PageRequest{Limit: 100})
	if e != nil {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	for _, event := range page.Items {
		switch event.ID {
		case currentID, legacyID:
			if event.Action != "device.cancel" || event.ObjectID != d.ID || event.ActorKind != "user" || event.Outcome != "success" {
				t.Fatal("cancellation lost safe action or object metadata")
			}
			seen[event.ID] = true
		case unknownID:
			if event.Action != "other" || event.ObjectID != "" {
				t.Fatal("unrecognized action acquired device object metadata")
			}
			seen[event.ID] = true
		}
	}
	if len(seen) != 3 {
		t.Fatal("admin audit omitted cancellation regression records")
	}
}
