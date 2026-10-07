package store

import (
	"database/sql"
	"errors"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/domain"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func deviceInput() domain.DeviceRequest {
	return domain.DeviceRequest{RequestID: auth.RandomToken(), Name: "Мой телефон", OS: "ios"}
}
func TestDeviceRequestsOwnershipAndLifecycle(t *testing.T) {
	p, s, _, _ := authStore(t)
	a, _ := enroll(t, s, "alice")
	b, _ := enroll(t, s, "bob")
	in := deviceInput()
	d, e := p.RequestDevice(ctx, a.ID, in)
	if e != nil {
		t.Fatal(e)
	}
	if d.State != "pending" || d.Revision != 1 || len(d.Profiles) != 2 {
		t.Fatal("incorrect initial state")
	}
	var secrets int
	if e = p.db.QueryRow("SELECT count(*) FROM profiles WHERE device_id=? AND (ciphertext IS NOT NULL OR allocated_ip IS NOT NULL OR installed_revision IS NOT NULL)", d.ID).Scan(&secrets); e != nil || secrets != 0 {
		t.Fatal("provisioning was performed", e)
	}
	same, e := p.RequestDevice(ctx, a.ID, in)
	if e != nil || same.ID != d.ID {
		t.Fatal("not idempotent", e)
	}
	mismatch := in
	mismatch.Name = "Other"
	if _, e = p.RequestDevice(ctx, a.ID, mismatch); !errors.Is(e, ErrConflict) {
		t.Fatal("key reused for different payload", e)
	}
	other, e := p.RequestDevice(ctx, b.ID, in)
	if e != nil || other.ID == d.ID {
		t.Fatal("idempotency crossed owner", e)
	}
	if _, e = p.RenameDevice(ctx, b.ID, d.ID, "Changed", 1); !errors.Is(e, ErrNotFound) {
		t.Fatal("IDOR rename", e)
	}
	if _, e = p.CancelDeviceRequest(ctx, b.ID, d.ID, 1); !errors.Is(e, ErrNotFound) {
		t.Fatal("IDOR cancel", e)
	}
	renamed, e := p.RenameDevice(ctx, a.ID, d.ID, "Ноутбук", 1)
	if e != nil || renamed.Revision != 2 {
		t.Fatal(e)
	}
	if _, e = p.CancelDeviceRequest(ctx, a.ID, d.ID, 1); !errors.Is(e, ErrConflict) {
		t.Fatal("stale mutation", e)
	}
	cancelled, e := p.CancelDeviceRequest(ctx, a.ID, d.ID, 2)
	if e != nil || cancelled.State != "revoked" {
		t.Fatal(e)
	}
	for _, pr := range cancelled.Profiles {
		if pr.State != "revoked" {
			t.Fatal("pending profile survived cancellation")
		}
	}
	replay, e := p.RequestDevice(ctx, a.ID, in)
	if e != nil || replay.State != "revoked" || replay.Name != "Ноутбук" {
		t.Fatal("replay resurrected/overwrote device", e)
	}
	q, e := p.DeviceQuota(ctx, a.ID)
	if e != nil || q.Used != 0 || q.Remaining != q.Limit {
		t.Fatal("slot not released", e)
	}
}
func TestDeviceSlotRaceAndConcurrentRetry(t *testing.T) {
	for _, sameKey := range []bool{false, true} {
		t.Run(map[bool]string{false: "last-slot", true: "same-request"}[sameKey], func(t *testing.T) {
			p, s, _, path := authStore(t)
			u, _ := enroll(t, s, "alice")
			p.db.Exec("UPDATE users SET device_limit=1 WHERE id=?", u.ID)
			other, e := OpenExistingPortal(ctx, path)
			if e != nil {
				t.Fatal(e)
			}
			defer other.Close()
			first, second := deviceInput(), deviceInput()
			if sameKey {
				second = first
			}
			type result struct {
				d domain.Device
				e error
			}
			out := make(chan result, 2)
			var wg sync.WaitGroup
			for i, db := range []*PortalStore{p, other} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					in := first
					if i == 1 {
						in = second
					}
					d, e := db.RequestDevice(ctx, u.ID, in)
					out <- result{d, e}
				}()
			}
			wg.Wait()
			close(out)
			success := 0
			id := ""
			for r := range out {
				if r.e == nil {
					success++
					if id != "" && id != r.d.ID {
						t.Fatal("duplicate retry")
					}
					id = r.d.ID
				} else if !errors.Is(r.e, domain.ErrDeviceLimit) {
					t.Fatal(r.e)
				}
			}
			want := 1
			if sameKey {
				want = 2
			}
			if success != want {
				t.Fatal("unexpected successful requests", success)
			}
			q, e := p.DeviceQuota(ctx, u.ID)
			if e != nil || q.Used != 1 {
				t.Fatal("oversubscribed", e)
			}
		})
	}
}
func TestDeviceCancellationDoesNotRevokeIssuedAccess(t *testing.T) {
	p, s, _, _ := authStore(t)
	u, _ := enroll(t, s, "alice")
	cases := []string{
		"UPDATE profiles SET state='ready' WHERE device_id=?",
		"UPDATE profiles SET allocated_ip='10.22.0.2' WHERE device_id=?",
		"UPDATE profiles SET installed_revision='installed' WHERE device_id=?",
		"UPDATE profiles SET ciphertext=x'01',nonce=x'01',key_id='test' WHERE device_id=? AND protocol='awg'",
	}
	for i, sql := range cases {
		in := deviceInput()
		in.Name = "Protected"
		d, e := p.RequestDevice(ctx, u.ID, in)
		if e != nil {
			t.Fatal(e)
		}
		// IP uniqueness permits changing only one profile; other properties may cover both.
		if i == 1 {
			sql = "UPDATE profiles SET allocated_ip='10.22.0.2' WHERE device_id=? AND protocol='awg'"
		}
		if _, e = p.db.Exec(sql, d.ID); e != nil {
			t.Fatal(e)
		}
		if _, e = p.CancelDeviceRequest(ctx, u.ID, d.ID, 1); !errors.Is(e, domain.ErrDeviceState) {
			t.Fatal("cancel issued device", i, e)
		}
	}
}
func TestDeviceAtomicAuditAndInput(t *testing.T) {
	p, s, _, _ := authStore(t)
	u, _ := enroll(t, s, "alice")
	in := deviceInput()
	if _, e := p.db.Exec(`CREATE TRIGGER fail_device_audit BEFORE INSERT ON audit_events WHEN NEW.action='device.request' BEGIN SELECT RAISE(ABORT,'test'); END`); e != nil {
		t.Fatal(e)
	}
	if _, e := p.RequestDevice(ctx, u.ID, in); e == nil {
		t.Fatal("audit failure accepted")
	}
	var n int
	p.db.QueryRow("SELECT count(*) FROM devices").Scan(&n)
	if n != 0 {
		t.Fatal("device leaked from failed tx")
	}
	p.db.QueryRow("SELECT count(*) FROM profiles").Scan(&n)
	if n != 0 {
		t.Fatal("profile leaked from failed tx")
	}
	p.db.Exec("DROP TRIGGER fail_device_audit")
	d, e := p.RequestDevice(ctx, u.ID, in)
	if e != nil {
		t.Fatal("retry could not reuse request", e)
	}
	for _, name := range []string{"", " \t ", "bad\nname", "bad\u202ename"} {
		if _, e = p.RenameDevice(ctx, u.ID, d.ID, name, 1); !errors.Is(e, domain.ErrDeviceInput) {
			t.Fatal("invalid name", e)
		}
	}
	p.db.Exec("UPDATE users SET state='disabled' WHERE id=?", u.ID)
	if _, e = p.RequestDevice(ctx, u.ID, deviceInput()); !errors.Is(e, auth.ErrDenied) {
		t.Fatal("disabled write", e)
	}
}

func TestUpgradeV3PreservesDevicesAndSession(t *testing.T) {
	path, e := privatePath(filepath.Join(t.TempDir(), "portal", "state.db"), true)
	if e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	steps, e := plan(Portal)
	if e != nil {
		t.Fatal(e)
	}
	if e = migrate(ctx, db, Portal, steps[:3]); e != nil {
		t.Fatal(e)
	}
	old := &PortalStore{&Database{db: db, kind: Portal}}
	if e = old.InitializeLocalAuth(ctx); e != nil {
		t.Fatal(e)
	}
	s, e := auth.New(old, nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	u, _ := enroll(t, s, "alice")
	if _, e = db.Exec("INSERT INTO devices(id,user_id,name,os,state,revision,created_at) VALUES('legacy',?,'Старый телефон','ios','pending',7,?)", u.ID, stamp(time.Now())); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("INSERT INTO profiles(id,device_id,protocol,generation,state,format) VALUES('legacy-profile','legacy','awg',1,'pending','')"); e != nil {
		t.Fatal(e)
	}
	old.Close()
	if runtime, e := OpenExistingPortal(ctx, path); !errors.Is(e, ErrSchema) {
		if runtime != nil {
			runtime.Close()
		}
		t.Fatal("old schema accepted at runtime", e)
	}
	current, e := OpenPortal(ctx, path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer current.Close()
	s.Repo = current
	if _, e = s.Authenticate(ctx, u.Token); e != nil {
		t.Fatal("session lost", e)
	}
	ds, e := current.DevicesForOwner(ctx, u.ID)
	if e != nil || len(ds) != 1 || ds[0].Revision != 7 || ds[0].Name != "Старый телефон" || len(ds[0].Profiles) != 1 {
		t.Fatal("device data changed", e)
	}
	if _, e = current.CancelDeviceRequest(ctx, u.ID, "legacy", 7); !errors.Is(e, domain.ErrDeviceState) {
		t.Fatal("legacy record treated as new request", e)
	}
	d, e := current.RequestDevice(ctx, u.ID, deviceInput())
	if e != nil || d.State != "pending" {
		t.Fatal("new request after upgrade", e)
	}
}

func TestUpgradeV4PreservesPendingRequest(t *testing.T) {
	path, e := privatePath(filepath.Join(t.TempDir(), "portal", "state.db"), true)
	if e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	steps, e := plan(Portal)
	if e != nil {
		t.Fatal(e)
	}
	if e = migrate(ctx, db, Portal, steps[:4]); e != nil {
		t.Fatal(e)
	}
	old := &PortalStore{&Database{db: db, kind: Portal}}
	if e = old.InitializeLocalAuth(ctx); e != nil {
		t.Fatal(e)
	}
	s, e := auth.New(old, nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	u, _ := enroll(t, s, "alice")
	in := deviceInput()
	d, e := old.RequestDevice(ctx, u.ID, in)
	if e != nil {
		t.Fatal(e)
	}
	old.Close()
	if runtime, e := OpenExistingPortal(ctx, path); !errors.Is(e, ErrSchema) {
		if runtime != nil {
			runtime.Close()
		}
		t.Fatal("v4 runtime accepted", e)
	}
	current, e := OpenPortal(ctx, path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer current.Close()
	s.Repo = current
	if _, e = s.Authenticate(ctx, u.Token); e != nil {
		t.Fatal("session lost", e)
	}
	replay, e := current.RequestDevice(ctx, u.ID, in)
	if e != nil || replay.ID != d.ID || replay.Revision != 1 {
		t.Fatal("pending request changed", e)
	}
	if e = current.InitializeProfileVault(ctx, profileTestKey(t)); e != nil {
		t.Fatal(e)
	}
	if _, e = current.CancelDeviceRequest(ctx, u.ID, d.ID, 1); e != nil {
		t.Fatal("empty pending request not cancellable", e)
	}
}
