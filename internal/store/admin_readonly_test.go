package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAdminReadOnlyActiveEnrollmentAndMutationBoundary(t *testing.T) {
	f := newAdminFixture(t)
	ro, e := OpenAdminReadOnly(ctx, f.path)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	if active, e := ro.HasActiveAdmin(ctx); e != nil || active {
		t.Fatal("pending enrollment counted as active", e)
	}
	f.activate(t)
	if active, e := ro.HasActiveAdmin(ctx); e != nil || !active {
		t.Fatal("confirmed enrollment omitted", e)
	}
	var before int
	if e = f.a.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&before); e != nil {
		t.Fatal(e)
	}
	if e = ro.AdminDisable(ctx, "operator", f.now); e == nil {
		t.Fatal("read-only diagnostic handle disabled account")
	}
	if active, e := f.a.HasActiveAdmin(ctx); e != nil || !active {
		t.Fatal("read-only mutation changed active account", e)
	}
	var after, sessions int
	if e = f.a.db.QueryRow("SELECT count(*) FROM audit_events").Scan(&after); e != nil {
		t.Fatal(e)
	}
	if e = f.a.db.QueryRow("SELECT count(*) FROM sessions").Scan(&sessions); e != nil {
		t.Fatal(e)
	}
	if after != before || sessions != 0 {
		t.Fatal("diagnostic read or rejected mutation wrote audit/session data")
	}
	if e = f.a.AdminDisable(ctx, "operator", f.now); e != nil {
		t.Fatal(e)
	}
	if active, e := ro.HasActiveAdmin(ctx); e != nil || active {
		t.Fatal("disabled enrollment counted as active", e)
	}
}

func TestAdminReadOnlyRejectsWrongIdentitySchemaAndMissingFile(t *testing.T) {
	_, portalPath := portalForTest(t)
	if a, e := OpenAdminReadOnly(ctx, portalPath); !errors.Is(e, ErrSchema) {
		if a != nil {
			a.Close()
		}
		t.Fatal("portal database accepted as admin database", e)
	}
	adminPath := filepath.Join(t.TempDir(), "private", "admin.db")
	a, e := OpenAdmin(ctx, adminPath, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.db.Exec("UPDATE schema_migrations SET checksum='invalid'"); e != nil {
		a.Close()
		t.Fatal(e)
	}
	a.Close()
	if a, e := OpenAdminReadOnly(ctx, adminPath); !errors.Is(e, ErrSchema) {
		if a != nil {
			a.Close()
		}
		t.Fatal("modified admin schema accepted", e)
	}
	missing := filepath.Join(t.TempDir(), "missing.db")
	if a, e := OpenAdminReadOnly(ctx, missing); e == nil {
		a.Close()
		t.Fatal("missing admin database accepted")
	}
	if _, e = os.Stat(missing); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("diagnostic open created a missing database", e)
	}
}
