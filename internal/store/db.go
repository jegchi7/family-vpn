// Package store owns schema lifecycle; HTTP processes open existing stores read-only.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	_ "modernc.org/sqlite"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

//go:embed migrations/*/*.sql
var migrationFiles embed.FS

type Kind string

const (
	Admin   Kind = "admin"
	Portal  Kind = "portal"
	Control Kind = "control"
)

var ErrSchema = errors.New("incompatible database schema")
var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("revision conflict")

type migration struct {
	version         int
	name, sql, hash string
}
type Database struct {
	db   *sql.DB
	kind Kind
}

func (d *Database) Close() error                   { return d.db.Close() }
func (d *Database) Ping(ctx context.Context) error { return d.db.PingContext(ctx) }
func appID(k Kind) (int, error) {
	switch k {
	case Admin:
		return 1179668545, nil
	case Portal:
		return 1179668560, nil
	case Control:
		return 1179668547, nil
	}
	return 0, fmt.Errorf("unknown database kind %q", k)
}
func plan(k Kind) ([]migration, error) {
	if _, e := appID(k); e != nil {
		return nil, e
	}
	names, e := fs.Glob(migrationFiles, "migrations/"+string(k)+"/*.sql")
	if e != nil {
		return nil, e
	}
	sort.Strings(names)
	out := []migration{}
	for i, n := range names {
		b, e := migrationFiles.ReadFile(n)
		if e != nil {
			return nil, e
		}
		sum := sha256.Sum256(b)
		out = append(out, migration{i + 1, n, string(b), hex.EncodeToString(sum[:])})
	}
	return out, nil
}

// privatePath refuses aliases and permissive files. No silent chmod of existing stores.
// Production requires distinct service UIDs and ancestors that untrusted users cannot replace.
func privatePath(path string, create bool) (string, error) {
	abs, e := filepath.Abs(path)
	if e != nil {
		return "", e
	}
	dir := filepath.Dir(abs)
	if create {
		if e = os.MkdirAll(dir, 0700); e != nil {
			return "", e
		}
	}
	resolved, e := filepath.EvalSymlinks(dir)
	if e != nil {
		return "", e
	}
	if resolved != dir {
		return "", errors.New("database parent must not contain symlinks")
	}
	info, e := os.Stat(dir)
	if e != nil {
		return "", e
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return "", errors.New("database directory must be private (0700)")
	}
	if create {
		f, e := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e == nil {
			if e = f.Close(); e != nil {
				return "", e
			}
		} else if !errors.Is(e, os.ErrExist) {
			return "", e
		}
	}
	info, e = os.Lstat(abs)
	if e != nil {
		return "", e
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("database must be a regular file, not a symlink")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return "", errors.New("database file must be private (0600)")
	}
	return abs, nil
}
func Open(ctx context.Context, path string, kind Kind, readOnly bool) (*Database, error) {
	return open(ctx, path, kind, readOnly, !readOnly)
}
func OpenExistingPortal(ctx context.Context, path string) (*PortalStore, error) {
	d, e := open(ctx, path, Portal, false, false)
	if e != nil {
		return nil, e
	}
	return &PortalStore{d}, nil
}
func open(ctx context.Context, path string, kind Kind, readOnly, allowMigrations bool) (*Database, error) {
	steps, e := plan(kind)
	if e != nil {
		return nil, e
	}
	abs, e := privatePath(path, allowMigrations)
	if e != nil {
		return nil, e
	}
	uriPath := filepath.ToSlash(abs)
	if runtime.GOOS == "windows" {
		// Keep the drive letter in the path, never in the URI authority.
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	q := u.Query()
	if readOnly {
		q.Set("mode", "ro")
	} else {
		q.Set("mode", "rw")
	}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	u.RawQuery = q.Encode()
	db, e := sql.Open("sqlite", u.String())
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	cleanup := func(err error) (*Database, error) { _ = db.Close(); return nil, err }
	if e = db.PingContext(ctx); e != nil {
		return cleanup(e)
	}
	if !allowMigrations {
		e = validate(ctx, db, kind, steps, true)
	} else {
		e = migrate(ctx, db, kind, steps)
	}
	if e != nil {
		return cleanup(e)
	}
	if !readOnly {
		var mode string
		e = db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode)
		if e != nil {
			return cleanup(e)
		}
		if mode != "wal" {
			return cleanup(errors.New("WAL unavailable"))
		}
		if _, e = db.ExecContext(ctx, "PRAGMA synchronous=FULL"); e != nil {
			return cleanup(e)
		}
	}
	return &Database{db: db, kind: kind}, nil
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func validate(ctx context.Context, q queryer, k Kind, steps []migration, exact bool) error {
	var id, version int
	if e := q.QueryRowContext(ctx, "PRAGMA application_id").Scan(&id); e != nil {
		return e
	}
	want, _ := appID(k)
	if id != want {
		return fmt.Errorf("%w: wrong database identity", ErrSchema)
	}
	if e := q.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); e != nil {
		return e
	}
	if version > len(steps) || version < 1 || (exact && version != len(steps)) {
		return fmt.Errorf("%w: version %d (expected %d)", ErrSchema, version, len(steps))
	}
	rows, e := q.QueryContext(ctx, "SELECT version,checksum FROM schema_migrations ORDER BY version")
	if e != nil {
		return fmt.Errorf("%w: migration history missing", ErrSchema)
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		var v int
		var h string
		if e = rows.Scan(&v, &h); e != nil {
			return e
		}
		if i >= len(steps) || v != i+1 || steps[i].hash != h {
			return fmt.Errorf("%w: migration history mismatch", ErrSchema)
		}
		i++
	}
	if e = rows.Err(); e != nil {
		return e
	}
	if i != version {
		return fmt.Errorf("%w: migration history gap", ErrSchema)
	}
	return nil
}
func migrate(ctx context.Context, db *sql.DB, k Kind, steps []migration) error {
	c, e := db.Conn(ctx)
	if e != nil {
		return e
	}
	defer c.Close()
	if _, e = c.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
		return e
	}
	defer c.ExecContext(context.Background(), "ROLLBACK")
	var id, version int
	if e = c.QueryRowContext(ctx, "PRAGMA application_id").Scan(&id); e != nil {
		return e
	}
	want, _ := appID(k)
	if id == 0 {
		if e = c.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); e != nil {
			return e
		}
		var count int
		if e = c.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").Scan(&count); e != nil {
			return e
		}
		if count != 0 || version != 0 {
			return fmt.Errorf("%w: refusing an unowned database", ErrSchema)
		}
		if _, e = c.ExecContext(ctx, fmt.Sprintf("PRAGMA application_id=%d", want)); e != nil {
			return e
		}
		if _, e = c.ExecContext(ctx, "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,checksum TEXT NOT NULL,applied_at TEXT NOT NULL)"); e != nil {
			return e
		}
	} else {
		if e = validate(ctx, c, k, steps, false); e != nil {
			return e
		}
		if e = c.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); e != nil {
			return e
		}
	}
	for _, m := range steps[version:] {
		if _, e = c.ExecContext(ctx, m.sql); e != nil {
			return fmt.Errorf("migration %s failed: %w", m.name, e)
		}
		if _, e = c.ExecContext(ctx, "INSERT INTO schema_migrations VALUES(?,?,?)", m.version, m.hash, time.Now().UTC().Format(time.RFC3339Nano)); e != nil {
			return e
		}
		if _, e = c.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", m.version)); e != nil {
			return e
		}
	}
	_, e = c.ExecContext(ctx, "COMMIT")
	return e
}
func (d *Database) Status(ctx context.Context) (map[string]any, error) {
	var v int
	var sqliteVersion string
	if e := d.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); e != nil {
		return nil, e
	}
	if e := d.db.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&sqliteVersion); e != nil {
		return nil, e
	}
	return map[string]any{"kind": d.kind, "schema_version": v, "sqlite_version": sqliteVersion}, nil
}
func (d *Database) AssertDemo(ctx context.Context) error {
	var value string
	if e := d.db.QueryRowContext(ctx, "SELECT value FROM app_metadata WHERE key='dataset'").Scan(&value); e != nil || value != "demo-v1" {
		return errors.New("refusing to serve a non-demo database without authentication")
	}
	return nil
}
func validName(name string) bool { return strings.TrimSpace(name) != "" && len([]rune(name)) <= 64 }
