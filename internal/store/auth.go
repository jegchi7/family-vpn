package store

import (
	"context"
	"database/sql"
	"errors"
	"familyvpn.local/platform/internal/auth"
	"fmt"
	"time"
)

var _ auth.Repository = (*PortalStore)(nil)

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// InitializeLocalAuth never relabels a demo or populated store.
func (p *PortalStore) InitializeLocalAuth(ctx context.Context) error {
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var marker string
	e = tx.QueryRowContext(ctx, "SELECT value FROM app_metadata WHERE key='dataset'").Scan(&marker)
	if e == nil {
		if marker == "local-auth-v1" {
			return nil
		}
		return errors.New("refusing to change dataset mode")
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	var n int
	e = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM users)+(SELECT count(*) FROM instructions)+(SELECT count(*) FROM health_samples)+(SELECT count(*) FROM public_operations)+(SELECT count(*) FROM audit_events)+(SELECT count(*) FROM app_metadata)`).Scan(&n)
	if e != nil {
		return e
	}
	if n != 0 {
		return errors.New("local auth requires an empty store")
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO app_metadata VALUES('dataset','local-auth-v1')"); e != nil {
		return e
	}
	return tx.Commit()
}
func (p *PortalStore) AssertLocalAuth(ctx context.Context) error {
	var v string
	if e := p.db.QueryRowContext(ctx, "SELECT value FROM app_metadata WHERE key='dataset'").Scan(&v); e != nil || v != "local-auth-v1" {
		return errors.New("expected separate local-auth database")
	}
	return nil
}

// Atomic, persistent fixed-window counters; expired keys are pruned and cardinality bounded.
func (p *PortalStore) ReserveAttempts(ctx context.Context, ip, account []byte, now time.Time) error {
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "DELETE FROM auth_rate_limits WHERE window_start<=?", now.Add(-auth.Window).Unix()); e != nil {
		return e
	}
	limited := false
	for i, key := range [][]byte{ip, account} {
		limit := 30
		if i == 1 {
			limit = 5
		}
		var count int
		e = tx.QueryRowContext(ctx, "SELECT attempts FROM auth_rate_limits WHERE scope_hash=?", key).Scan(&count)
		if errors.Is(e, sql.ErrNoRows) {
			var n int
			if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM auth_rate_limits").Scan(&n); e != nil {
				return e
			}
			if n >= 4096 {
				limited = true
				continue
			}
			count = 0
		} else if e != nil {
			return e
		}
		if count >= limit {
			limited = true
			continue
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO auth_rate_limits VALUES(?,?,1) ON CONFLICT(scope_hash) DO UPDATE SET attempts=attempts+1", key, now.Unix()); e != nil {
			return e
		}
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	if limited {
		return auth.ErrLimited
	}
	return nil
}
func audit(ctx context.Context, tx *sql.Tx, actor, action, object string, now time.Time) error {
	_, e := tx.ExecContext(ctx, "INSERT INTO audit_events(id,actor,action,object_ref,outcome,time) VALUES(?,?,?,?,'succeeded',?)", auth.RandomToken(), actor, action, object, stamp(now))
	return e
}
func (p *PortalStore) CreateInvite(ctx context.Context, id, login, name string, hash []byte, now, expires time.Time) error {
	if e := p.AssertLocalAuth(ctx); e != nil {
		return e
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	res, e := tx.ExecContext(ctx, "INSERT INTO users(id,login,display_name,role,state,created_at) VALUES(?,?,?,'user','invited',?) ON CONFLICT(login) DO NOTHING", id, login, name, stamp(now))
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return auth.ErrConflict
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO one_time_tokens(token_hash,user_id,purpose,expires_at) VALUES(?,?,'invite',?)", hash, id, stamp(expires)); e != nil {
		return e
	}
	if e = audit(ctx, tx, "local-cli", "invite.create", id, now); e != nil {
		return e
	}
	return tx.Commit()
}
func (p *PortalStore) PasswordCredential(ctx context.Context, login string) (string, string, error) {
	var id, encoded string
	e := p.db.QueryRowContext(ctx, `SELECT u.id,c.password_hash FROM users u JOIN credentials c ON c.user_id=u.id AND c.kind='password' WHERE u.login=? AND u.state='active' AND u.role='user'`, login).Scan(&id, &encoded)
	if errors.Is(e, sql.ErrNoRows) {
		e = auth.ErrDenied
	}
	return id, encoded, e
}
func newSession(ctx context.Context, tx *sql.Tx, id string, hash []byte, now, expires time.Time) (auth.Session, error) {
	var s auth.Session
	e := tx.QueryRowContext(ctx, "SELECT id,login,display_name,role FROM users WHERE id=? AND state='active' AND role='user'", id).Scan(&s.ID, &s.Login, &s.DisplayName, &s.Role)
	if errors.Is(e, sql.ErrNoRows) {
		return s, auth.ErrDenied
	}
	if e != nil {
		return s, e
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO sessions(token_hash,user_id,created_at,last_seen_at,expires_at,auth_time) VALUES(?,?,?,?,?,?)", hash, id, stamp(now), stamp(now), stamp(expires), stamp(now))
	s.ExpiresAt = expires
	s.AuthTime = now
	return s, e
}
func (p *PortalStore) AcceptInvite(ctx context.Context, token []byte, encoded string, sessionHash []byte, now, expires time.Time) (auth.Session, error) {
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return auth.Session{}, e
	}
	defer tx.Rollback()
	res, e := tx.ExecContext(ctx, `UPDATE one_time_tokens SET consumed_at=? WHERE token_hash=? AND purpose='invite' AND consumed_at IS NULL AND revoked_at IS NULL AND julianday(expires_at)>julianday(?) AND EXISTS(SELECT 1 FROM users WHERE id=one_time_tokens.user_id AND state='invited' AND role='user')`, stamp(now), token, stamp(now))
	if e != nil {
		return auth.Session{}, e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return auth.Session{}, e
	}
	if n != 1 {
		return auth.Session{}, auth.ErrDenied
	}
	var id string
	if e = tx.QueryRowContext(ctx, "SELECT user_id FROM one_time_tokens WHERE token_hash=?", token).Scan(&id); e != nil {
		return auth.Session{}, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE users SET state='active' WHERE id=?", id); e != nil {
		return auth.Session{}, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO credentials(id,user_id,kind,password_hash,created_at) VALUES(?,?,'password',?,?)", auth.RandomToken(), id, encoded, stamp(now)); e != nil {
		return auth.Session{}, e
	}
	s, e := newSession(ctx, tx, id, sessionHash, now, expires)
	if e != nil {
		return s, e
	}
	if e = audit(ctx, tx, id, "invite.accept", id, now); e != nil {
		return s, e
	}
	return s, tx.Commit()
}
func (p *PortalStore) CreateSession(ctx context.Context, id, expectedHash string, hash []byte, now, expires time.Time) (auth.Session, error) {
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return auth.Session{}, e
	}
	defer tx.Rollback()
	// Take writer lock before reading so a concurrent password reset cannot interleave.
	if _, e = tx.ExecContext(ctx, "UPDATE users SET state=state WHERE id=?", id); e != nil {
		return auth.Session{}, e
	}
	var n int
	e = tx.QueryRowContext(ctx, "SELECT count(*) FROM credentials WHERE user_id=? AND kind='password' AND password_hash=?", id, expectedHash).Scan(&n)
	if e != nil {
		return auth.Session{}, e
	}
	if n != 1 {
		return auth.Session{}, auth.ErrDenied
	}
	s, e := newSession(ctx, tx, id, hash, now, expires)
	if e != nil {
		return s, e
	}
	if e = audit(ctx, tx, id, "session.login", id, now); e != nil {
		return s, e
	}
	return s, tx.Commit()
}
func (p *PortalStore) Session(ctx context.Context, hash []byte, now time.Time, idle time.Duration) (auth.Session, error) {
	var s auth.Session
	var expires, authtime string
	e := p.db.QueryRowContext(ctx, `SELECT u.id,u.login,u.display_name,u.role,s.expires_at,s.auth_time FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND julianday(s.expires_at)>julianday(?) AND julianday(s.last_seen_at)>julianday(?) AND u.state='active' AND u.role='user'`, hash, stamp(now), stamp(now.Add(-idle))).Scan(&s.ID, &s.Login, &s.DisplayName, &s.Role, &expires, &authtime)
	if errors.Is(e, sql.ErrNoRows) {
		return s, auth.ErrDenied
	}
	if e != nil {
		return s, e
	}
	s.ExpiresAt, e = time.Parse(time.RFC3339Nano, expires)
	if e != nil {
		return s, e
	}
	s.AuthTime, e = time.Parse(time.RFC3339Nano, authtime)
	return s, e
}
func (p *PortalStore) TouchSession(ctx context.Context, hash []byte, now time.Time, idle time.Duration) error {
	res, e := p.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at=? WHERE token_hash=? AND revoked_at IS NULL AND julianday(expires_at)>julianday(?) AND julianday(last_seen_at)>julianday(?) AND EXISTS(SELECT 1 FROM users WHERE id=sessions.user_id AND role='user' AND state='active')`, stamp(now), hash, stamp(now), stamp(now.Add(-idle)))
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return auth.ErrDenied
	}
	return nil
}
func (p *PortalStore) RevokeSession(ctx context.Context, hash []byte, now time.Time) error {
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "UPDATE sessions SET revoked_at=COALESCE(revoked_at,?) WHERE token_hash=?", stamp(now), hash); e != nil {
		return e
	}
	var id string
	e = tx.QueryRowContext(ctx, "SELECT user_id FROM sessions WHERE token_hash=?", hash).Scan(&id)
	if e != nil {
		return fmt.Errorf("revoke: %w", e)
	}
	if e = audit(ctx, tx, id, "session.logout", id, now); e != nil {
		return e
	}
	return tx.Commit()
}
