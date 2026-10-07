package store

import (
	"context"
	"database/sql"
	"errors"
	"familyvpn.local/platform/internal/auth"
	"time"
)

// lockUser takes a writer lock before reading role/state to serialize with login,
// enrollment and another administrative reset. No token can change its purpose.
func lockUser(ctx context.Context, tx *sql.Tx, login, state string) (string, error) {
	if _, e := tx.ExecContext(ctx, "UPDATE users SET state=state WHERE login=?", login); e != nil {
		return "", e
	}
	var id string
	e := tx.QueryRowContext(ctx, "SELECT id FROM users WHERE login=? AND role='user' AND state=?", login, state).Scan(&id)
	if errors.Is(e, sql.ErrNoRows) {
		return "", auth.ErrDenied
	}
	return id, e
}
func revokeUserSessions(ctx context.Context, tx *sql.Tx, id string, now time.Time) error {
	_, e := tx.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", stamp(now), id)
	return e
}
func revokeUserTokens(ctx context.Context, tx *sql.Tx, id string, now time.Time) error {
	_, e := tx.ExecContext(ctx, "UPDATE one_time_tokens SET revoked_at=? WHERE user_id=? AND consumed_at IS NULL AND revoked_at IS NULL", stamp(now), id)
	return e
}
func passwordOnlyUser(ctx context.Context, tx *sql.Tx, id string) error {
	var n int
	if e := tx.QueryRowContext(ctx, "SELECT count(*) FROM credentials WHERE user_id=? AND kind!='password'", id).Scan(&n); e != nil {
		return e
	}
	// Fail closed for future passkey/MFA credentials; their recovery is not implemented.
	if n != 0 {
		return auth.ErrDenied
	}
	return nil
}
func (p *PortalStore) CreateRecovery(ctx context.Context, login string, hash []byte, now, expires time.Time) error {
	if e := p.AssertLocalAuth(ctx); e != nil {
		return e
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	id, e := lockUser(ctx, tx, login, "active")
	if e != nil {
		return e
	}
	if e = passwordOnlyUser(ctx, tx, id); e != nil {
		return e
	}
	if e = revokeUserSessions(ctx, tx, id, now); e != nil {
		return e
	}
	if e = revokeUserTokens(ctx, tx, id, now); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM credentials WHERE user_id=? AND kind='password'", id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO one_time_tokens(token_hash,user_id,purpose,expires_at) VALUES(?,?,'recovery',?)", hash, id, stamp(expires)); e != nil {
		return e
	}
	if e = audit(ctx, tx, "local-cli", "recovery.issue", id, now); e != nil {
		return e
	}
	return tx.Commit()
}
func (p *PortalStore) CompleteRecovery(ctx context.Context, token []byte, encoded string, now time.Time) error {
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	result, e := tx.ExecContext(ctx, `UPDATE one_time_tokens SET consumed_at=? WHERE token_hash=? AND purpose='recovery' AND consumed_at IS NULL AND revoked_at IS NULL AND julianday(expires_at)>julianday(?) AND EXISTS(SELECT 1 FROM users WHERE id=one_time_tokens.user_id AND role='user' AND state='active') AND NOT EXISTS(SELECT 1 FROM credentials WHERE user_id=one_time_tokens.user_id AND kind!='password')`, stamp(now), token, stamp(now))
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return auth.ErrDenied
	}
	var id string
	if e = tx.QueryRowContext(ctx, "SELECT user_id FROM one_time_tokens WHERE token_hash=?", token).Scan(&id); e != nil {
		return e
	}
	if e = revokeUserSessions(ctx, tx, id, now); e != nil {
		return e
	}
	if e = revokeUserTokens(ctx, tx, id, now); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM credentials WHERE user_id=? AND kind='password'", id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO credentials(id,user_id,kind,password_hash,created_at) VALUES(?,?,'password',?,?)", auth.RandomToken(), id, encoded, stamp(now)); e != nil {
		return e
	}
	if e = audit(ctx, tx, id, "recovery.complete", id, now); e != nil {
		return e
	}
	return tx.Commit()
}
func (p *PortalStore) ReplaceInvite(ctx context.Context, login string, hash []byte, now, expires time.Time) error {
	if e := p.AssertLocalAuth(ctx); e != nil {
		return e
	}
	tx, e := p.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	id, e := lockUser(ctx, tx, login, "invited")
	if e != nil {
		return e
	}
	var n int
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM credentials WHERE user_id=?", id).Scan(&n); e != nil {
		return e
	}
	if n != 0 {
		return auth.ErrDenied
	}
	if e = revokeUserTokens(ctx, tx, id, now); e != nil {
		return e
	}
	if e = revokeUserSessions(ctx, tx, id, now); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO one_time_tokens(token_hash,user_id,purpose,expires_at) VALUES(?,?,'invite',?)", hash, id, stamp(expires)); e != nil {
		return e
	}
	if e = audit(ctx, tx, "local-cli", "invite.reissue", id, now); e != nil {
		return e
	}
	return tx.Commit()
}
