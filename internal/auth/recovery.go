package auth

import (
	"context"
	"time"
)

const RecoveryTTL = 15 * time.Minute
const MaxRecoveryTTL = time.Hour

// IssueRecovery is called by the trusted local CLI, never by an anonymous HTTP endpoint.
// Issuance immediately disables the old password and revokes all portal sessions.
func (s *Service) IssueRecovery(ctx context.Context, login string, ttl time.Duration) (string, error) {
	login, e := NormalizeLogin(login)
	if e != nil || ttl <= 0 || ttl > MaxRecoveryTTL {
		return "", ErrInput
	}
	raw := RandomToken()
	now := s.Now()
	if e = s.Repo.CreateRecovery(ctx, login, TokenHash(raw), now, now.Add(ttl)); e != nil {
		return "", e
	}
	return raw, nil
}
func (s *Service) Recover(ctx context.Context, ip, token, password string) error {
	if e := s.Repo.ReserveAttempts(ctx, TokenHash("ip:"+ip), TokenHash("recovery:"+token), s.Now()); e != nil {
		return e
	}
	if !ValidToken(token) || !ValidPassword(password) {
		return ErrDenied
	}
	if !s.acquire() {
		return ErrLimited
	}
	defer func() { <-s.slots }()
	encoded, e := HashPassword(password)
	if e != nil {
		return e
	}
	// The transaction rechecks purpose, expiry, revocation, user role/state after KDF.
	// Recovery deliberately does not create a session. Login is a separate action.
	return s.Repo.CompleteRecovery(ctx, TokenHash(token), encoded, s.Now())
}
func (s *Service) ReissueInvite(ctx context.Context, login string, ttl time.Duration) (string, error) {
	login, e := NormalizeLogin(login)
	if e != nil || ttl <= 0 || ttl > 24*time.Hour {
		return "", ErrInput
	}
	raw := RandomToken()
	now := s.Now()
	if e = s.Repo.ReplaceInvite(ctx, login, TokenHash(raw), now, now.Add(ttl)); e != nil {
		return "", e
	}
	return raw, nil
}
