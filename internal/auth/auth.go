// Package auth implements user-only password authentication. Admin MFA lives in the separate adminauth package.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

var ErrDenied = errors.New("authentication denied")
var ErrLimited = errors.New("authentication rate limited")
var ErrInput = errors.New("invalid authentication input")
var ErrConflict = errors.New("login already exists")

// Parameters are fixed and bounded; encoded data cannot request arbitrary KDF resources.
const passwordPrefix = "$argon2id$v=19$m=19456,t=2,p=1$"
const Window = 5 * time.Minute

type User struct {
	ID          string `json:"id"`
	Login       string `json:"login"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
}
type Session struct {
	User
	ExpiresAt time.Time `json:"expires_at"`
	AuthTime  time.Time `json:"-"`
}
type Result struct {
	Session
	CSRF  string `json:"csrf_token"`
	Token string `json:"-"`
}
type Repository interface {
	CreateRecovery(context.Context, string, []byte, time.Time, time.Time) error
	CompleteRecovery(context.Context, []byte, string, time.Time) error
	ReplaceInvite(context.Context, string, []byte, time.Time, time.Time) error
	ReserveAttempts(context.Context, []byte, []byte, time.Time) error
	CreateInvite(context.Context, string, string, string, []byte, time.Time, time.Time) error
	PasswordCredential(context.Context, string) (string, string, error)
	AcceptInvite(context.Context, []byte, string, []byte, time.Time, time.Time) (Session, error)
	CreateSession(context.Context, string, string, []byte, time.Time, time.Time) (Session, error)
	Session(context.Context, []byte, time.Time, time.Duration) (Session, error)
	TouchSession(context.Context, []byte, time.Time, time.Duration) error
	RevokeSession(context.Context, []byte, time.Time) error
}
type Service struct {
	Repo      Repository
	Now       func() time.Time
	TTL, Idle time.Duration
	slots     chan struct{}
	dummy     string
}

func New(repo Repository, now func() time.Time, ttl, idle time.Duration) (*Service, error) {
	if now == nil {
		now = time.Now
	}
	if ttl == 0 {
		ttl = 30 * 24 * time.Hour
	}
	if idle == 0 {
		idle = 7 * 24 * time.Hour
	}
	if ttl <= 0 || ttl > 30*24*time.Hour || idle <= 0 || idle > ttl {
		return nil, ErrInput
	}
	dummy, e := HashPassword(RandomToken())
	if e != nil {
		return nil, e
	}
	return &Service{repo, now, ttl, idle, make(chan struct{}, 2), dummy}, nil
}
func RandomToken() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func TokenHash(raw string) []byte { s := sha256.Sum256([]byte(raw)); return s[:] }
func ValidToken(raw string) bool {
	b, e := base64.RawURLEncoding.DecodeString(raw)
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == raw
}
func CSRF(raw string) string {
	h := hmac.New(sha256.New, []byte(raw))
	h.Write([]byte("family-vpn/session-csrf/v1"))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
func Equal(a, b string) bool {
	return len(a) > 0 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func NormalizeLogin(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) < 3 || len(s) > 64 {
		return "", ErrInput
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return "", ErrInput
		}
	}
	return s, nil
}
func ValidPassword(s string) bool {
	return utf8.ValidString(s) && utf8.RuneCountInString(s) >= 12 && len(s) <= 1024
}
func HashPassword(password string) (string, error) {
	if !ValidPassword(password) {
		return "", ErrInput
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	key := argon2.IDKey([]byte(password), salt, 2, 19456, 1, 32)
	return passwordPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}
func VerifyPassword(password, encoded string) bool {
	if len(password) > 1024 || !strings.HasPrefix(encoded, passwordPrefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(encoded, passwordPrefix), "$")
	if len(parts) != 2 {
		return false
	}
	salt, e := base64.RawStdEncoding.DecodeString(parts[0])
	if e != nil || len(salt) != 16 {
		return false
	}
	want, e := base64.RawStdEncoding.DecodeString(parts[1])
	if e != nil || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 2, 19456, 1, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}
func (s *Service) IssueInvite(ctx context.Context, login, name string, ttl time.Duration) (string, error) {
	login, e := NormalizeLogin(login)
	if e != nil || strings.TrimSpace(name) == "" || utf8.RuneCountInString(name) > 64 || ttl <= 0 || ttl > 24*time.Hour {
		return "", ErrInput
	}
	token := RandomToken()
	now := s.Now()
	e = s.Repo.CreateInvite(ctx, RandomToken(), login, name, TokenHash(token), now, now.Add(ttl))
	if e != nil {
		return "", e
	}
	return token, nil
}
func (s *Service) acquire() bool {
	select {
	case s.slots <- struct{}{}:
		return true
	default:
		return false
	}
}
func (s *Service) Login(ctx context.Context, ip, login, password string) (Result, error) {
	normalized, e := NormalizeLogin(login)
	if e != nil {
		normalized = "invalid-login"
	}
	if e = s.Repo.ReserveAttempts(ctx, TokenHash("ip:"+ip), TokenHash("login:"+normalized), s.Now()); e != nil {
		return Result{}, e
	}
	if !s.acquire() {
		return Result{}, ErrLimited
	}
	defer func() { <-s.slots }()
	id, encoded, e := s.Repo.PasswordCredential(ctx, normalized)
	if e != nil && !errors.Is(e, ErrDenied) {
		return Result{}, e
	}
	known := e == nil
	if !known {
		encoded = s.dummy
	}
	valid := VerifyPassword(password, encoded)
	if !known || !valid {
		return Result{}, ErrDenied
	}
	token := RandomToken()
	now := s.Now()
	session, e := s.Repo.CreateSession(ctx, id, encoded, TokenHash(token), now, now.Add(s.TTL))
	if e != nil {
		return Result{}, e
	}
	return Result{session, CSRF(token), token}, nil
}
func (s *Service) Accept(ctx context.Context, ip, token, password string) (Result, error) {
	if e := s.Repo.ReserveAttempts(ctx, TokenHash("ip:"+ip), TokenHash("invite:"+token), s.Now()); e != nil {
		return Result{}, e
	}
	if !ValidToken(token) || !ValidPassword(password) {
		return Result{}, ErrDenied
	}
	if !s.acquire() {
		return Result{}, ErrLimited
	}
	defer func() { <-s.slots }()
	encoded, e := HashPassword(password)
	if e != nil {
		return Result{}, e
	}
	raw := RandomToken()
	now := s.Now()
	session, e := s.Repo.AcceptInvite(ctx, TokenHash(token), encoded, TokenHash(raw), now, now.Add(s.TTL))
	if e != nil {
		return Result{}, e
	}
	return Result{session, CSRF(raw), raw}, nil
}
func (s *Service) Authenticate(ctx context.Context, raw string) (Session, error) {
	if !ValidToken(raw) {
		return Session{}, ErrDenied
	}
	return s.Repo.Session(ctx, TokenHash(raw), s.Now(), s.Idle)
}
func (s *Service) Touch(ctx context.Context, raw string) error {
	return s.Repo.TouchSession(ctx, TokenHash(raw), s.Now(), s.Idle)
}
func (s *Service) Logout(ctx context.Context, raw string) error {
	return s.Repo.RevokeSession(ctx, TokenHash(raw), s.Now())
}
