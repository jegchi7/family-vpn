package adminauth

import (
	"context"
	"errors"
	"familyvpn.local/platform/internal/auth"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"time"
)

const TTL = 12 * time.Hour
const Idle = 30 * time.Minute
const ChallengeTTL = 3 * time.Minute
const EnrollmentTTL = 10 * time.Minute

type Credential struct {
	ID, Login, DisplayName, PasswordHash, KeyID string
	Ciphertext                                  []byte
	LastStep                                    int64
}
type Repository interface {
	ReserveAttempts(context.Context, []byte, []byte, time.Time) error
	AdminID(context.Context, string) (string, error)
	AdminCredential(context.Context, string) (Credential, error)
	AdminEnroll(context.Context, Credential, bool, time.Time, time.Time) error
	AdminConfirm(context.Context, string, string, time.Time, func(Credential, string) (int64, error)) error
	AdminDisable(context.Context, string, time.Time) error
	AdminChallenge(context.Context, Credential, []byte, []byte, time.Time, time.Time) error
	AdminFinish(context.Context, []byte, []byte, string, []byte, time.Time, time.Time, func(Credential, string) (int64, error)) (auth.Session, error)
	AdminSession(context.Context, []byte, time.Time, time.Duration) (auth.Session, error)
	AdminTouch(context.Context, []byte, time.Time, time.Duration) error
	AdminLogout(context.Context, []byte, time.Time) error
	CheckAdminKey(context.Context, *Vault) error
}
type Service struct {
	Repo  Repository
	Vault *Vault
	Now   func() time.Time
	slots chan struct{}
	dummy string
}
type Challenge struct {
	Token     string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

func New(repo Repository, vault *Vault, now func() time.Time) (*Service, error) {
	if vault == nil {
		return nil, ErrKey
	}
	if now == nil {
		now = time.Now
	}
	if e := repo.CheckAdminKey(context.Background(), vault); e != nil {
		return nil, e
	}
	dummy, e := auth.HashPassword(auth.RandomToken())
	if e != nil {
		return nil, e
	}
	return &Service{repo, vault, now, make(chan struct{}, 2), dummy}, nil
}
func (s *Service) Enroll(ctx context.Context, login, name, password string, reset bool) (string, error) {
	login, e := auth.NormalizeLogin(login)
	if e != nil || len(name) == 0 || len(name) > 256 {
		return "", auth.ErrInput
	}
	encoded, e := auth.HashPassword(password)
	if e != nil {
		return "", e
	}
	key, e := totp.Generate(totp.GenerateOpts{Issuer: "Family VPN Admin", AccountName: login, SecretSize: 20, Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if e != nil {
		return "", e
	}
	id := auth.RandomToken()
	if reset {
		id, e = s.Repo.AdminID(ctx, login)
		if e != nil {
			return "", e
		}
	}
	c := Credential{ID: id, Login: login, DisplayName: name, PasswordHash: encoded, KeyID: s.Vault.ID, Ciphertext: s.Vault.Seal(id, key.Secret()), LastStep: -1}
	now := s.Now()
	if e = s.Repo.AdminEnroll(ctx, c, reset, now, now.Add(EnrollmentTTL)); e != nil {
		return "", e
	}
	return key.Secret(), nil
}
func (s *Service) verify(c Credential, code string) (int64, error) {
	secret, e := s.Vault.Open(c.ID, c.KeyID, c.Ciphertext)
	if e != nil {
		return 0, e
	}
	now := s.Now().UTC()
	step := now.Unix() / 30
	// Test each accepted step explicitly so the database can enforce monotonic replay protection.
	for _, delta := range []int64{0, -1, 1} {
		candidate := step + delta
		if candidate <= c.LastStep {
			continue
		}
		valid, e := totp.ValidateCustom(code, secret, time.Unix(candidate*30, 0), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if e == nil && valid {
			return candidate, nil
		}
	}
	return 0, auth.ErrDenied
}
func (s *Service) Confirm(ctx context.Context, login, code string) error {
	login, e := auth.NormalizeLogin(login)
	if e != nil {
		return auth.ErrDenied
	}
	if e = s.Repo.ReserveAttempts(ctx, auth.TokenHash("admin-cli"), auth.TokenHash("enroll:"+login), s.Now()); e != nil {
		return e
	}
	return s.Repo.AdminConfirm(ctx, login, code, s.Now(), s.verify)
}
func (s *Service) Login(ctx context.Context, ip, binding, login, password string) (Challenge, error) {
	normalized, e := auth.NormalizeLogin(login)
	if e != nil {
		normalized = "invalid-login"
	}
	if !auth.ValidToken(binding) {
		return Challenge{}, auth.ErrDenied
	}
	if e = s.Repo.ReserveAttempts(ctx, auth.TokenHash("admin-ip:"+ip), auth.TokenHash("admin-login:"+normalized), s.Now()); e != nil {
		return Challenge{}, e
	}
	select {
	case s.slots <- struct{}{}:
	default:
		return Challenge{}, auth.ErrLimited
	}
	defer func() { <-s.slots }()
	c, e := s.Repo.AdminCredential(ctx, normalized)
	if e != nil && !errors.Is(e, auth.ErrDenied) {
		return Challenge{}, e
	}
	known := e == nil
	encoded := c.PasswordHash
	if !known {
		encoded = s.dummy
	}
	valid := auth.VerifyPassword(password, encoded)
	if !known || !valid {
		return Challenge{}, auth.ErrDenied
	}
	now := s.Now()
	ch := Challenge{auth.RandomToken(), now.Add(ChallengeTTL)}
	e = s.Repo.AdminChallenge(ctx, c, auth.TokenHash(ch.Token), auth.TokenHash(binding), now, ch.ExpiresAt)
	return ch, e
}
func (s *Service) Finish(ctx context.Context, ip, binding, challenge, code string) (auth.Result, error) {
	if !auth.ValidToken(binding) || !auth.ValidToken(challenge) {
		return auth.Result{}, auth.ErrDenied
	}
	if e := s.Repo.ReserveAttempts(ctx, auth.TokenHash("admin-ip:"+ip), auth.TokenHash("admin-challenge:"+challenge), s.Now()); e != nil {
		return auth.Result{}, e
	}
	raw := auth.RandomToken()
	now := s.Now()
	session, e := s.Repo.AdminFinish(ctx, auth.TokenHash(challenge), auth.TokenHash(binding), code, auth.TokenHash(raw), now, now.Add(TTL), s.verify)
	if e != nil {
		return auth.Result{}, e
	}
	return auth.Result{Session: session, Token: raw, CSRF: auth.CSRF(raw)}, nil
}
func (s *Service) Authenticate(ctx context.Context, raw string) (auth.Session, error) {
	if !auth.ValidToken(raw) {
		return auth.Session{}, auth.ErrDenied
	}
	return s.Repo.AdminSession(ctx, auth.TokenHash(raw), s.Now(), Idle)
}
func (s *Service) Touch(ctx context.Context, raw string) error {
	return s.Repo.AdminTouch(ctx, auth.TokenHash(raw), s.Now(), Idle)
}
func (s *Service) Logout(ctx context.Context, raw string) error {
	return s.Repo.AdminLogout(ctx, auth.TokenHash(raw), s.Now())
}
