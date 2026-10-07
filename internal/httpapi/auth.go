package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"familyvpn.local/platform/internal/auth"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"
)

const sessionCookie = "__Host-fvpn_session"
const preauthCookie = "__Host-fvpn_preauth"

type identityKey struct{}

func owner(r *http.Request) string {
	if s, ok := r.Context().Value(identityKey{}).(auth.Session); ok {
		return s.ID
	}
	return "demo-family"
}
func identity(r *http.Request) (auth.Session, bool) {
	s, ok := r.Context().Value(identityKey{}).(auth.Session)
	return s, ok
}
func authFailure(w http.ResponseWriter, e error) {
	id := w.Header().Get("X-Request-ID")
	switch {
	case errors.Is(e, auth.ErrDenied):
		fail(w, 401, "AUTH_FAILED", "Не удалось войти. Проверьте данные или запросите новое приглашение.", id)
	case errors.Is(e, auth.ErrLimited):
		w.Header().Set("Retry-After", "300")
		fail(w, 429, "RATE_LIMITED", "Слишком много попыток. Повторите через 5 минут.", id)
	case errors.Is(e, auth.ErrInput):
		fail(w, 400, "INVALID_INPUT", "Проверьте введённые данные", id)
	default:
		unavailable(w)
	}
}
func setSession(w http.ResponseWriter, result auth.Result, now time.Time) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: result.Token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: result.ExpiresAt, MaxAge: int(result.ExpiresAt.Sub(now).Seconds())})
	clearCookie(w, preauthCookie)
}
func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
}
func cookieValue(r *http.Request, name string) string {
	var value string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == name {
			value = c.Value
			count++
		}
	}
	if count != 1 {
		return ""
	}
	return value
}
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	typ, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || typ != "application/json" {
		fail(w, 415, "JSON_REQUIRED", "Ожидается JSON", w.Header().Get("X-Request-ID"))
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e = d.Decode(v); e == nil {
		var extra any
		e = d.Decode(&extra)
		if e == io.EOF {
			return true
		}
	}
	fail(w, 400, "INVALID_JSON", "Некорректный JSON или превышен размер запроса", w.Header().Get("X-Request-ID"))
	return false
}
func authRoutes(mux *http.ServeMux, s *auth.Service) {
	mux.HandleFunc("POST /api/v1/auth/recovery/consume", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Token       string `json:"token"`
			NewPassword string `json:"new_password"`
		}
		if !decodeBody(w, r, &in) {
			return
		}
		ip, _, e := net.SplitHostPort(r.RemoteAddr)
		if e != nil {
			ip = r.RemoteAddr
		}
		if e = s.Recover(r.Context(), ip, in.Token, in.NewPassword); e != nil {
			if errors.Is(e, auth.ErrDenied) {
				fail(w, 401, "RECOVERY_FAILED", "Не удалось восстановить доступ. Проверьте код и пароль или запросите новый код у администратора.", w.Header().Get("X-Request-ID"))
			} else {
				authFailure(w, e)
			}
			return
		}
		// No auto-login after recovery. Clear both cookies and require normal login.
		clearCookie(w, sessionCookie)
		clearCookie(w, preauthCookie)
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /api/v1/auth/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		token := auth.RandomToken()
		http.SetCookie(w, &http.Cookie{Name: preauthCookie, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 600})
		writeJSON(w, 200, map[string]string{"mode": "local-auth", "csrf_token": token})
	})
	mux.HandleFunc("POST /api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Login    string `json:"login"`
			Password string `json:"password"`
		}
		if !decodeBody(w, r, &in) {
			return
		}
		ip, _, e := net.SplitHostPort(r.RemoteAddr)
		if e != nil {
			ip = r.RemoteAddr
		}
		result, e := s.Login(r.Context(), ip, in.Login, in.Password)
		if e != nil {
			authFailure(w, e)
			return
		}
		setSession(w, result, s.Now())
		writeJSON(w, 200, result)
	})
	mux.HandleFunc("POST /api/v1/auth/invitations/accept", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Token    string `json:"token"`
			Password string `json:"password"`
		}
		if !decodeBody(w, r, &in) {
			return
		}
		ip, _, e := net.SplitHostPort(r.RemoteAddr)
		if e != nil {
			ip = r.RemoteAddr
		}
		result, e := s.Accept(r.Context(), ip, in.Token, in.Password)
		if e != nil {
			authFailure(w, e)
			return
		}
		setSession(w, result, s.Now())
		writeJSON(w, 200, result)
	})
	mux.HandleFunc("POST /api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		var in struct{}
		if !decodeBody(w, r, &in) {
			return
		}
		if e := s.Logout(r.Context(), cookieValue(r, sessionCookie)); e != nil {
			authFailure(w, e)
			return
		}
		clearCookie(w, sessionCookie)
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /api/v1/auth/session/touch", func(w http.ResponseWriter, r *http.Request) {
		var in struct{}
		if !decodeBody(w, r, &in) {
			return
		}
		if e := s.Touch(r.Context(), cookieValue(r, sessionCookie)); e != nil {
			authFailure(w, e)
			return
		}
		w.WriteHeader(204)
	})
}

type sessionAuthenticator interface {
	Authenticate(context.Context, string) (auth.Session, error)
}

func authenticateRequest(w http.ResponseWriter, r *http.Request, s sessionAuthenticator, host string, admin bool) (*http.Request, bool) {
	id := w.Header().Get("X-Request-ID")
	sessionName, preauthName := sessionCookie, preauthCookie
	if admin {
		sessionName, preauthName = adminSessionCookie, adminPreauthCookie
	}
	if r.TLS == nil {
		fail(w, 403, "TLS_REQUIRED", "Требуется HTTPS", id)
		return r, false
	}
	if r.URL.RawQuery != "" && (r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/api/v1/auth/")) {
		fail(w, 400, "QUERY_FORBIDDEN", "Параметры авторизации передаются только в теле запроса", id)
		return r, false
	}
	if !admin && (strings.HasPrefix(r.URL.Path, "/api/v1/admin/") || strings.HasPrefix(r.URL.Path, "/api/v1/auth/admin/")) {
		fail(w, 404, "NOT_FOUND", "Endpoint не найден", id)
		return r, false
	}
	// No forwarded headers are trusted; exact configured origin plus JSON and CSRF for every POST.
	if r.Method != "GET" && r.Method != "HEAD" {
		if r.Header.Get("Origin") != "https://"+host || (r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "same-origin") {
			fail(w, 403, "INVALID_ORIGIN", "Недопустимый источник запроса", id)
			return r, false
		}
	}
	p := r.URL.Path
	anonymous := p == "/api/v1/auth/login" || p == "/api/v1/auth/invitations/accept" || p == "/api/v1/auth/recovery/consume"
	if admin {
		anonymous = p == "/api/v1/auth/admin/password" || p == "/api/v1/auth/admin/totp"
	}
	if anonymous {
		raw := cookieValue(r, preauthName)
		if !auth.ValidToken(raw) || !auth.Equal(raw, r.Header.Get("X-CSRF-Token")) {
			fail(w, 403, "CSRF_FAILED", "Обновите страницу входа", id)
			return r, false
		}
		return r, true
	}
	if p == "/api/v1/auth/bootstrap" || p == "/healthz" || p == "/readyz" || !strings.HasPrefix(p, "/api/") {
		return r, true
	}
	raw := cookieValue(r, sessionName)
	session, e := s.Authenticate(r.Context(), raw)
	if e != nil {
		authFailure(w, e)
		return r, false
	}
	if r.Method != "GET" && r.Method != "HEAD" && !auth.Equal(auth.CSRF(raw), r.Header.Get("X-CSRF-Token")) {
		fail(w, 403, "CSRF_FAILED", "Обновите страницу кабинета", id)
		return r, false
	}
	return r.WithContext(context.WithValue(r.Context(), identityKey{}, session)), true
}
