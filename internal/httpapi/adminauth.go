package httpapi

import (
	"familyvpn.local/platform/internal/adminauth"
	"familyvpn.local/platform/internal/auth"
	"net"
	"net/http"
)

const adminSessionCookie = "__Host-fvpn_admin_session"
const adminPreauthCookie = "__Host-fvpn_admin_preauth"

func remoteIP(r *http.Request) string {
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return r.RemoteAddr
	}
	return ip
}
func adminAuthRoutes(mux *http.ServeMux, s *adminauth.Service) {
	mux.HandleFunc("GET /api/v1/auth/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		token := auth.RandomToken()
		http.SetCookie(w, &http.Cookie{Name: adminPreauthCookie, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 600})
		writeJSON(w, 200, map[string]string{"mode": "local-admin", "csrf_token": token})
	})
	mux.HandleFunc("POST /api/v1/auth/admin/password", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Login    string `json:"login"`
			Password string `json:"password"`
		}
		if !decodeBody(w, r, &in) {
			return
		}
		result, e := s.Login(r.Context(), remoteIP(r), cookieValue(r, adminPreauthCookie), in.Login, in.Password)
		if e != nil {
			authFailure(w, e)
			return
		}
		writeJSON(w, 200, result)
	})
	mux.HandleFunc("POST /api/v1/auth/admin/totp", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Challenge string `json:"challenge"`
			Code      string `json:"code"`
		}
		if !decodeBody(w, r, &in) {
			return
		}
		result, e := s.Finish(r.Context(), remoteIP(r), cookieValue(r, adminPreauthCookie), in.Challenge, in.Code)
		if e != nil {
			authFailure(w, e)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: adminSessionCookie, Value: result.Token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: result.ExpiresAt, MaxAge: int(adminauth.TTL.Seconds())})
		clearCookie(w, adminPreauthCookie)
		writeJSON(w, 200, result)
	})
	mux.HandleFunc("POST /api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		var in struct{}
		if !decodeBody(w, r, &in) {
			return
		}
		if e := s.Logout(r.Context(), cookieValue(r, adminSessionCookie)); e != nil {
			authFailure(w, e)
			return
		}
		clearCookie(w, adminSessionCookie)
		clearCookie(w, adminPreauthCookie)
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /api/v1/auth/session/touch", func(w http.ResponseWriter, r *http.Request) {
		var in struct{}
		if !decodeBody(w, r, &in) {
			return
		}
		if e := s.Touch(r.Context(), cookieValue(r, adminSessionCookie)); e != nil {
			authFailure(w, e)
			return
		}
		w.WriteHeader(204)
	})
}
