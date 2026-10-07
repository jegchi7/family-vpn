package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"familyvpn.local/platform/internal/adapters/fake"
	"familyvpn.local/platform/internal/adminauth"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/guides"
	"familyvpn.local/platform/internal/repository"
)

type Options struct {
	Admin     bool
	Host      string
	WebDir    string
	Now       func() time.Time
	Store     repository.Reader
	Auth      *auth.Service
	AdminAuth *adminauth.Service
	Devices   repository.DeviceWriter
	AdminData repository.AdminReader
	Guides    *guides.Catalog
}
type APIError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
	Retryable bool   `json:"retryable"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, code int, name, message, id string) {
	writeJSON(w, code, map[string]any{"error": APIError{name, message, id, false}})
}

// New serves explicit demo fixtures or separate local user/admin authentication.
func New(o Options) http.Handler {
	if o.Guides != nil && o.Auth == nil && o.AdminAuth == nil {
		panic("versioned catalog requires authenticated local listener")
	}
	if o.AdminData != nil && (o.AdminAuth == nil || !o.Admin || o.Auth != nil) {
		panic("admin data requires authenticated management listener")
	}
	if o.Auth != nil && (o.Admin || o.Store == nil) {
		panic("invalid local auth API configuration")
	}
	if o.AdminAuth != nil && (!o.Admin || o.Auth != nil || o.Store == nil) {
		panic("invalid admin auth configuration")
	}
	if o.Devices != nil && (o.Auth == nil || o.Admin) {
		panic("device mutations require user auth listener")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Store == nil {
		o.Store = fake.New(o.Now())
	}
	mux := http.NewServeMux()
	if o.Guides != nil {
		offlineGuideRoutes(mux, o.Guides)
	}
	if o.AdminData != nil {
		adminViewRoutes(mux, o.AdminData)
	}
	if o.Devices != nil {
		deviceRoutes(mux, o.Devices)
	}
	mode := "demo"
	if o.Auth != nil {
		mode = "local-auth"
	}
	if o.AdminAuth != nil {
		mode = "local-admin"
		adminAuthRoutes(mux, o.AdminAuth)
	}
	if o.Auth != nil {
		authRoutes(mux, o.Auth)
	}
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := o.Store.Ping(r.Context()); err != nil {
			unavailable(w)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok", "mode": mode})
	})
	mux.HandleFunc("GET /api/v1/me", func(w http.ResponseWriter, r *http.Request) {
		if s, ok := identity(r); ok {
			writeJSON(w, 200, map[string]any{"id": s.ID, "display_name": s.DisplayName, "role": s.Role, "mode": mode, "storage": o.Store.Backend(), "csrf_token": auth.CSRF(cookieValue(r, selectedSessionCookie(o.Admin)))})
			return
		}
		role := "user"
		name := "Семейный кабинет"
		if o.Admin {
			role = "admin"
			name = "Администратор · демо"
		}
		writeJSON(w, 200, map[string]any{"id": "demo-family", "display_name": name, "role": role, "mode": "demo", "storage": o.Store.Backend()})
	})
	mux.HandleFunc("GET /api/v1/devices", func(w http.ResponseWriter, r *http.Request) {
		devices, err := o.Store.DevicesForOwner(r.Context(), owner(r))
		if err != nil {
			unavailable(w)
			return
		}
		writeJSON(w, 200, map[string]any{"items": devices})
	})
	mux.HandleFunc("GET /api/v1/devices/{id}", func(w http.ResponseWriter, r *http.Request) {
		devices, err := o.Store.DevicesForOwner(r.Context(), owner(r))
		if err != nil {
			unavailable(w)
			return
		}
		for _, d := range devices {
			if d.ID == r.PathValue("id") {
				writeJSON(w, 200, d)
				return
			}
		}
		fail(w, 404, "NOT_FOUND", "Объект не найден", w.Header().Get("X-Request-ID"))
	})
	mux.HandleFunc("GET /api/v1/profiles/{id}/download", func(w http.ResponseWriter, r *http.Request) {
		id := w.Header().Get("X-Request-ID")
		p, ok, err := o.Store.ProfileForOwner(r.Context(), owner(r), r.PathValue("id"))
		if err != nil {
			unavailable(w)
			return
		}
		if !ok {
			fail(w, 404, "NOT_FOUND", "Объект не найден", id)
			return
		}
		if p.State != "ready" {
			fail(w, 409, "PROFILE_NOT_READY", "Профиль ещё не готов", id)
			return
		}
		if format := r.URL.Query().Get("format"); format != "" && format != "txt" {
			fail(w, 400, "UNSUPPORTED_FORMAT", "Демо выдаёт только текстовую памятку", id)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="demo-profile.txt"`)
		fmt.Fprintf(w, "ДЕМОНСТРАЦИЯ — НЕ VPN-КОНФИГ\nПротокол: %s\nЗдесь нет ключей, адресов VPS и рабочего доступа. Не импортируйте этот файл в VPN-клиент.\n", p.Protocol)
	})
	mux.HandleFunc("GET /api/v1/instructions", func(w http.ResponseWriter, r *http.Request) {
		if o.Guides != nil {
			writeJSON(w, 200, map[string]any{"items": o.Guides.List()})
			return
		}
		guides, err := o.Store.Instructions(r.Context())
		if err != nil {
			unavailable(w)
			return
		}
		writeJSON(w, 200, map[string]any{"items": guides})
	})
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		samples := []domain.Health{}
		health, err := o.Store.HealthSamples(r.Context())
		if err != nil {
			unavailable(w)
			return
		}
		for _, h := range health {
			samples = append(samples, h.At(o.Now()))
		}
		writeJSON(w, 200, map[string]any{"mode": mode, "items": samples})
	})
	if o.Admin {
		mux.HandleFunc("GET /api/v1/admin/overview", func(w http.ResponseWriter, r *http.Request) {
			count, err := o.Store.DeviceCount(r.Context())
			if err != nil {
				unavailable(w)
				return
			}
			writeJSON(w, 200, map[string]any{"mode": mode, "total_devices": count, "mutations_enabled": false, "message": "Управление узлами отключено. Данные сохранены локально; подключения к VPS и VPN-ядрам нет.", "components": []string{"Публичный API: отдельный listener", "Агент: ещё не реализован", "Контроллер: ещё не реализован", "Хранилище: " + o.Store.Backend()}})
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		id := w.Header().Get("X-Request-ID")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			fail(w, 404, "NOT_FOUND", "Endpoint не найден", id)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			fail(w, 405, "METHOD_NOT_ALLOWED", "Разрешено только чтение", id)
			return
		}
		if o.WebDir == "" {
			fail(w, 503, "WEB_NOT_BUILT", "Сначала выполните npm run build", id)
			return
		}
		clean := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if clean == "." || clean == "" {
			clean = "index.html"
		}
		// os.DirFS serves only build assets. Reject dotfiles; no directory listing or SPA fallback for missing assets.
		for _, segment := range strings.Split(clean, "/") {
			if strings.HasPrefix(segment, ".") {
				http.NotFound(w, r)
				return
			}
		}
		root := os.DirFS(o.WebDir)
		file, err := root.Open(clean)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		st, err := file.Stat()
		_ = file.Close()
		if err != nil || st.IsDir() {
			http.NotFound(w, r)
			return
		}
		http.FileServer(http.FS(fs.FS(root))).ServeHTTP(w, r)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		id := hex.EncodeToString(b)
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		// Exact numeric loopback Host prevents DNS rebinding. No permissive CORS.
		if r.Host != o.Host {
			fail(w, 403, "INVALID_HOST", "Недопустимый Host", id)
			return
		}
		if o.Auth != nil || o.AdminAuth != nil {
			var ok bool
			var a sessionAuthenticator = o.Auth
			if o.AdminAuth != nil {
				a = o.AdminAuth
			}
			r, ok = authenticateRequest(w, r, a, o.Host, o.Admin)
			if !ok {
				return
			}
		} else if r.Method != "GET" && r.Method != "HEAD" {
			fail(w, 405, "READ_ONLY_DEMO", "Изменения в этом демо отключены", id)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func ValidateListen(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("demo must bind a numeric loopback address, got %q", addr)
	}
	return nil
}

func unavailable(w http.ResponseWriter) {
	fail(w, 503, "STORAGE_UNAVAILABLE", "Хранилище временно недоступно", w.Header().Get("X-Request-ID"))
}

func selectedSessionCookie(admin bool) string {
	if admin {
		return adminSessionCookie
	}
	return sessionCookie
}
