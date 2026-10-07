package httpapi

import (
	"errors"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/repository"
	"net/http"
	"net/url"
	"strconv"
)

func parseAdminQuery(r *http.Request) (url.Values, error) {
	if len(r.URL.RawQuery) > 1024 {
		return nil, auth.ErrInput
	}
	return url.ParseQuery(r.URL.RawQuery)
}
func adminViewFailure(w http.ResponseWriter, e error) {
	if errors.Is(e, auth.ErrInput) {
		fail(w, 400, "INVALID_PAGE", "Некорректный курсор или параметры страницы", w.Header().Get("X-Request-ID"))
		return
	}
	unavailable(w)
}

func adminPageRequest(w http.ResponseWriter, r *http.Request, device bool) (domain.PageRequest, bool) {
	q, e := parseAdminQuery(r)
	if e != nil {
		fail(w, 400, "INVALID_PAGE", "Некорректные параметры страницы", w.Header().Get("X-Request-ID"))
		return domain.PageRequest{}, false
	}
	for k, v := range q {
		if len(v) != 1 || (k != "limit" && k != "after" && !(device && k == "state")) {
			fail(w, 400, "INVALID_PAGE", "Некорректные параметры страницы", w.Header().Get("X-Request-ID"))
			return domain.PageRequest{}, false
		}
	}
	limit := 25
	if raw, ok := q["limit"]; ok {
		limit, e = strconv.Atoi(raw[0])
		if e != nil || limit < 1 || limit > 100 {
			fail(w, 400, "INVALID_PAGE", "Размер страницы: от 1 до 100", w.Header().Get("X-Request-ID"))
			return domain.PageRequest{}, false
		}
	}
	if len(q.Get("after")) > 256 {
		fail(w, 400, "INVALID_PAGE", "Некорректный курсор", w.Header().Get("X-Request-ID"))
		return domain.PageRequest{}, false
	}
	return domain.PageRequest{Limit: limit, After: q.Get("after")}, true
}
func adminViewRoutes(mux *http.ServeMux, reader repository.AdminReader) {
	mux.HandleFunc("GET /api/v1/admin/users", func(w http.ResponseWriter, r *http.Request) {
		request, ok := adminPageRequest(w, r, false)
		if !ok {
			return
		}
		page, e := reader.AdminUsers(r.Context(), request)
		if e != nil {
			adminViewFailure(w, e)
			return
		}
		writeJSON(w, 200, page)
	})
	mux.HandleFunc("GET /api/v1/admin/devices", func(w http.ResponseWriter, r *http.Request) {
		request, ok := adminPageRequest(w, r, true)
		if !ok {
			return
		}
		state := r.URL.Query().Get("state")
		if state == "" {
			state = "pending"
		}
		page, e := reader.AdminDevices(r.Context(), request, state)
		if e != nil {
			adminViewFailure(w, e)
			return
		}
		writeJSON(w, 200, page)
	})
	mux.HandleFunc("GET /api/v1/admin/audit", func(w http.ResponseWriter, r *http.Request) {
		request, ok := adminPageRequest(w, r, false)
		if !ok {
			return
		}
		page, e := reader.AdminAudit(r.Context(), request)
		if e != nil {
			adminViewFailure(w, e)
			return
		}
		writeJSON(w, 200, page)
	})
}
