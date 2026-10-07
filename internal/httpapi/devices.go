package httpapi

import (
	"errors"
	"familyvpn.local/platform/internal/auth"
	"familyvpn.local/platform/internal/domain"
	"familyvpn.local/platform/internal/repository"
	"familyvpn.local/platform/internal/store"
	"net/http"
)

func deviceFailure(w http.ResponseWriter, e error) {
	id := w.Header().Get("X-Request-ID")
	switch {
	case errors.Is(e, store.ErrNotFound):
		fail(w, 404, "NOT_FOUND", "Устройство не найдено", id)
	case errors.Is(e, store.ErrConflict):
		fail(w, 409, "REVISION_CONFLICT", "Запись уже изменилась или запрос использован с другими данными. Обновите список.", id)
	case errors.Is(e, domain.ErrDeviceInput):
		fail(w, 400, "INVALID_DEVICE", "Проверьте название, ОС и параметры запроса", id)
	case errors.Is(e, domain.ErrDeviceLimit):
		fail(w, 409, "DEVICE_LIMIT", "Достигнут лимит устройств или истории заявок. Обратитесь к администратору.", id)
	case errors.Is(e, domain.ErrDeviceState):
		fail(w, 409, "DEVICE_STATE", "Действие недоступно для этого состояния. Для отзыва выданного доступа нужен администратор.", id)
	case errors.Is(e, auth.ErrDenied):
		authFailure(w, e)
	default:
		unavailable(w)
	}
}

// Registered only on an authenticated user listener; it records local intent, never provisions a peer.
func deviceRoutes(mux *http.ServeMux, repo repository.DeviceWriter) {
	mux.HandleFunc("GET /api/v1/devices/quota", func(w http.ResponseWriter, r *http.Request) {
		q, e := repo.DeviceQuota(r.Context(), owner(r))
		if e != nil {
			deviceFailure(w, e)
			return
		}
		writeJSON(w, 200, q)
	})
	mux.HandleFunc("POST /api/v1/devices", func(w http.ResponseWriter, r *http.Request) {
		var in domain.DeviceRequest
		if !decodeBody(w, r, &in) {
			return
		}
		d, e := repo.RequestDevice(r.Context(), owner(r), in)
		if e != nil {
			deviceFailure(w, e)
			return
		}
		writeJSON(w, 200, d)
	})
	mux.HandleFunc("POST /api/v1/devices/{id}/rename", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Name     string `json:"name"`
			Revision int    `json:"expected_revision"`
		}
		if !decodeBody(w, r, &in) {
			return
		}
		d, e := repo.RenameDevice(r.Context(), owner(r), r.PathValue("id"), in.Name, in.Revision)
		if e != nil {
			deviceFailure(w, e)
			return
		}
		writeJSON(w, 200, d)
	})
	mux.HandleFunc("POST /api/v1/devices/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Revision int `json:"expected_revision"`
		}
		if !decodeBody(w, r, &in) {
			return
		}
		d, e := repo.CancelDeviceRequest(r.Context(), owner(r), r.PathValue("id"), in.Revision)
		if e != nil {
			deviceFailure(w, e)
			return
		}
		writeJSON(w, 200, d)
	})
}
