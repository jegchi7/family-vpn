package httpapi

import (
	"familyvpn.local/platform/internal/guides"
	"fmt"
	"net/http"
)

func offlineGuideRoutes(mux *http.ServeMux, c *guides.Catalog) {
	mux.HandleFunc("GET /api/v1/instructions/{id}/offline", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			fail(w, 400, "QUERY_FORBIDDEN", "Памятка не принимает параметры", w.Header().Get("X-Request-ID"))
			return
		}
		guide, ok := c.Get(r.PathValue("id"))
		if !ok {
			fail(w, 404, "NOT_FOUND", "Инструкция не найдена", w.Header().Get("X-Request-ID"))
			return
		}
		body, e := guides.Render(guide)
		if e != nil {
			unavailable(w)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="family-vpn-guide-%s-v%d.html"`, guide.ID, guide.ContentVersion))
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		_, _ = w.Write(body)
	})
}
