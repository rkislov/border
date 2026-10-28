package web

import (
	"github.com/rkislov/border/internal/store"
	"net/http"
	"time"
)

func (a *app) retentionRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/retention", func(w http.ResponseWriter, r *http.Request) {
		p, err := a.s.Retention(r.Context())
		if err != nil {
			http.Error(w, "retention unavailable", 503)
			return
		}
		reply(w, p)
	})
	m.HandleFunc("POST /api/retention/preview", func(w http.ResponseWriter, r *http.Request) {
		var p store.RetentionPolicy
		if !decode(w, r, &p) {
			return
		}
		if err := p.Validate(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		result, err := a.s.PreviewRetention(r.Context(), p, time.Now())
		if err != nil {
			http.Error(w, "preview unavailable", 503)
			return
		}
		reply(w, result)
	})
	m.HandleFunc("POST /api/retention", func(w http.ResponseWriter, r *http.Request) {
		var p store.RetentionPolicy
		if !decode(w, r, &p) {
			return
		}
		if err := p.Validate(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		a.finish(w, r, a.s.SaveRetention(r.Context(), p), "save history retention policy")
	})
}
