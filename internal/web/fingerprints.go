package web

import (
	"github.com/rkislov/border/internal/store"
	"net/http"
)

func (a *app) fingerprintRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/fingerprints", func(w http.ResponseWriter, r *http.Request) {
		f, err := a.s.Fingerprints(r.Context())
		if err != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		reply(w, f)
	})
	m.HandleFunc("POST /api/fingerprints", func(w http.ResponseWriter, r *http.Request) {
		var f store.Fingerprint
		if !decode(w, r, &f) {
			return
		}
		f.Source = "admin"
		a.finish(w, r, a.s.ObserveFingerprint(r.Context(), f), "save device fingerprint")
	})
	m.HandleFunc("POST /api/fingerprints/oui", func(w http.ResponseWriter, r *http.Request) {
		var v struct{ Prefix, Manufacturer string }
		if !decode(w, r, &v) {
			return
		}
		a.finish(w, r, a.s.SetOUI(r.Context(), v.Prefix, v.Manufacturer), "save OUI prefix")
	})
	m.HandleFunc("GET /api/fingerprints/history", func(w http.ResponseWriter, r *http.Request) {
		rows, err := a.s.DB.QueryContext(r.Context(), a.s.SQL("SELECT observed_at,source,detail FROM fingerprint_history WHERE mac=? ORDER BY observed_at DESC,id DESC LIMIT 100"), r.URL.Query().Get("mac"))
		if err != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		defer rows.Close()
		type entry struct {
			Time           int64
			Source, Detail string
		}
		out := []entry{}
		for rows.Next() {
			var v entry
			if err = rows.Scan(&v.Time, &v.Source, &v.Detail); err != nil {
				http.Error(w, "database unavailable", 503)
				return
			}
			out = append(out, v)
		}
		if rows.Err() != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		reply(w, out)
	})
}
