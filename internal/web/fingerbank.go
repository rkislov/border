package web

import (
	"github.com/rkislov/border/internal/fingerbank"
	"net/http"
)

func (a *app) fingerbankRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/fingerbank/config", func(w http.ResponseWriter, r *http.Request) {
		c, err := a.fingerbank.Config(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 503)
			return
		}
		reply(w, map[string]any{"Enabled": c.Enabled, "TTLHours": c.TTLHours, "HasKey": c.Key != ""})
	})
	m.HandleFunc("POST /api/fingerbank/config", func(w http.ResponseWriter, r *http.Request) {
		var c fingerbank.Config
		if !decode(w, r, &c) {
			return
		}
		a.finish(w, r, a.fingerbank.Save(r.Context(), c), "save encrypted Fingerbank configuration")
	})
	m.HandleFunc("POST /api/fingerbank/lookup", func(w http.ResponseWriter, r *http.Request) {
		var v struct{ MAC string }
		if !decode(w, r, &v) {
			return
		}
		var e fingerbank.Evidence
		if err := a.s.Row(r.Context(), "SELECT mac,dhcp_options,vendor_class FROM device_fingerprints WHERE mac=?", v.MAC).Scan(&e.MAC, &e.DHCP, &e.Vendor); err != nil {
			http.Error(w, "device fingerprint not found", 404)
			return
		}
		result, err := a.fingerbank.Lookup(r.Context(), "default", e)
		if err != nil {
			http.Error(w, err.Error(), 503)
			return
		}
		reply(w, result)
	})
}
