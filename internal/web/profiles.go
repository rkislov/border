package web

import (
	"github.com/rkislov/border/internal/radprofile"
	"net/http"
)

func (a *app) profileRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/nas/compatibility", a.nasCompatibility)
	m.HandleFunc("GET /api/dictionaries", func(w http.ResponseWriter, r *http.Request) {
		type entry struct {
			radprofile.Profile
			Capabilities radprofile.Capabilities
		}
		result := []entry{}
		for _, p := range radprofile.Catalog {
			c, _ := radprofile.Describe(p.ID)
			result = append(result, entry{p, c})
		}
		reply(w, result)
	})
	m.HandleFunc("GET /api/nas/grants", func(w http.ResponseWriter, r *http.Request) {
		g, err := a.s.NASGrants(r.Context())
		if err != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		reply(w, g)
	})
	m.HandleFunc("POST /api/nas/grants", func(w http.ResponseWriter, r *http.Request) {
		var g radprofile.Grant
		if !decode(w, r, &g) {
			return
		}
		if err := g.Validate(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		c, err := a.s.NASProfile(r.Context(), g.NAS)
		if err != nil || c.Mode != g.Mode {
			http.Error(w, "grant must match NAS mode", 400)
			return
		}
		a.finish(w, r, a.s.Exec(r.Context(), "INSERT INTO nas_grants(nas,username,mode,role,group_name,filter_id,privilege) VALUES(?,?,?,?,?,?,?) ON CONFLICT(nas,username,mode) DO UPDATE SET role=excluded.role,group_name=excluded.group_name,filter_id=excluded.filter_id,privilege=excluded.privilege", g.NAS, g.Username, g.Mode, g.Role, g.Group, g.Filter, g.Privilege), "save NAS authorization")
	})
	m.HandleFunc("POST /api/nas/grants/delete", func(w http.ResponseWriter, r *http.Request) {
		var g radprofile.Grant
		if !decode(w, r, &g) {
			return
		}
		a.finish(w, r, a.s.Exec(r.Context(), "DELETE FROM nas_grants WHERE nas=? AND username=? AND mode=?", g.NAS, g.Username, g.Mode), "delete NAS authorization")
	})
}
