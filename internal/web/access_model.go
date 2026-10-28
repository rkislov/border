package web

import (
	"github.com/rkislov/border/internal/identitysource"
	"github.com/rkislov/border/internal/store"
	"net/http"
	"strings"
)

func (a *app) accessRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/access-model", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		locations, err := a.s.NamedList(ctx, "locations")
		if err != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		segments, err := a.s.NamedList(ctx, "network_segments")
		if err != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		authentication, err := a.s.Authentications(ctx)
		if err != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		access, err := a.s.Accesses(ctx)
		if err != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		mappings, err := a.s.Mappings(ctx)
		if err != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		domains, err := a.identities.Domains(ctx)
		if err != nil {
			http.Error(w, "domain configuration unavailable", 503)
			return
		}
		users, err := a.identities.Locals(ctx)
		if err != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		groups, err := a.s.UserGroups(ctx)
		if err != nil {
			http.Error(w, "groups unavailable", 503)
			return
		}
		rules := []store.RuleSet{}
		for _, p := range access {
			c, e := a.s.Rules(ctx, p.ID)
			if e != nil {
				http.Error(w, "rules unavailable", 503)
				return
			}
			rules = append(rules, c)
		}
		reply(w, map[string]any{"Groups": groups, "RuleSets": rules, "Locations": locations, "Segments": segments, "Authentication": authentication, "Access": access, "Mappings": mappings, "Domains": domains, "Users": users})
	})
	m.HandleFunc("GET /api/nas-policies", func(w http.ResponseWriter, r *http.Request) {
		set, err := a.s.NASPolicies(r.Context(), r.URL.Query().Get("nas"))
		if err != nil {
			http.Error(w, "configuration unavailable", 503)
			return
		}
		reply(w, set)
	})
	m.HandleFunc("POST /api/nas-policies", func(w http.ResponseWriter, r *http.Request) {
		var set store.NASPolicySet
		if !decode(w, r, &set) {
			return
		}
		a.finish(w, r, a.s.SaveNASPolicies(r.Context(), set), "save NAS policy bindings")
	})
	m.HandleFunc("POST /api/user-groups", func(w http.ResponseWriter, r *http.Request) {
		var g store.UserGroup
		if !decode(w, r, &g) {
			return
		}
		a.finish(w, r, a.s.SaveUserGroup(r.Context(), g), "save local group")
	})
	m.HandleFunc("POST /api/access-rules", func(w http.ResponseWriter, r *http.Request) {
		var c store.RuleSet
		if !decode(w, r, &c) {
			return
		}
		a.finish(w, r, a.s.SaveRules(r.Context(), c), "save ordered access rules")
	})
	m.HandleFunc("POST /api/authentication-policies", func(w http.ResponseWriter, r *http.Request) {
		var v store.AuthenticationPolicy
		if !decode(w, r, &v) {
			return
		}
		a.finish(w, r, a.s.SaveAuthentication(r.Context(), v), "save authentication policy")
	})
	m.HandleFunc("POST /api/access-policies", func(w http.ResponseWriter, r *http.Request) {
		var v store.AccessPolicy
		if !decode(w, r, &v) {
			return
		}
		for i := range v.Subjects {
			v.Subjects[i] = strings.ToLower(strings.TrimSpace(v.Subjects[i]))
		}
		a.finish(w, r, a.s.SaveAccess(r.Context(), v), "save access policy")
	})
	m.HandleFunc("POST /api/segment-mappings", func(w http.ResponseWriter, r *http.Request) {
		var v store.SegmentMapping
		if !decode(w, r, &v) {
			return
		}
		a.finish(w, r, a.s.SaveMapping(r.Context(), v), "save location/NAS segment mapping")
	})
	for _, kind := range []string{"locations", "network_segments"} {
		m.HandleFunc("POST /api/"+kind, func(w http.ResponseWriter, r *http.Request) {
			var v store.Named
			if !decode(w, r, &v) {
				return
			}
			if !identitysource.IDPattern.MatchString(v.ID) || v.Name == "" || len(v.Name) > 100 {
				http.Error(w, "ID and name required", 400)
				return
			}
			a.finish(w, r, a.s.Exec(r.Context(), "INSERT INTO "+kind+"(id,name) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name", v.ID, v.Name), "save "+kind)
		})
	}
	m.HandleFunc("POST /api/domains", func(w http.ResponseWriter, r *http.Request) {
		var v identitysource.Domain
		if !decode(w, r, &v) {
			return
		}
		a.finish(w, r, a.identities.SaveDomain(r.Context(), v), "save encrypted domain connection")
	})
	m.HandleFunc("POST /api/local-users", func(w http.ResponseWriter, r *http.Request) {
		var v identitysource.LocalUser
		if !decode(w, r, &v) {
			return
		}
		a.finish(w, r, a.identities.SaveLocal(r.Context(), v), "save local network user")
	})
}
