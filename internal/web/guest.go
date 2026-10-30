// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"github.com/rkislov/border/internal/guest"
	"github.com/rkislov/border/internal/sms"
	"github.com/rkislov/border/internal/store"
	"net/http"
	"net/url"
	"strings"
)

func (a *app) guestRoutes(mux *http.ServeMux) {
	ready := func(w http.ResponseWriter) bool {
		if a.guest == nil {
			http.Error(w, "guest portal requires BORDER_MASTER_KEY", 503)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /api/guest/config", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		c, err := a.guest.Config(r.Context())
		if err != nil {
			http.Error(w, "SMS settings unavailable", 503)
			return
		}
		hasToken := c.Token != ""
		c.Token = ""
		policy, err := a.s.GuestPolicy(r.Context())
		if err != nil {
			http.Error(w, "run init-db to update guest schema", 503)
			return
		}
		sessions, err := a.s.GuestSessions(r.Context())
		if err != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		reply(w, map[string]any{"SMS": c, "HasToken": hasToken, "Policy": policy, "Sessions": sessions})
	})
	mux.HandleFunc("POST /api/guest/sms", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		var c sms.Config
		if !decode(w, r, &c) {
			return
		}
		if err := a.guest.SetConfig(r.Context(), c); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		a.finish(w, r, nil, "save encrypted SMS configuration")
	})
	mux.HandleFunc("POST /api/guest/policy", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		var p store.GuestPolicy
		if !decode(w, r, &p) {
			return
		}
		// Channel availability is scoped to NAS/domain and checked when issuing a code.

		a.finish(w, r, a.s.SetGuestPolicy(r.Context(), p), "save guest policy")
	})
	mux.HandleFunc("POST /api/guest/revoke", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		var v struct{ NAS, MAC string }
		if !decode(w, r, &v) {
			return
		}
		a.finish(w, r, a.s.Exec(r.Context(), "DELETE FROM guest_sessions WHERE nas=? AND mac=?", v.NAS, v.MAC), "revoke guest grant")
	})
	mux.HandleFunc("POST /api/guest/link", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		var v struct{ NAS, MAC, SessionID, Domain string }
		if !decode(w, r, &v) {
			return
		}
		var secret string
		if a.s.Row(r.Context(), "SELECT secret FROM nas WHERE address=? AND portal_enabled=1", v.NAS).Scan(&secret) != nil {
			http.Error(w, "NAS must allow guest portal", 400)
			return
		}
		if v.Domain != "" {
			if a.s.ValidatePortalScope(r.Context(), "domain:"+v.Domain) != nil {
				http.Error(w, "unknown domain", 400)
				return
			}
		}
		token, err := guest.SignRedirect(guest.Redirect{NAS: v.NAS, MAC: v.MAC, SessionID: v.SessionID, Domain: v.Domain}, secret)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		base := strings.TrimSuffix(a.guest.PublicURL, "/")
		u, err := url.Parse(base)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			http.Error(w, "set a public HTTPS --portal-url first", 400)
			return
		}
		reply(w, map[string]string{"URL": base + "/guest?token=" + url.QueryEscape(token)})
	})
}
