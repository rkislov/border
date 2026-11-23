// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"github.com/rkislov/border/internal/netcraze"
	"net/http"
)

func (a *app) netcrazeRoutes(m *http.ServeMux) {
	service := func() *netcraze.Service {
		n := &netcraze.Service{Store: a.s, Vault: a.routerOS.Vault}
		if a.guest != nil {
			n.PublicURL = a.guest.PublicURL
		}
		return n
	}
	m.HandleFunc("GET /api/netcraze", func(w http.ResponseWriter, r *http.Request) {
		nas := r.URL.Query().Get("nas")
		n := service()
		c, e := n.Config(r.Context(), nas)
		if e != nil {
			http.Error(w, "Netcraze configuration unavailable", 503)
			return
		}
		hasPassword, hasUAM := c.Password != "", c.UAMSecret != ""
		c.Password = ""
		c.UAMSecret = ""
		u, _ := netcraze.RedirectURL(n.PublicURL, nas)
		reply(w, struct {
			netcraze.Config
			HasPassword, HasUAMSecret bool
			UAMURL                    string
		}{c, hasPassword, hasUAM, u})
	})
	m.HandleFunc("POST /api/netcraze", func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			NAS string
			netcraze.Config
		}
		if !decode(w, r, &v) {
			return
		}
		a.finish(w, r, service().Save(r.Context(), v.NAS, v.Config), "save encrypted Netcraze captive configuration")
	})
	m.HandleFunc("POST /api/netcraze/check", func(w http.ResponseWriter, r *http.Request) {
		var v struct{ NAS string }
		if !decode(w, r, &v) {
			return
		}
		if e := service().Probe(r.Context(), v.NAS); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		reply(w, map[string]bool{"Ready": true})
	})
}
