// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"github.com/rkislov/border/internal/routeros"
	"net/http"
)

func (a *app) routerOSRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/routeros", func(w http.ResponseWriter, r *http.Request) {
		c, e := a.routerOS.Config(r.Context(), r.URL.Query().Get("nas"))
		if e != nil {
			http.Error(w, e.Error(), 503)
			return
		}
		reply(w, map[string]any{"Enabled": c.Enabled, "Address": c.Address, "Username": c.Username, "HostKey": c.HostKey, "HasPassword": c.Password != ""})
	})
	m.HandleFunc("POST /api/routeros", func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			NAS string
			routeros.Config
		}
		if !decode(w, r, &v) {
			return
		}
		a.finish(w, r, a.routerOS.Save(r.Context(), v.NAS, v.Config), "save encrypted RouterOS management configuration")
	})
}
