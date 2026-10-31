// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"github.com/rkislov/border/internal/guest"
	"net/http"
)

func (a *app) guestOIDCRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/guest/oidc", func(w http.ResponseWriter, r *http.Request) {
		if a.guest == nil {
			http.Error(w, "guest portal unavailable", 503)
			return
		}
		scope := r.URL.Query().Get("scope")
		if a.s.ValidatePortalScope(r.Context(), scope) != nil {
			http.Error(w, "unknown scope", 400)
			return
		}
		providers, err := a.s.OIDCProviders(r.Context(), scope)
		if err != nil {
			http.Error(w, "OIDC configuration unavailable", 503)
			return
		}
		callback, _ := a.guest.OIDCCallbackURL()
		reply(w, map[string]any{"Providers": providers, "CallbackURL": callback})
	})
	mux.HandleFunc("POST /api/guest/oidc", func(w http.ResponseWriter, r *http.Request) {
		if a.guest == nil {
			http.Error(w, "guest portal unavailable", 503)
			return
		}
		var c guest.OIDCConfiguration
		if !decode(w, r, &c) {
			return
		}
		a.finish(w, r, a.guest.SaveOIDCProvider(r.Context(), c), "save guest OIDC provider "+c.ID+" scope "+c.Scope)
	})
}
