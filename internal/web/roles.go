// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"github.com/rkislov/border/internal/adminauth"
	"github.com/rkislov/border/internal/store"
	"net/http"
)

type principalKey struct{}

func requestAccount(r *http.Request) store.AdminAccount {
	p, _ := r.Context().Value(principalKey{}).(store.AdminAccount)
	return p
}
func (a *app) roleAllowed(p store.AdminAccount, r *http.Request) bool {
	if p.Role == "monitor" {
		return r.Method == "GET" && ((r.URL.Path == "/metrics" && adminauth.HasScope(p.MonitoringScopes, "metrics:read")) || (r.URL.Path == "/api/health" && adminauth.HasScope(p.MonitoringScopes, "health:read")))
	}
	if p.Role == "admin" {
		return true
	}
	if r.Method == "GET" {
		switch r.URL.Path {
		case "/", "/api/me", "/api/sessions", "/account/security", "/api/admin-security":
			return p.Role == "operator" || p.Role == "viewer"
		case "/api/events":
			return p.Role == "viewer"
		}
	}
	if r.Method == "POST" && (r.URL.Path == "/api/logout" || r.URL.Path == "/api/admin-security/begin" || r.URL.Path == "/api/admin-security/confirm" || r.URL.Path == "/api/admin-security/recovery" || r.URL.Path == "/api/admin-security/disable") {
		return true
	}
	return p.Role == "operator" && r.Method == "POST" && r.URL.Path == "/api/sessions/action"
}
func (a *app) roleRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/me", func(w http.ResponseWriter, r *http.Request) {
		p := requestAccount(r)
		role := p.Role
		if role == "admin" && a.platform != nil {
			role = "platform_admin"
		}
		reply(w, map[string]any{"Username": p.Username, "Role": role, "LocationID": p.LocationID, "MFAEnabled": p.MFAEnabled})
	})
	m.HandleFunc("GET /api/admins", func(w http.ResponseWriter, r *http.Request) {
		v, err := a.s.AdminAccounts(r.Context())
		if err != nil {
			http.Error(w, "accounts unavailable", 503)
			return
		}
		reply(w, v)
	})
	m.HandleFunc("POST /api/admins", func(w http.ResponseWriter, r *http.Request) {
		var c store.AdminChange
		if !decode(w, r, &c) {
			return
		}
		err := a.s.SaveAdminAccount(r.Context(), requestAccount(r).Username, c)
		c.Password = ""
		a.finish(w, r, err, "update administrator account "+c.Username)
	})
}
