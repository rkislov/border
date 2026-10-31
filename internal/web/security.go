// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"bytes"
	"encoding/base64"
	"html/template"
	"image/png"
	"net/http"

	"github.com/pquerna/otp"
	"github.com/rkislov/border/internal/store"
)

// Sensitive changes require the current password and, once enabled, a fresh
// second factor. A cookie alone cannot enroll, remove MFA or issue a token.
func (a *app) securityProof(w http.ResponseWriter, r *http.Request, password, code string, factor bool) (store.AdminAccount, bool) {
	current := requestAccount(r)
	if len(password) > 72 || len(code) > 40 || !a.attempt(r, current.Username, false) {
		http.Error(w, "слишком много попыток подтверждения", 429)
		return store.AdminAccount{}, false
	}
	p, ok := a.s.AuthenticateAdmin(r.Context(), current.Username, password)
	if !ok || p.Revision != current.Revision {
		http.Error(w, "неверный пароль или учётная запись изменилась", 401)
		return p, false
	}
	if factor && p.MFAEnabled {
		if e := a.adminSecurity.Verify(r.Context(), p, code); e != nil {
			http.Error(w, "неверный код, код уже использован или проверка временно заблокирована", 401)
			return p, false
		}
	}
	a.attempt(r, p.Username, true)
	return p, true
}
func (a *app) securityRoutes(m *http.ServeMux) {
	page := template.Must(template.ParseFS(assets, "assets/security.html", "assets/security-fields.html"))
	m.HandleFunc("GET /account/security", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = page.Execute(w, a.csrf)
	})
	m.HandleFunc("GET /api/admin-security", func(w http.ResponseWriter, r *http.Request) {
		v, e := a.adminSecurity.Status(r.Context(), requestAccount(r).Username)
		if e != nil {
			http.Error(w, "security status unavailable", 503)
			return
		}
		reply(w, v)
	})
	m.HandleFunc("POST /api/admin-security/begin", func(w http.ResponseWriter, r *http.Request) {
		var v struct{ Password string }
		if !decode(w, r, &v) {
			return
		}
		p, ok := a.securityProof(w, r, v.Password, "", false)
		v.Password = ""
		if !ok {
			return
		}
		enrollment, e := a.adminSecurity.Begin(r.Context(), p)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		key, e := otp.NewKeyFromURL(enrollment.URL)
		if e != nil {
			http.Error(w, "QR unavailable", 500)
			return
		}
		img, e := key.Image(256, 256)
		if e != nil {
			http.Error(w, "QR unavailable", 500)
			return
		}
		var b bytes.Buffer
		if e = png.Encode(&b, img); e != nil {
			http.Error(w, "QR unavailable", 500)
			return
		}
		reply(w, map[string]any{"Secret": enrollment.Secret, "URL": enrollment.URL, "ExpiresAt": enrollment.ExpiresAt, "QR": "data:image/png;base64," + base64.StdEncoding.EncodeToString(b.Bytes())})
	})
	for _, action := range []string{"confirm", "recovery", "disable"} {
		m.HandleFunc("POST /api/admin-security/"+action, func(w http.ResponseWriter, r *http.Request) {
			var v struct{ Password, Code string }
			if !decode(w, r, &v) {
				return
			}
			p, ok := a.securityProof(w, r, v.Password, v.Code, action != "confirm")
			v.Password = ""
			if !ok {
				return
			}
			if action != "confirm" && !p.MFAEnabled {
				http.Error(w, "TOTP не включён", 400)
				return
			}
			var codes []string
			var e error
			switch action {
			case "confirm":
				codes, e = a.adminSecurity.Confirm(r.Context(), p, v.Code)
			case "recovery":
				codes, e = a.adminSecurity.Regenerate(r.Context(), p)
			case "disable":
				e = a.adminSecurity.Disable(r.Context(), p)
			}
			if e != nil {
				http.Error(w, e.Error(), 400)
				return
			}
			next, e := a.s.AdminAccount(r.Context(), p.Username)
			if e != nil || next.Revision != p.Revision+1 {
				http.Error(w, "учётная запись изменилась; войдите заново", 401)
				return
			}
			if !a.issueSession(w, next, next.MFAEnabled) {
				return
			}
			reply(w, map[string]any{"ok": true, "RecoveryCodes": codes})
		})
	}
	m.HandleFunc("GET /api/monitoring-tokens", func(w http.ResponseWriter, r *http.Request) {
		v, e := a.adminSecurity.Tokens(r.Context())
		if e != nil {
			http.Error(w, "token status unavailable", 503)
			return
		}
		reply(w, v)
	})
	m.HandleFunc("POST /api/monitoring-tokens", func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Name, Password, Code string
			Scopes               []string
			ExpiresAt            int64
		}
		if !decode(w, r, &v) {
			return
		}
		p, ok := a.securityProof(w, r, v.Password, v.Code, true)
		v.Password = ""
		if !ok {
			return
		}
		metadata, token, e := a.adminSecurity.CreateToken(r.Context(), p, v.Name, v.Scopes, v.ExpiresAt)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		reply(w, map[string]any{"Metadata": metadata, "Token": token})
	})
	m.HandleFunc("POST /api/monitoring-tokens/revoke", func(w http.ResponseWriter, r *http.Request) {
		var v struct{ ID, Password, Code string }
		if !decode(w, r, &v) {
			return
		}
		p, ok := a.securityProof(w, r, v.Password, v.Code, true)
		v.Password = ""
		if !ok {
			return
		}
		if e := a.adminSecurity.RevokeToken(r.Context(), p, v.ID); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		reply(w, map[string]bool{"ok": true})
	})
}
