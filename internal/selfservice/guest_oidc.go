// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package selfservice

import (
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rkislov/border/internal/guest"
)

type oidcResult struct {
	Grant   guest.Grant
	Success bool
	Until   int64
}

var oidcResultPage = template.Must(template.New("result").Parse(`<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Border · Гостевой доступ</title><link rel="stylesheet" href="{{.Style}}"></head><body><header><b>◈ BORDER</b><span>Гостевой Wi-Fi</span></header><main><section class="panel"><h1>{{.Title}}</h1><p role="status">{{.Message}}</p><p>{{.Expiry}}</p></section></main></body></html>`))

func (p *Portal) guestOIDCRoutes(mux *http.ServeMux) {
	cookie := func(name, value string, age int) *http.Cookie {
		u, _ := url.Parse(p.Guest.PublicURL)
		path := "/"
		if u != nil {
			path = strings.TrimSuffix(u.Path, "/") + "/"
		}
		return &http.Cookie{Name: name, Value: value, Path: path, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: age}
	}
	mux.HandleFunc("POST /api/guest/oidc/start", func(w http.ResponseWriter, r *http.Request) {
		if p.Guest == nil {
			http.Error(w, "guest portal unavailable", 503)
			return
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !p.allow("guest-oidc:"+ip, 10) {
			http.Error(w, "Слишком много попыток входа", 429)
			return
		}
		var v struct{ Token, Provider string }
		if !decode(w, r, &v) {
			return
		}
		result, err := p.Guest.StartOIDC(r.Context(), v.Token, v.Provider)
		if err != nil {
			http.Error(w, "OIDC-вход недоступен. Проверьте настройки или повторите вход через минуту.", 400)
			return
		}
		http.SetCookie(w, cookie("__Secure-border-oidc", result.BrowserBinding, 300))
		jsonReply(w, result)
	})
	mux.HandleFunc("GET /api/guest/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		if p.Guest == nil {
			http.Error(w, "guest portal unavailable", 503)
			return
		}
		q := r.URL.Query()
		binding, _ := r.Cookie("__Secure-border-oidc")
		browser := ""
		if binding != nil {
			browser = binding.Value
		}
		// Reject parameter pollution before exchanging any authorization code.
		invalid := len(q["state"]) != 1 || len(q["code"]) > 1 || len(q["error"]) > 1
		state := q.Get("state")
		if invalid {
			state = ""
		}
		grant, err := p.Guest.FinishOIDC(r.Context(), state, browser, q.Get("code"), q.Get("error"))
		http.SetCookie(w, cookie("__Secure-border-oidc", "", -1))
		raw, _ := json.Marshal(oidcResult{Grant: grant, Success: err == nil, Until: time.Now().Unix() + 60})
		sealed := p.Guest.Vault.Seal(raw, "guest-oidc-result")
		http.SetCookie(w, cookie("__Secure-border-oidc-result", sealed, 60))
		u, e := url.Parse(p.Guest.PublicURL)
		if e != nil || u.Scheme != "https" {
			http.Error(w, "portal URL unavailable", 503)
			return
		}
		http.Redirect(w, r, strings.TrimSuffix(u.Path, "/")+"/guest/oidc/result", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /guest/oidc/result", func(w http.ResponseWriter, r *http.Request) {
		if p.Guest == nil {
			http.Error(w, "guest portal unavailable", 503)
			return
		}
		var result oidcResult
		if c, e := r.Cookie("__Secure-border-oidc-result"); e == nil {
			raw, e := p.Guest.Vault.Open(c.Value, "guest-oidc-result")
			if e == nil {
				_ = json.Unmarshal(raw, &result)
			}
			clear(raw)
		}
		http.SetCookie(w, cookie("__Secure-border-oidc-result", "", -1))
		title, message, expiry := "Вход не завершён", "Откройте портал заново через гостевую сеть и повторите вход.", ""
		if result.Success && result.Until > time.Now().Unix() && result.Grant.Expires > time.Now().Unix() {
			title = "Вход подтверждён"
			message = "Переподключитесь к Wi-Fi: устройство проверит политику доступа и применит настройки сети."
			expiry = "Доступ разрешён до " + time.Unix(result.Grant.Expires, 0).UTC().Format("02.01.2006 15:04 UTC")
		}
		u, _ := url.Parse(p.Guest.PublicURL)
		style := "/style.css"
		if u != nil {
			style = strings.TrimSuffix(u.Path, "/") + style
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = oidcResultPage.Execute(w, map[string]string{"Title": title, "Message": message, "Expiry": expiry, "Style": style})
	})
}
