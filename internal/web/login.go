// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rkislov/border/internal/store"
)

type loginAttempt struct {
	Count int
	Since time.Time
}
type adminSession struct {
	Username string
	Revision int64
	Expires  time.Time
	MFA      bool
}
type adminChallenge struct {
	Account  store.AdminAccount
	Expires  time.Time
	Attempts int
}

func (a *app) attempt(r *http.Request, user string, success bool) bool {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	keys := []string{"ip:" + ip, "user:" + user}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, v := range a.attempts {
		if now.Sub(v.Since) > 15*time.Minute {
			delete(a.attempts, k)
		}
	}
	if success {
		for _, k := range keys {
			delete(a.attempts, k)
		}
		return true
	}
	if len(a.attempts) > 20000 {
		return false
	}
	for i, k := range keys {
		v := a.attempts[k]
		limit := 20
		if i == 1 {
			limit = 10
		}
		if v.Count >= limit {
			return false
		}
	}
	for _, k := range keys {
		v := a.attempts[k]
		if v.Since.IsZero() {
			v.Since = now
		}
		v.Count++
		a.attempts[k] = v
	}
	return true
}
func (a *app) principal(r *http.Request) (store.AdminAccount, bool) {
	// An explicit Bearer credential never falls back to a browser cookie/Basic.
	if h := r.Header.Get("Authorization"); h != "" && (len(h) < 6 || !strings.EqualFold(h[:6], "Basic ")) {
		fields := strings.Fields(h)
		if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
			return store.AdminAccount{}, false
		}
		return a.adminSecurity.TokenPrincipal(r.Context(), fields[1])
	}
	if cookie, e := r.Cookie("border_admin"); e == nil && r.Header.Get("Authorization") == "" {
		a.mu.Lock()
		v, ok := a.sessions[cookie.Value]
		if ok && !time.Now().Before(v.Expires) {
			delete(a.sessions, cookie.Value)
			ok = false
		}
		a.mu.Unlock()
		if ok {
			p, e := a.s.AdminAccount(r.Context(), v.Username)
			if e == nil && p.Enabled && p.Revision == v.Revision && (!p.MFAEnabled || v.MFA) {
				return p, true
			}
			return store.AdminAccount{}, false
		}
	}
	user, password, ok := r.BasicAuth()
	if !ok || len(user) > 100 || len(password) > 72 || !a.attempt(r, user, false) {
		return store.AdminAccount{}, false
	}
	p, valid := a.s.AuthenticateAdmin(r.Context(), user, password)
	if !valid || p.MFAEnabled {
		return store.AdminAccount{}, false
	}
	a.attempt(r, user, true)
	return p, true
}
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && origin != "https://"+r.Host {
		http.Error(w, "cross-origin login rejected", 403)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "JSON required", 415)
		return
	}
	var v struct{ Username, Password, Challenge, Code string }
	if !decode(w, r, &v) {
		return
	}
	if v.Challenge != "" {
		if v.Username != "" || v.Password != "" {
			http.Error(w, "invalid challenge request", 400)
			return
		}
		a.mu.Lock()
		c, ok := a.challenges[v.Challenge]
		delete(a.challenges, v.Challenge)
		a.mu.Unlock()
		if !ok || !time.Now().Before(c.Expires) || c.Attempts >= 5 {
			http.Error(w, "проверка истекла; введите пароль заново", 401)
			return
		}
		c.Attempts++
		if e := a.adminSecurity.Verify(r.Context(), c.Account, v.Code); e != nil {
			if c.Attempts < 5 && time.Now().Before(c.Expires) {
				a.mu.Lock()
				a.challenges[v.Challenge] = c
				a.mu.Unlock()
			}
			http.Error(w, "неверный код, код уже использован или проверка временно заблокирована", 401)
			return
		}
		current, e := a.s.AdminAccount(r.Context(), c.Account.Username)
		if e != nil || !current.Enabled || current.Revision != c.Account.Revision || !current.MFAEnabled {
			http.Error(w, "учётная запись изменилась; войдите заново", 401)
			return
		}
		if !a.issueSession(w, current, true) {
			return
		}
		a.attempt(r, current.Username, true)
		_ = a.s.Audit(r.Context(), "admin_security", current.Username, "login", "admin MFA login")
		reply(w, map[string]bool{"ok": true})
		return
	}
	if v.Code != "" || len(v.Username) > 100 || len(v.Password) > 72 {
		http.Error(w, "invalid credentials", 401)
		return
	}
	if !a.attempt(r, v.Username, false) {
		http.Error(w, "too many login attempts", 429)
		return
	}
	p, valid := a.s.AuthenticateAdmin(r.Context(), v.Username, v.Password)
	v.Password = ""
	if !valid {
		http.Error(w, "неверный логин или пароль", 401)
		return
	}
	if p.MFAEnabled {
		id := randomSessionID()
		a.mu.Lock()
		for k, c := range a.challenges {
			if !time.Now().Before(c.Expires) {
				delete(a.challenges, k)
			}
		}
		if len(a.challenges) >= 10000 {
			a.mu.Unlock()
			http.Error(w, "busy", 503)
			return
		}
		a.challenges[id] = adminChallenge{Account: p, Expires: time.Now().Add(3 * time.Minute)}
		a.mu.Unlock()
		reply(w, map[string]any{"MFARequired": true, "Challenge": id, "ExpiresIn": 180})
		return
	}
	if !a.issueSession(w, p, false) {
		return
	}
	a.attempt(r, p.Username, true)
	_ = a.s.Audit(r.Context(), "web", p.Username, "login", "admin password login")
	reply(w, map[string]bool{"ok": true})
}
func randomSessionID() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func (a *app) issueSession(w http.ResponseWriter, p store.AdminAccount, mfa bool) bool {
	id := randomSessionID()
	now := time.Now()
	a.mu.Lock()
	for key, v := range a.sessions {
		if !now.Before(v.Expires) {
			delete(a.sessions, key)
		}
	}
	if len(a.sessions) >= 10000 {
		a.mu.Unlock()
		http.Error(w, "busy", 503)
		return false
	}
	a.sessions[id] = adminSession{Username: p.Username, Revision: p.Revision, Expires: now.Add(30 * time.Minute), MFA: mfa}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "border_admin", Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 1800})
	return true
}
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie("border_admin"); e == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "border_admin", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	reply(w, map[string]bool{"ok": true})
}
