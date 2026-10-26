// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"time"
)

type loginAttempt struct {
	Count int
	Since time.Time
}

func (a *app) authenticated(r *http.Request) bool {
	if cookie, err := r.Cookie("border_admin"); err == nil {
		a.mu.Lock()
		expiry, ok := a.sessions[cookie.Value]
		if ok && time.Now().After(expiry) {
			delete(a.sessions, cookie.Value)
			ok = false
		}
		a.mu.Unlock()
		if ok {
			return true
		}
	}
	user, password, ok := r.BasicAuth()
	if !ok {
		return false
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	now := time.Now()
	a.mu.Lock()
	v := a.attempts[ip]
	if now.Sub(v.Since) > 15*time.Minute {
		v = loginAttempt{Since: now}
	}
	blocked := v.Count >= 10 || len(a.attempts) > 10000
	a.mu.Unlock()
	if blocked {
		return false
	}
	valid := a.s.CheckAdmin(r.Context(), user, password)
	if !valid {
		a.mu.Lock()
		v = a.attempts[ip]
		if now.Sub(v.Since) > 15*time.Minute {
			v = loginAttempt{Since: now}
		}
		v.Count++
		a.attempts[ip] = v
		a.mu.Unlock()
	}
	return valid
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
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	now := time.Now()
	a.mu.Lock()
	for k, v := range a.attempts {
		if now.Sub(v.Since) > 15*time.Minute {
			delete(a.attempts, k)
		}
	}
	attempt := a.attempts[ip]
	if attempt.Since.IsZero() {
		attempt.Since = now
	}
	if attempt.Count >= 10 || len(a.attempts) > 10000 {
		a.mu.Unlock()
		http.Error(w, "too many login attempts", 429)
		return
	}
	attempt.Count++
	a.attempts[ip] = attempt
	a.mu.Unlock()
	var v struct{ Username, Password string }
	if !decode(w, r, &v) {
		return
	}
	valid := a.s.CheckAdmin(r.Context(), v.Username, v.Password)
	v.Password = ""
	if !valid {
		http.Error(w, "неверный логин или пароль", 401)
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "session unavailable", 500)
		return
	}
	id := hex.EncodeToString(raw)
	a.mu.Lock()
	for key, expiry := range a.sessions {
		if now.After(expiry) {
			delete(a.sessions, key)
		}
	}
	if len(a.sessions) >= 10000 {
		a.mu.Unlock()
		http.Error(w, "busy", 503)
		return
	}
	a.sessions[id] = now.Add(30 * time.Minute)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "border_admin", Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 1800})
	_ = a.s.Audit(r.Context(), "web", v.Username, "login", "admin password login")
	reply(w, map[string]bool{"ok": true})
}
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("border_admin"); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "border_admin", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	reply(w, map[string]bool{"ok": true})
}
