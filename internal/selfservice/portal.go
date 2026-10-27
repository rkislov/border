// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package selfservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"image/png"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/directory"
	"github.com/rkislov/border/internal/guest"
	"github.com/rkislov/border/internal/pki"
)

//go:embed assets/*
var assets embed.FS

type session struct {
	User    directory.Identity
	CSRF    string
	Expires time.Time
}
type attempt struct {
	N     int
	Since time.Time
}
type Portal struct {
	Guest     *guest.Service
	Auth      directory.Authenticator
	Codes     *auth.Service
	PKI       *pki.Manager
	PublicURL string
	mu        sync.Mutex
	sessions  map[string]session
	attempts  map[string]attempt
	slots     chan struct{}
}

func New(a directory.Authenticator, c *auth.Service, p *pki.Manager, url string, guests ...*guest.Service) *Portal {
	portal := &Portal{Auth: a, Codes: c, PKI: p, PublicURL: strings.TrimSuffix(url, "/"), sessions: make(map[string]session), attempts: make(map[string]attempt), slots: make(chan struct{}, 16)}
	if len(guests) > 0 {
		portal.Guest = guests[0]
	}
	return portal
}
func token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func jsonReply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "JSON required", 415)
		return false
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		http.Error(w, "invalid JSON", 400)
		return false
	}
	return true
}
func (p *Portal) Handler() http.Handler {
	mux := http.NewServeMux()
	p.guestRoutes(mux)
	p.pushRoutes(mux)
	files, _ := fs.Sub(assets, "assets")
	mux.Handle("GET /", http.FileServer(http.FS(files)))
	mux.HandleFunc("GET /crl/{id}", func(w http.ResponseWriter, r *http.Request) {
		b, err := p.PKI.CRL(r.Context(), r.PathValue("id"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(b)
	})
	mux.HandleFunc("POST /api/login", p.login)
	mux.HandleFunc("GET /api/me", p.protected(p.me))
	mux.HandleFunc("POST /api/logout", p.protected(func(w http.ResponseWriter, r *http.Request, s session) {
		cookie, _ := r.Cookie("border_session")
		if cookie != nil {
			p.mu.Lock()
			delete(p.sessions, cookie.Value)
			p.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "border_session", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		jsonReply(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/email-code", p.protected(func(w http.ResponseWriter, r *http.Request, s session) {
		if err := p.Codes.EmailCode(r.Context(), s.User.Username); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		jsonReply(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/totp/enroll", p.protected(func(w http.ResponseWriter, r *http.Request, s session) {
		secret, uri, err := p.Codes.Enrollment(r.Context(), s.User.Username)
		if err != nil {
			http.Error(w, "enrollment failed", 500)
			return
		}
		key, err := otp.NewKeyFromURL(uri)
		if err != nil {
			http.Error(w, "QR failed", 500)
			return
		}
		img, err := key.Image(256, 256)
		if err != nil {
			http.Error(w, "QR failed", 500)
			return
		}
		var b bytes.Buffer
		if err = png.Encode(&b, img); err != nil {
			http.Error(w, "QR failed", 500)
			return
		}
		jsonReply(w, map[string]string{"secret": secret, "uri": uri, "qr": "data:image/png;base64," + base64.StdEncoding.EncodeToString(b.Bytes())})
	}))
	mux.HandleFunc("POST /api/totp/confirm", p.protected(func(w http.ResponseWriter, r *http.Request, s session) {
		var v struct{ Code string }
		if !decode(w, r, &v) {
			return
		}
		if !p.allow("confirm:"+s.User.Username, 5) {
			http.Error(w, "слишком много попыток; подождите 15 минут", 429)
			return
		}
		codes, err := p.Codes.Confirm(r.Context(), s.User.Username, v.Code)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		p.changed(w, r, s, "TOTP enabled or replaced", codes)
	}))
	mux.HandleFunc("POST /api/recovery", p.protected(func(w http.ResponseWriter, r *http.Request, s session) {
		if !p.allow("recovery:"+s.User.Username, 5) {
			http.Error(w, "too many requests", 429)
			return
		}
		codes, err := p.Codes.Recovery(r.Context(), s.User.Username)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		p.changed(w, r, s, "Recovery codes replaced", codes)
	}))
	mux.HandleFunc("POST /api/certificates/issue", p.protected(func(w http.ResponseWriter, r *http.Request, s session) {
		var v struct{ CA, Renewal string }
		if !decode(w, r, &v) {
			return
		}
		if !p.allow("issue:"+s.User.Username, 5) {
			http.Error(w, "too many requests", 429)
			return
		}
		crl := ""
		if p.PublicURL != "" {
			crl = p.PublicURL + "/crl/" + v.CA
		}
		b, err := p.PKI.Issue(r.Context(), v.CA, s.User.Username, s.User.Email, v.Renewal, crl, 90)
		if err != nil {
			http.Error(w, "certificate issuance failed; check CA and renewal ownership", 400)
			return
		}
		_ = p.Codes.Store.Audit(r.Context(), "portal", s.User.Username, "issued", b.Serial)
		notification := p.Codes.Notify(r.Context(), s.User.Username, "Border certificate issued", "A client certificate was issued for your account. Serial: "+b.Serial)
		jsonReply(w, map[string]any{"bundle": b, "notification_sent": notification == nil})
	}))
	mux.HandleFunc("POST /api/certificates/revoke", p.protected(func(w http.ResponseWriter, r *http.Request, s session) {
		var v struct{ Serial string }
		if !decode(w, r, &v) {
			return
		}
		if err := p.PKI.Revoke(r.Context(), v.Serial, s.User.Username); err != nil {
			http.Error(w, "certificate not found", 400)
			return
		}
		p.changed(w, r, s, "Certificate revoked: "+v.Serial, nil)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if r.TLS == nil {
			http.Error(w, "HTTPS required", 403)
			return
		}
		if r.Method == "POST" {
			if origin := r.Header.Get("Origin"); origin != "" && origin != "https://"+r.Host {
				http.Error(w, "cross-origin request rejected", 403)
				return
			}
			if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
				http.Error(w, "cross-site request rejected", 403)
				return
			}
		}
		select {
		case p.slots <- struct{}{}:
			defer func() { <-p.slots }()
		default:
			http.Error(w, "busy", 503)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		mux.ServeHTTP(w, r)
	})
}
func (p *Portal) allow(key string, limit int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for k, v := range p.attempts {
		if now.Sub(v.Since) > 15*time.Minute {
			delete(p.attempts, k)
		}
	}
	v := p.attempts[key]
	if v.Since.IsZero() {
		v.Since = now
	}
	if v.N >= limit || len(p.attempts) > 10000 {
		return false
	}
	v.N++
	p.attempts[key] = v
	return true
}
func (p *Portal) login(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !p.allow("login:"+ip, 10) {
		http.Error(w, "слишком много попыток входа", 429)
		return
	}
	var v struct{ Username, Password string }
	if !decode(w, r, &v) {
		return
	}
	if p.Auth == nil {
		http.Error(w, "domain authentication not configured", 503)
		return
	}
	i, err := p.Auth.Authenticate(r.Context(), v.Username, v.Password)
	v.Password = ""
	if err != nil {
		http.Error(w, "неверный логин или пароль", 401)
		return
	}
	if err = p.Codes.Register(r.Context(), i); err != nil {
		http.Error(w, "database unavailable", 503)
		return
	}
	id := token()
	s := session{User: i, CSRF: token(), Expires: time.Now().Add(10 * time.Minute)}
	p.mu.Lock()
	for k, v := range p.sessions {
		if time.Now().After(v.Expires) {
			delete(p.sessions, k)
		}
	}
	if len(p.sessions) >= 10000 {
		p.mu.Unlock()
		http.Error(w, "busy", 503)
		return
	}
	p.sessions[id] = s
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "border_session", Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 600})
	_ = p.Codes.Store.Audit(r.Context(), "portal", i.Username, "login", "domain login")
	jsonReply(w, map[string]string{"csrf": s.CSRF, "username": i.Username, "email": i.Email})
}
func (p *Portal) protected(next func(http.ResponseWriter, *http.Request, session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("border_session")
		if err != nil {
			http.Error(w, "login required", 401)
			return
		}
		p.mu.Lock()
		s, ok := p.sessions[cookie.Value]
		if ok && time.Now().After(s.Expires) {
			delete(p.sessions, cookie.Value)
			ok = false
		}
		p.mu.Unlock()
		if !ok {
			http.Error(w, "session expired", 401)
			return
		}
		if r.Method == "POST" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.CSRF)) != 1 {
			http.Error(w, "invalid CSRF token", 403)
			return
		}
		if active, ok := p.Auth.(interface {
			Active(context.Context, string) bool
		}); ok && strings.Contains(s.User.Username, "/") && !active.Active(r.Context(), s.User.Username) {
			http.Error(w, "account disabled", 401)
			return
		}
		next(w, r, s)
	}
}
func (p *Portal) me(w http.ResponseWriter, r *http.Request, s session) {
	cas, err := p.PKI.Authorities(r.Context())
	if err != nil {
		http.Error(w, "database unavailable", 503)
		return
	}
	certs, err := p.PKI.Certificates(r.Context(), s.User.Username)
	if err != nil {
		http.Error(w, "database unavailable", 503)
		return
	}
	var secret string
	if err = p.Codes.Store.Row(r.Context(), "SELECT totp_secret FROM identities WHERE username=?", s.User.Username).Scan(&secret); err != nil {
		http.Error(w, "database unavailable", 503)
		return
	}
	jsonReply(w, map[string]any{"username": s.User.Username, "email": s.User.Email, "csrf": s.CSRF, "totp": secret != "", "authorities": cas, "certificates": certs})
}
func (p *Portal) changed(w http.ResponseWriter, r *http.Request, s session, action string, codes []string) {
	_ = p.Codes.Store.Audit(r.Context(), "portal", s.User.Username, "updated", action)
	notification := p.Codes.Notify(r.Context(), s.User.Username, "Border security notification", action+". If this was not you, contact your administrator.")
	jsonReply(w, map[string]any{"ok": true, "codes": codes, "notification_sent": notification == nil})
}
