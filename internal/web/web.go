// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rkislov/border/internal/aaa"
	"github.com/rkislov/border/internal/pki"
	"github.com/rkislov/border/internal/store"
)

//go:embed assets/*
var assets embed.FS

type app struct {
	mu       sync.Mutex
	sessions map[string]time.Time
	attempts map[string]loginAttempt
	s        *store.Store
	csrf     string
	t        *template.Template
	slots    chan struct{}
	pki      *pki.Manager
	acme     *pki.ACME
}

func Handler(s *store.Store) http.Handler { return HandlerWithOptions(s, nil, nil, true) }
func HandlerWithPKI(s *store.Store, manager *pki.Manager, acme *pki.ACME) http.Handler {
	return HandlerWithOptions(s, manager, acme, true)
}
func HandlerWithOptions(s *store.Store, manager *pki.Manager, acme *pki.ACME, requireMTLS bool) http.Handler {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	a := &app{sessions: make(map[string]time.Time), attempts: make(map[string]loginAttempt), pki: manager, acme: acme, s: s, csrf: hex.EncodeToString(b), t: template.Must(template.ParseFS(assets, "assets/index.html")), slots: make(chan struct{}, 16)}
	mux := http.NewServeMux()
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(sub))))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := a.t.Execute(w, a.csrf); err != nil {
			slog.Error("render failed")
		}
	})
	a.pkiRoutes(mux)
	mux.HandleFunc("GET /api/state", a.state)
	mux.HandleFunc("POST /api/nas", a.nas)
	mux.HandleFunc("POST /api/vlans", a.vlan)
	mux.HandleFunc("POST /api/devices", a.device)
	mux.HandleFunc("POST /api/settings", a.settings)
	mux.HandleFunc("POST /api/delete", a.delete)
	mux.HandleFunc("POST /api/logout", a.logout)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if r.TLS == nil || (requireMTLS && len(r.TLS.VerifiedChains) == 0) {
			http.Error(w, "client certificate required", http.StatusForbidden)
			return
		}
		select {
		case a.slots <- struct{}{}:
			defer func() { <-a.slots }()
		default:
			http.Error(w, "busy", 503)
			return
		}

		if r.URL.Path == "/api/login" && r.Method == "POST" {
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			a.login(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			mux.ServeHTTP(w, r)
			return
		}
		authenticated := a.authenticated(r)
		if !authenticated {
			if r.URL.Path == "/" && r.Method == "GET" {
				b, _ := assets.ReadFile("assets/login.html")
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write(b)
				return
			}
			http.Error(w, "authentication required", 401)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		if r.Method != "GET" && r.Method != "HEAD" {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(a.csrf)) != 1 {
				http.Error(w, "invalid CSRF token", 403)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		http.Error(w, "invalid JSON", 400)
		return false
	}
	return true
}
func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Debug("response write failed")
	}
}
func (a *app) finish(w http.ResponseWriter, r *http.Request, err error, action string) {
	if err != nil {
		http.Error(w, "операция отклонена: проверьте уникальность и ссылки на VLAN", 400)
		return
	}
	if err = a.s.Audit(r.Context(), "web", "admin", "updated", action); err != nil {
		slog.Error("admin audit failed")
	}
	reply(w, map[string]bool{"ok": true})
}
func (a *app) state(w http.ResponseWriter, r *http.Request) {
	n, err := a.s.NASList(r.Context())
	if err != nil {
		http.Error(w, "database unavailable", 503)
		return
	}
	v, err := a.s.VLANList(r.Context())
	if err != nil {
		http.Error(w, "database unavailable", 503)
		return
	}
	d, err := a.s.DeviceList(r.Context())
	if err != nil {
		http.Error(w, "database unavailable", 503)
		return
	}
	e, err := a.s.Events(r.Context())
	if err != nil {
		http.Error(w, "database unavailable", 503)
		return
	}
	s, err := a.s.Sessions(r.Context())
	if err != nil {
		http.Error(w, "database unavailable", 503)
		return
	}
	i, err := a.s.Isolation(r.Context())
	if err != nil {
		http.Error(w, "database unavailable", 503)
		return
	}
	reply(w, map[string]any{"nas": n, "vlans": v, "devices": d, "events": e, "sessions": s, "isolation": i, "time": time.Now().Unix()})
}
func (a *app) nas(w http.ResponseWriter, r *http.Request) {
	var v struct{ Address, Name, Secret string }
	if !decode(w, r, &v) {
		return
	}
	ip := net.ParseIP(v.Address)
	if ip == nil || strings.TrimSpace(v.Name) == "" || len(v.Name) > 100 || len(v.Secret) < 16 || len(v.Secret) > 128 {
		http.Error(w, "IP, имя и секрет 16–128 байт обязательны", 400)
		return
	}
	a.finish(w, r, a.s.Exec(r.Context(), "INSERT INTO nas(address,name,secret) VALUES (?,?,?) ON CONFLICT(address) DO UPDATE SET name=excluded.name,secret=excluded.secret", ip.String(), v.Name, v.Secret), "save NAS")
}
func (a *app) vlan(w http.ResponseWriter, r *http.Request) {
	var v store.VLAN
	if !decode(w, r, &v) {
		return
	}
	if v.ID < 1 || v.ID > 4094 || strings.TrimSpace(v.Name) == "" || len(v.Name) > 100 {
		http.Error(w, "VLAN: 1–4094, имя обязательно", 400)
		return
	}
	a.finish(w, r, a.s.Exec(r.Context(), "INSERT INTO vlan_catalog(id,name) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name", v.ID, v.Name), "save VLAN")
}
func (a *app) device(w http.ResponseWriter, r *http.Request) {
	var v store.Device
	if !decode(w, r, &v) {
		return
	}
	mac, err := aaa.NormalizeMAC(v.MAC)
	if err != nil || v.VLAN < 0 || v.VLAN > 4094 || len(v.Comment) > 500 {
		http.Error(w, "неверный MAC или VLAN", 400)
		return
	}
	var vlan any
	if v.VLAN > 0 {
		vlan = v.VLAN
	}
	active, voice := 0, 0
	if v.Active {
		active = 1
	}
	if v.Voice {
		voice = 1
	}
	a.finish(w, r, a.s.Exec(r.Context(), "INSERT INTO mac_auth(mac,vlan,active,voice,comment) VALUES (?,?,?,?,?) ON CONFLICT(mac) DO UPDATE SET vlan=excluded.vlan,active=excluded.active,voice=excluded.voice,comment=excluded.comment", mac, vlan, active, voice, v.Comment), "save device")
}
func (a *app) settings(w http.ResponseWriter, r *http.Request) {
	var v struct{ Isolation int }
	if !decode(w, r, &v) {
		return
	}
	if v.Isolation < 0 || v.Isolation > 4094 {
		http.Error(w, "invalid VLAN", 400)
		return
	}
	a.finish(w, r, a.s.SetIsolation(r.Context(), v.Isolation), "save isolation policy")
}
func (a *app) delete(w http.ResponseWriter, r *http.Request) {
	var v struct{ Kind, Key string }
	if !decode(w, r, &v) {
		return
	}
	var q string
	switch v.Kind {
	case "nas":
		q = "DELETE FROM nas WHERE address=?"
	case "devices":
		q = "DELETE FROM mac_auth WHERE mac=?"
	case "vlans":
		id, err := strconv.Atoi(v.Key)
		if err != nil {
			http.Error(w, "invalid VLAN", 400)
			return
		}
		a.finish(w, r, a.s.DeleteVLAN(r.Context(), id), "delete VLAN")
		return
	default:
		http.Error(w, "invalid kind", 400)
		return
	}
	a.finish(w, r, a.s.Exec(r.Context(), q, v.Key), "delete "+v.Kind)
}
