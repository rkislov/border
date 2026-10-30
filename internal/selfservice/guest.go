// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package selfservice

import (
	"net"
	"net/http"
)

func (p *Portal) guestRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/guest/design", func(w http.ResponseWriter, r *http.Request) {
		if p.Guest == nil {
			http.Error(w, "portal unavailable", 503)
			return
		}
		var v struct{ Token string }
		if !decode(w, r, &v) {
			return
		}
		d, err := p.Guest.Design(r.Context(), v.Token)
		if err != nil {
			http.Error(w, "invalid NAS redirect", 400)
			return
		}
		jsonReply(w, d)
	})
	mux.HandleFunc("GET /guest", func(w http.ResponseWriter, r *http.Request) {
		b, err := assets.ReadFile("assets/guest.html")
		if err != nil {
			http.Error(w, "portal unavailable", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	})
	mux.HandleFunc("POST /api/guest/start", func(w http.ResponseWriter, r *http.Request) {
		if p.Guest == nil {
			http.Error(w, "guest portal unavailable", 503)
			return
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !p.allow("guest-start:"+ip, 10) {
			http.Error(w, "слишком много запросов; подождите 15 минут", 429)
			return
		}
		var v struct{ Token, Phone, Email, Channel string }
		if !decode(w, r, &v) {
			return
		}
		if v.Channel == "" {
			v.Channel = "sms"
		}
		contact := v.Phone
		if v.Channel == "email" {
			contact = v.Email
		}
		result, err := p.Guest.RequestContact(r.Context(), v.Token, v.Channel, contact)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		jsonReply(w, result)
	})
	mux.HandleFunc("POST /api/guest/verify", func(w http.ResponseWriter, r *http.Request) {
		if p.Guest == nil {
			http.Error(w, "guest portal unavailable", 503)
			return
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !p.allow("guest-verify:"+ip, 60) {
			http.Error(w, "too many requests", 429)
			return
		}
		var v struct{ ID, Code string }
		if !decode(w, r, &v) {
			return
		}
		result, err := p.Guest.Confirm(r.Context(), v.ID, v.Code)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		jsonReply(w, result)
	})
}
