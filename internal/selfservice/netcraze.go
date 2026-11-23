// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package selfservice

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

func (p *Portal) netcrazeRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /uam/netcraze/{nas}", func(w http.ResponseWriter, r *http.Request) {
		if p.Guest == nil || p.Guest.CaptiveRedirect == nil {
			http.Error(w, "captive adapter unavailable", 503)
			return
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !p.allow("captive:"+ip, 60) {
			http.Error(w, "too many requests", 429)
			return
		}
		token, e := p.Guest.CaptiveRedirect(r.Context(), r.PathValue("nas"), r.URL.RawQuery, p.PublicURL)
		if e != nil {
			http.Error(w, "invalid or stale NAS redirect", 403)
			return
		}
		public, e := url.Parse(p.PublicURL)
		if e != nil || public.Scheme != "https" || public.Host == "" {
			http.Error(w, "portal URL unavailable", 503)
			return
		}
		http.Redirect(w, r, strings.TrimRight(public.Path, "/")+"/guest?token="+url.QueryEscape(token), http.StatusSeeOther)
	})
}
