// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"context"
	"github.com/rkislov/border/internal/store"
	"net/http"
	"strconv"
	"time"
)

func (a *app) listRoutes(m *http.ServeMux) {
	for _, kind := range []string{"sessions", "events"} {
		m.HandleFunc("GET /api/"+kind, func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			f := store.ListFilter{Query: q.Get("q"), Status: q.Get("status"), Result: q.Get("result"), Authorization: q.Get("authorization"), Page: 1, Limit: 50}
			for key, dst := range map[string]*int{"page": &f.Page, "limit": &f.Limit} {
				if q.Has(key) {
					n, e := strconv.Atoi(q.Get(key))
					if e != nil {
						http.Error(w, "invalid pagination", 400)
						return
					}
					*dst = n
				}
			}
			for key, dst := range map[string]*int64{"from": &f.From, "until": &f.Until} {
				if q.Has(key) {
					n, e := strconv.ParseInt(q.Get(key), 10, 64)
					if e != nil {
						http.Error(w, "invalid time filter", 400)
						return
					}
					*dst = n
				}
			}
			if err := f.Validate(); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			w.Header().Set("Cache-Control", "no-store")
			var page any
			var err error
			if kind == "sessions" {
				page, err = a.s.SessionsPage(ctx, f)
			} else {
				page, err = a.s.EventsPage(ctx, f)
			}
			if err != nil {
				http.Error(w, "list unavailable", 503)
				return
			}
			reply(w, page)
		})
	}
}
