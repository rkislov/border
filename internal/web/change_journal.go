// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"

	"github.com/rkislov/border/internal/store"
)

func (a *app) changeJournalRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/change-journal", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		before := int64(0)
		limit := 50
		var e error
		if q.Get("before") != "" {
			before, e = strconv.ParseInt(q.Get("before"), 10, 64)
			if e != nil {
				http.Error(w, "invalid cursor", 400)
				return
			}
		}
		if q.Get("limit") != "" {
			limit, e = strconv.Atoi(q.Get("limit"))
			if e != nil {
				http.Error(w, "invalid limit", 400)
				return
			}
		}
		out, e := a.s.ChangeJournal(r.Context(), q.Get("q"), q.Get("actor"), q.Get("action"), before, limit)
		if e != nil {
			if errors.Is(e, store.ErrChangeJournalFilter) {
				http.Error(w, "invalid journal filter", 400)
			} else {
				http.Error(w, "journal unavailable", 500)
			}
			return
		}
		reply(w, out)
	})
	m.HandleFunc("GET /api/change-journal/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, e := a.s.ChangeJournalDetail(r.Context(), r.PathValue("id"))
		if e != nil {
			if errors.Is(e, sql.ErrNoRows) {
				http.Error(w, "change record unavailable", 404)
			} else {
				http.Error(w, "journal unavailable", 500)
			}
			return
		}
		reply(w, out)
	})
}
