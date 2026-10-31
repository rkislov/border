// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"net/http"

	"github.com/rkislov/border/internal/backup"
)

func (a *app) backupRoutes(m *http.ServeMux) {
	// A tenant administrator cannot export the platform master key or other tenants.
	if a.platform == nil {
		return
	}
	m.HandleFunc("GET /api/backups", func(w http.ResponseWriter, r *http.Request) {
		v, e := backup.ReadStatus(r.Context(), a.s)
		if e != nil {
			http.Error(w, "backup status unavailable", 503)
			return
		}
		reply(w, v)
	})
	m.HandleFunc("POST /api/backups/schedule", func(w http.ResponseWriter, r *http.Request) {
		var v backup.Schedule
		if !decode(w, r, &v) {
			return
		}
		if e := backup.SaveSchedule(r.Context(), a.s, v); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		a.finish(w, r, nil, "update backup schedule")
	})
	m.HandleFunc("POST /api/backups/jobs", func(w http.ResponseWriter, r *http.Request) {
		var v struct{ Kind, SourceID, RequestID string }
		if !decode(w, r, &v) {
			return
		}
		id, e := backup.Request(r.Context(), a.s, v.Kind, v.SourceID, v.RequestID, requestAccount(r).Username)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		reply(w, map[string]string{"ID": id})
	})
}
