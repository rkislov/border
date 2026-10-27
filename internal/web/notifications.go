// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"github.com/rkislov/border/internal/notification"
	"net/http"
)

func (a *app) notificationRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/notifications", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("scope")
		if id == "" {
			id = "default"
		}
		c, e := a.notifications.Config(r.Context(), id)
		if e != nil {
			http.Error(w, "notification configuration unavailable", 400)
			return
		}
		reply(w, notification.Redacted(c))
	})
	m.HandleFunc("POST /api/notifications", func(w http.ResponseWriter, r *http.Request) {
		var c notification.Config
		if !decode(w, r, &c) {
			return
		}
		a.finish(w, r, a.notifications.Save(r.Context(), c), "save encrypted notification channels")
	})
}
