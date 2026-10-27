// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package selfservice

import (
	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/rkislov/border/internal/notification"
	"net/http"
)

func (p *Portal) pushRoutes(m *http.ServeMux) {
	service, ok := p.Codes.Mail.(*notification.Service)
	if !ok {
		return
	}
	m.HandleFunc("GET /api/push", p.protected(func(w http.ResponseWriter, r *http.Request, s session) {
		key, e := service.PushKey(r.Context(), s.User.Username)
		jsonReply(w, map[string]any{"Enabled": e == nil, "PublicKey": key})
	}))
	m.HandleFunc("POST /api/push/subscribe", p.protected(func(w http.ResponseWriter, r *http.Request, s session) {
		var v struct {
			Key          string
			Subscription webpush.Subscription
		}
		if !decode(w, r, &v) {
			return
		}
		if e := service.Subscribe(r.Context(), s.User.Username, v.Key, v.Subscription); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		jsonReply(w, map[string]bool{"ok": true})
	}))
	m.HandleFunc("POST /api/push/unsubscribe", p.protected(func(w http.ResponseWriter, r *http.Request, s session) {
		var v struct{ Endpoint string }
		if !decode(w, r, &v) {
			return
		}
		if e := service.Unsubscribe(r.Context(), s.User.Username, v.Endpoint); e != nil {
			http.Error(w, "unsubscribe failed", 503)
			return
		}
		jsonReply(w, map[string]bool{"ok": true})
	}))
	m.HandleFunc("POST /api/push/test", p.protected(func(w http.ResponseWriter, r *http.Request, s session) {
		if !p.allow("push:"+s.User.Username, 3) {
			http.Error(w, "подождите 15 минут", 429)
			return
		}
		n, e := service.Push(r.Context(), s.User.Username, "Border", "Проверочное уведомление личного кабинета.")
		if e != nil || n == 0 {
			http.Error(w, "push не доставлен; проверьте подписку", 400)
			return
		}
		jsonReply(w, map[string]int{"Sent": n})
	}))
}
