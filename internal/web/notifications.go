// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/rkislov/border/internal/notification"
	"github.com/rkislov/border/internal/store"
	"net/http"
)

func (a *app) notificationRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/policy-notifications", func(w http.ResponseWriter, r *http.Request) {
		targets, e := a.s.PolicyNotificationTargets(r.Context(), requestAccount(r).Username)
		if e != nil {
			http.Error(w, "recipients unavailable", 503)
			return
		}
		for i := range targets {
			if targets[i].Channel == "push" {
				targets[i].Destination = ""
			}
		}
		deliveries, e := a.s.PolicyDeliveries(r.Context())
		if e != nil {
			http.Error(w, "queue unavailable", 503)
			return
		}
		reply(w, map[string]any{"Targets": targets, "Deliveries": deliveries})
	})
	m.HandleFunc("POST /api/policy-notifications/recipient", func(w http.ResponseWriter, r *http.Request) {
		var v notification.PolicyRecipient
		if !decode(w, r, &v) {
			return
		}
		a.finish(w, r, a.notifications.SavePolicyRecipient(r.Context(), requestAccount(r).Username, v), "save own policy notification recipient")
	})
	m.HandleFunc("POST /api/policy-notifications/retry", func(w http.ResponseWriter, r *http.Request) {
		var v struct{ ID string }
		if !decode(w, r, &v) {
			return
		}
		a.finish(w, r, a.s.RetryPolicyDelivery(r.Context(), v.ID, requestAccount(r).Username), "retry policy delivery "+v.ID)
	})
	m.HandleFunc("GET /api/policy-notifications/push-key", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("scope")
		if id == "" {
			id = "default"
		}
		key, e := a.notifications.PushKey(r.Context(), id+"/administrator")
		if e != nil {
			http.Error(w, "push channel unavailable", 409)
			return
		}
		reply(w, map[string]string{"Key": key})
	})
	m.HandleFunc("POST /api/policy-notifications/push", func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Scope, Key   string
			Subscription webpush.Subscription
		}
		if !decode(w, r, &v) {
			return
		}
		a.finish(w, r, a.notifications.SubscribePolicy(r.Context(), requestAccount(r).Username, v.Scope, v.Key, v.Subscription), "subscribe own policy push notifications")
	})
	m.HandleFunc("POST /api/policy-notifications/push-disable", func(w http.ResponseWriter, r *http.Request) {
		a.finish(w, r, a.s.SavePolicyNotificationTarget(r.Context(), store.PolicyNotificationTarget{Username: requestAccount(r).Username, Channel: "push", Scope: "default"}), "disable own policy push notifications")
	})
	m.HandleFunc("GET /policy-sw.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(`self.addEventListener('push',e=>{let v={};try{v=e.data.json()}catch{}e.waitUntil(self.registration.showNotification(v.title||'Border',{body:v.body||'',tag:v.tag||'border-policy'}))});self.addEventListener('notificationclick',e=>{e.notification.close();e.waitUntil(clients.openWindow(self.registration.scope+'#policy-drafts'))});`))
	})

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
