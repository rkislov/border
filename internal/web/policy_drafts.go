// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"encoding/json"
	"github.com/rkislov/border/internal/store"
	"net/http"
	"strings"
)

func (a *app) stagePolicy(w http.ResponseWriter, r *http.Request, kind, id string, payload any) {
	raw, err := json.Marshal(payload)
	if err == nil {
		err = a.s.SavePolicyDraft(r.Context(), store.PolicyDraft{Kind: kind, PolicyID: id, Payload: raw}, requestAccount(r).Username)
	}
	a.finishPolicy(w, r, err, "save policy draft "+kind+"/"+id)
}
func (a *app) policyDraftRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/policy-drafts", func(w http.ResponseWriter, r *http.Request) {
		drafts, e := a.s.PolicyDrafts(r.Context())
		if e != nil {
			http.Error(w, "drafts unavailable", 503)
			return
		}
		releases, e := a.s.PolicyReleases(r.Context())
		if e != nil {
			http.Error(w, "history unavailable", 503)
			return
		}
		reply(w, map[string]any{"Drafts": drafts, "Releases": releases})
	})
	m.HandleFunc("POST /api/policy-drafts", func(w http.ResponseWriter, r *http.Request) {
		var d store.PolicyDraft
		if !decode(w, r, &d) {
			return
		}
		a.finishPolicy(w, r, a.s.SavePolicyDraft(r.Context(), d, requestAccount(r).Username), "save policy draft "+d.Kind+"/"+d.PolicyID)
	})
	m.HandleFunc("GET /api/policy-drafts/impact", func(w http.ResponseWriter, r *http.Request) {
		v, e := a.s.PolicyDraftImpact(r.Context(), r.URL.Query().Get("kind"), r.URL.Query().Get("id"))
		if e != nil {
			http.Error(w, e.Error(), 409)
			return
		}
		reply(w, v)
	})
	for _, action := range []string{"publish", "discard", "rollback"} {
		m.HandleFunc("POST /api/policy-drafts/"+action, func(w http.ResponseWriter, r *http.Request) {
			var v struct {
				Kind, PolicyID, ReleaseID string
				Revision                  int64
			}
			if !decode(w, r, &v) {
				return
			}
			actor := requestAccount(r).Username
			var err error
			switch action {
			case "publish":
				err = a.s.PublishPolicyDraft(r.Context(), v.Kind, v.PolicyID, v.Revision, actor)
			case "discard":
				err = a.s.DiscardPolicyDraft(r.Context(), v.Kind, v.PolicyID, v.Revision)
			case "rollback":
				err = a.s.RollbackPolicyDraft(r.Context(), v.ReleaseID, actor)
			}
			a.finishPolicy(w, r, err, action+" policy draft "+v.Kind+"/"+v.PolicyID+" "+v.ReleaseID)
		})
	}
}

func (a *app) finishPolicy(w http.ResponseWriter, r *http.Request, err error, action string) {
	if err != nil {
		message := "Не удалось сохранить политику. Проверьте поля и ссылки на существующие объекты."
		switch {
		case strings.Contains(err.Error(), "changed"):
			message = "Версия изменилась. Обновите список; при конфликте рабочей версии удалите черновик и создайте заново."
		case strings.Contains(err.Error(), "dependent policy"):
			message = "Изменение несовместимо с зависимой политикой доступа. Сначала измените её авторизацию, назначение или правила."
		case strings.Contains(err.Error(), "first publication"):
			message = "У первой публикации нет предыдущей версии. Создайте черновик с выключенной политикой."
		}
		http.Error(w, message, http.StatusConflict)
		return
	}
	a.finish(w, r, nil, action)
}
