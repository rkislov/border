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
	m.HandleFunc("POST /api/policy-drafts/review-settings", func(w http.ResponseWriter, r *http.Request) {
		var v store.ReviewSettings
		if !decode(w, r, &v) {
			return
		}
		a.finishPolicy(w, r, a.s.SaveReviewSettings(r.Context(), v, requestAccount(r).Username), "update policy review requirement")
	})
	m.HandleFunc("POST /api/policy-drafts/reviews", func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Drafts  []store.DraftRef
			Comment string
		}
		if !decode(w, r, &v) {
			return
		}
		id, e := a.s.SubmitPolicyReview(r.Context(), v.Drafts, v.Comment, requestAccount(r).Username)
		if e != nil {
			a.finishPolicy(w, r, e, "")
			return
		}
		reply(w, map[string]string{"ID": id})
	})
	m.HandleFunc("GET /api/policy-drafts/reviews/{id}", func(w http.ResponseWriter, r *http.Request) {
		v, e := a.s.PolicyReview(r.Context(), r.PathValue("id"))
		if e != nil {
			http.Error(w, "review unavailable", 404)
			return
		}
		reply(w, v)
	})
	m.HandleFunc("POST /api/policy-drafts/reviews/decision", func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			ID, Comment string
			Approve     bool
		}
		if !decode(w, r, &v) {
			return
		}
		a.finishPolicy(w, r, a.s.DecidePolicyReview(r.Context(), v.ID, v.Approve, v.Comment, requestAccount(r).Username), "decide policy review "+v.ID)
	})
	for _, action := range []string{"impact", "publish", "rollback"} {
		m.HandleFunc("POST /api/policy-drafts/batch/"+action, func(w http.ResponseWriter, r *http.Request) {
			var v struct {
				Drafts  []store.DraftRef
				BatchID string
			}
			if !decode(w, r, &v) {
				return
			}
			if action == "impact" {
				out, e := a.s.PolicyBatchImpact(r.Context(), v.Drafts)
				if e != nil {
					http.Error(w, "assessment unavailable", 503)
					return
				}
				reply(w, out)
				return
			}
			var err error
			if action == "publish" {
				err = a.s.PublishPolicyBatch(r.Context(), v.Drafts, requestAccount(r).Username)
			} else {
				err = a.s.RollbackPolicyBatch(r.Context(), v.BatchID, requestAccount(r).Username)
			}
			a.finishPolicy(w, r, err, action+" configuration batch "+v.BatchID)
		})
	}
	m.HandleFunc("POST /api/nas-assignment", func(w http.ResponseWriter, r *http.Request) {
		var v store.NASAssignment
		if !decode(w, r, &v) {
			return
		}
		a.stagePolicy(w, r, "nas-assignment", v.NAS, v)
	})
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
		settings, e := a.s.ReviewSettings(r.Context())
		if e != nil {
			http.Error(w, "review settings unavailable", 503)
			return
		}
		reviews, e := a.s.PolicyReviews(r.Context())
		if e != nil {
			http.Error(w, "reviews unavailable", 503)
			return
		}
		reply(w, map[string]any{"Drafts": drafts, "Releases": releases, "ReviewSettings": settings, "Reviews": reviews, "Username": requestAccount(r).Username})
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
		case strings.HasPrefix(err.Error(), "approval:"):
			message = reviewErrorText(strings.TrimSpace(strings.TrimPrefix(err.Error(), "approval:")))
		case strings.Contains(err.Error(), "changed"):
			message = "Версия изменилась. Обновите список; при конфликте рабочей версии удалите черновик и создайте заново."
		case strings.Contains(err.Error(), "dependent policy"):
			message = "Изменение несовместимо с зависимой политикой доступа. Сначала измените её авторизацию, назначение или правила."
		case strings.Contains(err.Error(), "cannot delete"):
			message = "Удаление заблокировано зависимостями. Оцените пакет и добавьте изменения связанных объектов."
		}
		http.Error(w, message, http.StatusConflict)
		return
	}
	a.finish(w, r, nil, action)
}

func reviewErrorText(reason string) string {
	messages := map[string]string{
		"active administrator required":                                 "Нужна действующая учётная запись администратора.",
		"enable at least two administrators first":                      "Сначала создайте минимум двух активных администраторов.",
		"comment exceeds 1000 bytes":                                    "Комментарий слишком длинный (максимум 1000 байт).",
		"review mode is disabled":                                       "Согласование выключено для этого тенанта.",
		"this package already has an active request":                    "Для этой редакции пакета уже есть активная заявка.",
		"rejection comment required (maximum 1000 bytes)":               "Для отклонения укажите причину (максимум 1000 байт).",
		"request is no longer pending":                                  "Заявка уже обработана или согласование сброшено. Обновите список.",
		"requester and draft authors cannot review their own package":   "Отправитель и авторы черновиков не могут согласовать или отклонить свой пакет.",
		"package changed":                                               "Пакет изменён. Отправьте новую заявку на согласование.",
		"second administrator approval required for this exact package": "Нужно одобрение второго администратора для полного пакета с текущими редакциями.",
		"reviewer account changed; submit a new request":                "Учётная запись согласующего изменилась. Отправьте новую заявку.",
	}
	if text, ok := messages[reason]; ok {
		return text
	}
	return "Не удалось выполнить согласование. Обновите список заявок."
}
