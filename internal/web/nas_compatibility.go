// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"context"
	"database/sql"
	"github.com/rkislov/border/internal/radprofile"
	"net/http"
	"net/netip"
	"time"
)

type compatibilityFinding struct{ Severity, Code, Message string }

func (a *app) nasCompatibility(w http.ResponseWriter, r *http.Request) {
	nas := r.URL.Query().Get("nas")
	if _, err := netip.ParseAddr(nas); err != nil {
		http.Error(w, "invalid NAS address", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var dictionary, mode, credential, policy string
	err := a.s.Row(ctx, "SELECT dictionary,access_mode,credential,COALESCE(access_policy_id,'') FROM nas WHERE address=?", nas).Scan(&dictionary, &mode, &credential, &policy)
	if err == sql.ErrNoRows {
		http.Error(w, "NAS unavailable in this tenant", 404)
		return
	}
	if err != nil {
		http.Error(w, "diagnostics unavailable", 503)
		return
	}
	capabilities, ok := radprofile.Describe(dictionary)
	findings := []compatibilityFinding{}
	add := func(severity, code, message string) {
		findings = append(findings, compatibilityFinding{severity, code, message})
	}
	if !ok {
		add("error", "unknown_profile", "Неизвестный профиль NAS.")
	} else if (radprofile.Config{Dictionary: dictionary, Mode: mode, Credential: credential}).Validate() != nil {
		add("error", "invalid_profile", "Режим или способ проверки несовместим с профилем NAS.")
	}
	set, err := a.s.NASPolicies(ctx, nas)
	if err != nil {
		http.Error(w, "diagnostics unavailable", 503)
		return
	}
	ids := []string{}
	if set.Enabled {
		for _, b := range set.Bindings {
			if b.Enabled {
				ids = append(ids, b.PolicyID)
			}
		}
	} else if policy != "" {
		ids = append(ids, policy)
	}
	if len(ids) == 0 {
		add("warning", "no_policy", "Нет активных привязок политик. Проверьте настройки прежнего режима разрешений.")
	}
	for _, id := range ids {
		var pm string
		var enabled bool
		var from, until int64
		err = a.s.Row(ctx, "SELECT mode,enabled,valid_from,valid_until FROM access_policies WHERE id=?", id).Scan(&pm, &enabled, &from, &until)
		if err == sql.ErrNoRows {
			add("error", "missing_policy", "Не найдена политика "+id)
			continue
		}
		if err != nil {
			http.Error(w, "diagnostics unavailable", 503)
			return
		}
		if !radprofile.SupportsMode(dictionary, pm) {
			add("error", "policy_mode", "Профиль не поддерживает назначение политики "+id)
		}
		if !set.Enabled && pm != mode {
			add("error", "mode_mismatch", "Назначение одиночной политики не совпадает с режимом NAS: "+id)
		}
		if from > time.Now().Unix() {
			add("warning", "future_policy", "Срок действия политики ещё не наступил: "+id)
		}
		if !enabled || until > 0 && until <= time.Now().Unix() {
			add("warning", "inactive_policy", "Политика выключена или истекла: "+id)
		}
	}
	var total, unlinked, last, acks, naks int64
	err = a.s.Row(ctx, `SELECT COUNT(*),COALESCE(SUM(CASE WHEN s.status IN ('active','stale') AND NOT EXISTS(SELECT 1 FROM access_grants g WHERE g.token=s.grant_token AND g.nas=s.nas) THEN 1 ELSE 0 END),0),COALESCE(MAX(s.last_seen),0),COALESCE(SUM(CASE WHEN s.revoke_response='Disconnect-ACK' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN s.revoke_cause=406 THEN 1 ELSE 0 END),0) FROM sessions s WHERE s.nas=?`, nas).Scan(&total, &unlinked, &last, &acks, &naks)
	if err != nil {
		http.Error(w, "diagnostics unavailable", 503)
		return
	}
	if total == 0 {
		add("warning", "no_accounting", "Нет сохранённых accounting-сессий. Передачу accounting подтвердить нельзя.")
	}
	if unlinked > 0 {
		add("warning", "unlinked_sessions", "Есть активные сессии без связи с разрешением: автоматический отзыв для них недоступен.")
	}
	if naks > 0 {
		add("warning", "unsupported_disconnect", "Сохранены ответы NAK 406: NAS отклонял операцию отзыва.")
	}
	add("info", "passive_check", "Проверка только конфигурации и сохранённых наблюдений. Пакеты на оборудование не отправляются; текущая доступность и совместимость прошивки не подтверждаются.")
	w.Header().Set("Cache-Control", "no-store")
	reply(w, map[string]any{"NAS": nas, "CheckedAt": time.Now().Unix(), "Capabilities": capabilities, "Findings": findings, "Sessions": total, "UnlinkedSessions": unlinked, "LastAccounting": last, "DisconnectACKs": acks, "UnsupportedDisconnects": naks})
}
