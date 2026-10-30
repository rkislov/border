// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"net/http"

	"github.com/rkislov/border/internal/aaa"
	"github.com/rkislov/border/internal/store"
)

func (a *app) sessionAction(w http.ResponseWriter, r *http.Request) {
	var v struct {
		NAS, ID, Action, MAC, Username, Generation string
		VLAN                                       int
		Updated                                    int64
	}
	if !decode(w, r, &v) {
		return
	}
	p := requestAccount(r)
	if p.Role == "operator" {
		var n int
		if p.LocationID == "" || (v.Action != "disconnect" && v.Action != "retry") || a.s.Row(r.Context(), "SELECT 1 FROM nas WHERE address=? AND location_id=?", v.NAS, p.LocationID).Scan(&n) != nil {
			http.Error(w, "session outside permitted scope or action forbidden", 403)
			return
		}
	}
	if v.Generation == "" {
		http.Error(w, "session generation required", 400)
		return
	}
	if v.Action == "retry" {
		if err := a.s.RetryRevocation(r.Context(), store.Session{NAS: v.NAS, ID: v.ID, Generation: v.Generation}); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := a.s.Audit(r.Context(), "web", p.Username, "queued", "manual revocation retry for "+v.NAS+"/"+v.ID); err != nil {
			http.Error(w, "retry queued but audit failed", 500)
			return
		}
		reply(w, map[string]bool{"Queued": true})
		return
	}
	result, err := aaa.ChangeSessionWithFallback(r.Context(), a.s, v.NAS, v.ID, v.Action, v.VLAN, a.routerOS.Disconnect, store.Session{NAS: v.NAS, ID: v.ID, MAC: v.MAC, Username: v.Username, Updated: v.Updated, Generation: v.Generation})
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if err := a.s.Audit(r.Context(), "web", p.Username, "session-action", v.Action+" "+v.NAS+"/"+v.ID); err != nil {
		http.Error(w, "action completed but audit failed", 500)
		return
	}
	reply(w, result)
}
