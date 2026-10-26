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
		NAS, ID, Action, MAC, Username string
		VLAN                           int
		Updated                        int64
	}
	if !decode(w, r, &v) {
		return
	}
	result, err := aaa.ChangeSession(r.Context(), a.s, v.NAS, v.ID, v.Action, v.VLAN, store.Session{NAS: v.NAS, ID: v.ID, MAC: v.MAC, Username: v.Username, Updated: v.Updated})
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	reply(w, result)
}
