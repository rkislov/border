// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import "net/http"

func (a *app) eapPolicy(w http.ResponseWriter, r *http.Request) {
	enabled, vlan, err := a.s.EAPPolicy(r.Context())
	if err != nil {
		http.Error(w, "EAP settings unavailable; run init-db", 503)
		return
	}
	reply(w, map[string]any{"Enabled": enabled, "VLAN": vlan, "Available": a.pki != nil})
}
func (a *app) setEAPPolicy(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Enabled bool
		VLAN    int
	}
	if !decode(w, r, &v) {
		return
	}
	if v.Enabled {
		if a.pki == nil {
			http.Error(w, "EAP requires BORDER_MASTER_KEY and managed PKI", 400)
			return
		}
		cas, err := a.pki.Authorities(r.Context())
		if err != nil || len(cas) == 0 {
			http.Error(w, "create a managed CA first", 400)
			return
		}
	}
	a.finish(w, r, a.s.SetEAPPolicy(r.Context(), v.Enabled, v.VLAN), "save EAP-TLS policy")
}
