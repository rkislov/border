// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/rkislov/border/internal/store"
)

func (a *app) policyDiagnostic(w http.ResponseWriter, r *http.Request) {
	var input struct {
		NAS string
		store.PolicyRequest
	}
	if !decode(w, r, &input) {
		return
	}
	_, ipErr := netip.ParseAddr(input.NAS)
	q := input.PolicyRequest
	if ipErr != nil || (q.Protocol != "pap" && q.Protocol != "mab" && q.Protocol != "eap") || len(q.Username) > 253 || len(q.SSID) > 32 || strings.ContainsAny(q.Username+q.SSID, "\x00\r\n") || q.ServiceType < 0 || q.ServiceType > 255 || (q.NASPortType != nil && (*q.NASPortType < 0 || *q.NASPortType > 255)) {
		http.Error(w, "invalid policy selectors", 400)
		return
	}
	var exists int
	if err := a.s.Row(r.Context(), "SELECT 1 FROM nas WHERE address=?", input.NAS).Scan(&exists); err != nil {
		http.Error(w, "NAS unavailable in this tenant", 404)
		return
	}
	p, configured, trace, err := a.s.ExplainPolicy(r.Context(), input.NAS, q)
	result := map[string]any{"Trace": trace, "Configured": configured, "Status": "no_match", "CheckedAt": time.Now().Unix()}
	if err != nil {
		// Do not expose database errors or credentials in diagnostics.
		result["Status"] = "configuration_error"
	} else if !configured {
		result["Status"] = "legacy"
	} else if p != nil {
		result["Status"] = "selected"
		result["PolicyID"] = p.Access.ID
		result["AuthenticationID"] = p.Authentication.ID
		result["Source"] = p.Authentication.Source
		result["DomainID"] = p.Authentication.DomainID
		result["Steps"] = p.Authentication.Chain()
		result["Mode"] = p.Access.Mode
		result["VLAN"] = p.VLAN
		result["BindingID"] = p.BindingID
		result["BindingVersion"] = p.BindingVersion
		if ttl, e := p.Timeout(time.Now()); e != nil {
			result["Status"] = "inactive"
		} else {
			result["SessionSeconds"] = ttl
		}
		// Check the same device profile constraints as processPolicy.
		profile, e := a.s.NASProfile(r.Context(), input.NAS)
		if e != nil {
			result["Status"] = "configuration_error"
		} else {
			if p.BindingID != "" {
				profile.Mode = p.Access.Mode
			}
			if profile.Mode != p.Access.Mode {
				result["Status"] = "mode_mismatch"
			}
			profile.Mode = p.Access.Mode
			if profile.Validate() != nil || (p.Access.Mode != "network" && (p.Authentication.Source == "mab" || p.Authentication.Source == "eap_tls")) {
				result["Status"] = "profile_incompatible"
			}
		}
	}
	reply(w, result)
}
