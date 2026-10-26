// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"net/http"

	"github.com/rkislov/border/internal/pki"
)

func (a *app) pkiRoutes(mux *http.ServeMux) {
	ready := func(w http.ResponseWriter) bool {
		if a.pki == nil {
			http.Error(w, "PKI requires BORDER_MASTER_KEY; restart with configured key", 503)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /api/pki", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		cas, err := a.pki.Authorities(r.Context())
		if err != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		certs, err := a.pki.Certificates(r.Context(), "")
		if err != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		reply(w, map[string]any{"authorities": cas, "certificates": certs, "acme": a.acme.Config()})
	})
	mux.HandleFunc("POST /api/pki/ca", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		var v struct{ Name, Certificate, PrivateKey string }
		if !decode(w, r, &v) {
			return
		}
		var ca pki.Authority
		var err error
		if v.Certificate != "" || v.PrivateKey != "" {
			ca, err = a.pki.ImportCA(r.Context(), v.Name, v.Certificate, v.PrivateKey)
		} else {
			ca, err = a.pki.CreateCA(r.Context(), v.Name)
		}
		if err != nil {
			http.Error(w, "invalid CA certificate, key or name", 400)
			return
		}
		_ = a.s.Audit(r.Context(), "web", "admin", "created", "CA "+ca.ID)
		reply(w, ca)
	})
	mux.HandleFunc("POST /api/pki/issue", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		var v struct {
			CA, Owner, Email, Renewal, CRLURL string
			Days                              int
		}
		if !decode(w, r, &v) {
			return
		}
		bundle, err := a.pki.Issue(r.Context(), v.CA, v.Owner, v.Email, v.Renewal, v.CRLURL, v.Days)
		if err != nil {
			http.Error(w, "certificate issuance failed; check CA validity, owner and renewal", 400)
			return
		}
		_ = a.s.Audit(r.Context(), "web", "admin", "issued", bundle.Serial)
		reply(w, bundle)
	})
	mux.HandleFunc("POST /api/pki/revoke", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		var v struct{ Serial string }
		if !decode(w, r, &v) {
			return
		}
		a.finish(w, r, a.pki.Revoke(r.Context(), v.Serial, ""), "revoke certificate "+v.Serial)
	})
	mux.HandleFunc("GET /api/pki/crl/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		b, err := a.pki.CRL(r.Context(), r.PathValue("id"))
		if err != nil {
			http.Error(w, "CRL unavailable", 400)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Header().Set("Content-Disposition", `attachment; filename="border.crl"`)
		w.Write(b)
	})
	mux.HandleFunc("POST /api/pki/acme", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		var v pki.ACMEConfig
		if !decode(w, r, &v) {
			return
		}
		if err := a.acme.Configure(r.Context(), v); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		_ = a.s.Audit(r.Context(), "web", "admin", "updated", "ACME configuration")
		reply(w, map[string]bool{"ok": true})
	})
}
