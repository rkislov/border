// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"bytes"
	"encoding/base64"
	"github.com/rkislov/border/internal/store"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
)

func (a *app) portalDesignRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/portal-design", func(w http.ResponseWriter, r *http.Request) {
		scope := r.URL.Query().Get("scope")
		if a.s.ValidatePortalScope(r.Context(), scope) != nil {
			http.Error(w, "unknown scope", 400)
			return
		}
		d, err := a.s.PortalDesign(r.Context(), scope)
		if err != nil {
			http.Error(w, "design unavailable", 503)
			return
		}
		reply(w, d)
	})
	mux.HandleFunc("POST /api/portal-design", func(w http.ResponseWriter, r *http.Request) {
		var d store.PortalDesign
		if !decode(w, r, &d) {
			return
		}
		scope := r.URL.Query().Get("scope")
		old, err := a.s.PortalDesign(r.Context(), scope)
		if err != nil {
			http.Error(w, "design unavailable", 503)
			return
		}
		d.Background = old.Background
		a.finish(w, r, a.s.SavePortalDesign(r.Context(), scope, d), "save captive portal design")
	})
	mux.HandleFunc("POST /api/portal-design/background", func(w http.ResponseWriter, r *http.Request) {
		scope := r.URL.Query().Get("scope")
		if a.s.ValidatePortalScope(r.Context(), scope) != nil {
			http.Error(w, "unknown scope", 400)
			return
		}
		d, err := a.s.PortalDesign(r.Context(), scope)
		if err != nil {
			http.Error(w, "design unavailable", 503)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
		if err != nil {
			http.Error(w, "image exceeds 2 MiB", 400)
			return
		}
		d.Background = ""
		if len(raw) > 0 {
			cfg, format, err := image.DecodeConfig(bytes.NewReader(raw))
			if err != nil || (format != "png" && format != "jpeg") || cfg.Width > 4096 || cfg.Height > 4096 || cfg.Width*cfg.Height > 12000000 {
				http.Error(w, "PNG/JPEG up to 4096px and 12 megapixels required", 400)
				return
			}
			if _, _, err = image.Decode(bytes.NewReader(raw)); err != nil {
				http.Error(w, "invalid image", 400)
				return
			}
			d.Background = "data:image/" + format + ";base64," + base64.StdEncoding.EncodeToString(raw)
		}
		a.finish(w, r, a.s.SavePortalDesign(r.Context(), scope, d), "update captive portal background")
	})
}
