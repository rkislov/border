// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"bytes"
	"encoding/json"
	"github.com/rkislov/border/internal/store"
	"image"
	"image/png"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestPortalDesignAPIImageAndCSRF(t *testing.T) {
	s, err := store.Open("sqlite", filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = s.Admin(t.Context(), "admin", "strong-password-123", false); err != nil {
		t.Fatal(err)
	}
	h := HandlerWithOptions(s, nil, nil, false)
	send := func(method, path string, body []byte, csrf string, authenticated bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://localhost"+path, bytes.NewReader(body))
		if authenticated {
			r.SetBasicAuth("admin", "strong-password-123")
		}
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	page := send("GET", "/", nil, "", true)
	csrf := strings.Split(strings.Split(page.Body.String(), `name="csrf-token" content="`)[1], `"`)[0]
	path := "/api/portal-design/background?scope=tenant"
	if w := send("GET", "/api/portal-design?scope=tenant", nil, "", false); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := send("POST", path, []byte("x"), "", true); w.Code != 403 {
		t.Fatal(w.Code)
	}
	for _, raw := range [][]byte{[]byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`), bytes.Repeat([]byte("x"), (2<<20)+1)} {
		if w := send("POST", path, raw, csrf, true); w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	var b bytes.Buffer
	if err = png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 4, 4))); err != nil {
		t.Fatal(err)
	}
	if w := send("POST", path, b.Bytes(), csrf, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	d := store.DefaultPortalDesign()
	d.Custom = true
	d.Background = "data:text/html,malicious"
	raw, _ := json.Marshal(d)
	if w := send("POST", "/api/portal-design?scope=tenant", raw, csrf, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	saved, err := s.PortalDesign(t.Context(), "tenant")
	if err != nil || !strings.HasPrefix(saved.Background, "data:image/png;base64,") {
		t.Fatal("background replaced through JSON", err)
	}
	if w := send("POST", path, nil, csrf, true); w.Code != 200 {
		t.Fatal(w.Code)
	}
	saved, _ = s.PortalDesign(t.Context(), "tenant")
	if saved.Background != "" {
		t.Fatal("background not removed")
	}
}
