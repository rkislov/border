// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package selfservice

import (
	"context"
	"errors"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/guest"
	"github.com/rkislov/border/internal/pki"
	"github.com/rkislov/border/internal/store"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetcrazeRedirectHTTPBoundary(t *testing.T) {
	s, e := store.Open("sqlite", filepath.Join(t.TempDir(), "portal.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	if e = s.Migrate(t.Context()); e != nil {
		t.Fatal(e)
	}
	codes, _ := auth.New(s, make([]byte, 32), nil, 0)
	g, _ := guest.New(s, make([]byte, 32))
	defer g.Close()
	const public = "https://border.example/portal/tenant-a"
	calls := 0
	g.CaptiveRedirect = func(_ context.Context, nas, query, base string) (string, error) {
		calls++
		if nas != "192.0.2.1" || base != public {
			t.Fatal("incorrect scope")
		}
		if query != "valid=1" {
			return "", errors.New("private-router-error")
		}
		return "signed+token", nil
	}
	h := New(testDirectory{}, codes, &pki.Manager{Store: s, Vault: codes.Vault}, public, g).Handler()
	send := func(query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://untrusted.example/uam/netcraze/192.0.2.1?"+query, nil)
		r.Header.Set("X-Forwarded-Host", "evil.example")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := send("valid=1")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/portal/tenant-a/guest?token=signed%2Btoken" {
		t.Fatal("unsafe tenant redirect", w.Code, w.Header())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("captive redirect cacheable")
	}
	w = send("invalid=1")
	if w.Code != 403 || strings.Contains(w.Body.String(), "private") {
		t.Fatal("error disclosure")
	}
	for i := 0; i < 59; i++ {
		send("invalid=1")
	}
	if calls != 60 {
		t.Fatal("rate limit", calls)
	}
}
