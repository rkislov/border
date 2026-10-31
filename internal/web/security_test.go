// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/pki"
	"github.com/rkislov/border/internal/store"
)

func TestAdminMFAAndMonitoringHTTPBoundary(t *testing.T) {
	s, e := store.Open("sqlite", filepath.Join(t.TempDir(), "root.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	ctx := t.Context()
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if e = s.Admin(ctx, "admin", "test-password-123", false); e != nil {
		t.Fatal(e)
	}
	key := make([]byte, 32)
	rand.Read(key)
	vault, _ := auth.NewVault(key)
	h := HandlerWithOptions(s, &pki.Manager{Store: s, Vault: vault}, nil, false)
	call := func(method, path string, body any, cookie *http.Cookie, authHeader, csrf string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, "https://border.test"+path, strings.NewReader(string(raw)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if authHeader == "basic" {
			r.SetBasicAuth("admin", "test-password-123")
		} else if authHeader != "" {
			r.Header.Set("Authorization", "Bearer "+authHeader)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	expect := func(w *httptest.ResponseRecorder, code int) {
		t.Helper()
		if w.Code != code {
			t.Fatalf("want %d got %d: %s", code, w.Code, w.Body.String())
		}
	}
	decodeJSON := func(w *httptest.ResponseRecorder, v any) {
		t.Helper()
		expect(w, 200)
		if e := json.Unmarshal(w.Body.Bytes(), v); e != nil {
			t.Fatal(e)
		}
	}
	loginBody := map[string]string{"Username": "admin", "Password": "test-password-123"}
	w := call("POST", "/api/login", loginBody, nil, "", "")
	expect(w, 200)
	old := w.Result().Cookies()[0]
	page := call("GET", "/", nil, old, "", "").Body.String()
	csrf := strings.Split(strings.Split(page, `name="csrf-token" content="`)[1], `"`)[0]
	expect(call("POST", "/api/admin-security/begin", map[string]string{"Password": "test-password-123"}, old, "", ""), 403)
	var enrollment struct{ Secret, QR string }
	decodeJSON(call("POST", "/api/admin-security/begin", map[string]string{"Password": "test-password-123"}, old, "", csrf), &enrollment)
	if !strings.HasPrefix(enrollment.QR, "data:image/png;base64,") {
		t.Fatal("missing local QR")
	}
	otp, _ := totp.GenerateCode(enrollment.Secret, time.Now())
	w = call("POST", "/api/admin-security/confirm", map[string]string{"Password": "test-password-123", "Code": otp}, old, "", csrf)
	var confirmed struct{ RecoveryCodes []string }
	decodeJSON(w, &confirmed)
	if len(confirmed.RecoveryCodes) != 10 {
		t.Fatal("recovery codes missing")
	}
	cookie := w.Result().Cookies()[0]
	expect(call("GET", "/api/me", nil, old, "", ""), 401)
	expect(call("GET", "/metrics", nil, nil, "basic", ""), 401)
	expect(call("GET", "/metrics", nil, cookie, "basic", ""), 401)
	var challenge struct {
		MFARequired bool
		Challenge   string
	}
	w = call("POST", "/api/login", loginBody, nil, "", "")
	decodeJSON(w, &challenge)
	if !challenge.MFARequired || len(w.Result().Cookies()) != 0 {
		t.Fatal("password-only session issued")
	}
	expect(call("POST", "/api/login", map[string]string{"Challenge": challenge.Challenge, "Code": otp}, nil, "", ""), 401)
	w = call("POST", "/api/login", map[string]string{"Challenge": challenge.Challenge, "Code": confirmed.RecoveryCodes[0]}, nil, "", "")
	expect(w, 200)
	cookie = w.Result().Cookies()[0]
	expect(call("POST", "/api/login", map[string]string{"Challenge": challenge.Challenge, "Code": confirmed.RecoveryCodes[1]}, nil, "", ""), 401)
	expect(call("POST", "/api/monitoring-tokens", map[string]any{"Name": "prom", "Scopes": []string{"metrics:read"}, "ExpiresAt": time.Now().Add(24 * time.Hour).Unix(), "Password": "test-password-123"}, cookie, "", csrf), 401)
	var token struct {
		Token    string
		Metadata struct{ ID string }
	}
	decodeJSON(call("POST", "/api/monitoring-tokens", map[string]any{"Name": "prom", "Scopes": []string{"metrics:read"}, "ExpiresAt": time.Now().Add(24 * time.Hour).Unix(), "Password": "test-password-123", "Code": confirmed.RecoveryCodes[1]}, cookie, "", csrf), &token)
	if token.Token == "" {
		t.Fatal("token not returned")
	}
	expect(call("GET", "/metrics", nil, nil, token.Token, ""), 200)
	for _, path := range []string{"/api/health", "/api/me", "/api/state", "/", "/api/backups", "/api/admin-security"} {
		expect(call("GET", path, nil, cookie, token.Token, ""), 403)
	}
	expect(call("POST", "/api/logout", map[string]string{}, cookie, token.Token, csrf), 403)
	expect(call("GET", "/api/me", nil, cookie, "invalid-token", ""), 401)
	list := call("GET", "/api/monitoring-tokens", nil, cookie, "", "")
	expect(list, 200)
	if strings.Contains(list.Body.String(), token.Token) {
		t.Fatal("token listed again")
	}
	var healthToken struct {
		Token    string
		Metadata struct{ ID string }
	}
	decodeJSON(call("POST", "/api/monitoring-tokens", map[string]any{"Name": "health", "Scopes": []string{"health:read"}, "ExpiresAt": time.Now().Add(24 * time.Hour).Unix(), "Password": "test-password-123", "Code": confirmed.RecoveryCodes[4]}, cookie, "", csrf), &healthToken)
	expect(call("GET", "/api/health", nil, nil, healthToken.Token, ""), 200)
	expect(call("GET", "/metrics", nil, nil, healthToken.Token, ""), 403)
	expect(call("POST", "/api/monitoring-tokens/revoke", map[string]string{"ID": healthToken.Metadata.ID, "Password": "test-password-123", "Code": confirmed.RecoveryCodes[5]}, cookie, "", csrf), 200)
	expect(call("GET", "/api/health", nil, nil, healthToken.Token, ""), 401)

	// Mutating MFA invalidates all prior browser sessions, pending challenges and tokens.
	var stale struct{ Challenge string }
	decodeJSON(call("POST", "/api/login", loginBody, nil, "", ""), &stale)
	w = call("POST", "/api/admin-security/recovery", map[string]string{"Password": "test-password-123", "Code": confirmed.RecoveryCodes[2]}, cookie, "", csrf)
	var rotated struct{ RecoveryCodes []string }
	decodeJSON(w, &rotated)
	next := w.Result().Cookies()[0]
	expect(call("GET", "/api/me", nil, cookie, "", ""), 401)
	expect(call("GET", "/metrics", nil, nil, token.Token, ""), 401)
	expect(call("POST", "/api/login", map[string]string{"Challenge": stale.Challenge, "Code": rotated.RecoveryCodes[0]}, nil, "", ""), 401)
	w = call("POST", "/api/admin-security/disable", map[string]string{"Password": "test-password-123", "Code": rotated.RecoveryCodes[0]}, next, "", csrf)
	expect(w, 200)
	expect(call("GET", "/api/me", nil, next, "", ""), 401)
	expect(call("GET", "/metrics", nil, nil, "basic", ""), 200)
}

func TestMonitoringTokensCannotCrossTenantsOrOperatorPermissions(t *testing.T) {
	var handlers []http.Handler
	for i := 0; i < 2; i++ {
		s, e := store.Open("sqlite", filepath.Join(t.TempDir(), "tenant.db"))
		if e != nil {
			t.Fatal(e)
		}
		defer s.DB.Close()
		if e = s.Migrate(t.Context()); e != nil {
			t.Fatal(e)
		}
		if e = s.Admin(t.Context(), "admin", "test-password-123", false); e != nil {
			t.Fatal(e)
		}
		if e = s.SaveAdminAccount(t.Context(), "admin", store.AdminChange{Username: "viewer", Password: "test-password-123", Role: "viewer", Enabled: true}); e != nil {
			t.Fatal(e)
		}
		handlers = append(handlers, HandlerWithOptions(s, nil, nil, false))
	}
	send := func(h http.Handler, user, path string, body any, token string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		method := "GET"
		if body != nil {
			method = "POST"
		}
		r := httptest.NewRequest(method, "https://border.test"+path, strings.NewReader(string(raw)))
		r.SetBasicAuth(user, "test-password-123")
		r.Header.Set("X-CSRF-Token", token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := send(handlers[0], "viewer", "/account/security", nil, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	csrf := strings.Split(strings.Split(w.Body.String(), `name="csrf-token" content="`)[1], `"`)[0]
	for _, path := range []string{"/api/monitoring-tokens", "/api/monitoring-tokens/revoke"} {
		w = send(handlers[0], "viewer", path, map[string]string{}, csrf)
		if w.Code != 403 {
			t.Fatal(path, w.Code)
		}
	}
	if w = send(handlers[0], "viewer", "/api/admin-security", nil, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	// A challenge and session are private to an app, even with identical passwords.
	w = send(handlers[0], "admin", "/api/login", map[string]string{"Username": "admin", "Password": "test-password-123"}, "")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	r := httptest.NewRequest("GET", "https://border.test/api/me", nil)
	r.AddCookie(w.Result().Cookies()[0])
	out := httptest.NewRecorder()
	handlers[1].ServeHTTP(out, r)
	if out.Code != 401 {
		t.Fatal("cross-tenant session", out.Code)
	}
}
