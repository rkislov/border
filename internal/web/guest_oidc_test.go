package web

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkislov/border/internal/guest"
	"github.com/rkislov/border/internal/store"
)

func TestGuestOIDCAdminAPISecretsAndCSRF(t *testing.T) {
	s, e := store.Open("sqlite", filepath.Join(t.TempDir(), "web.db"))
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
	for _, q := range []string{"INSERT INTO network_segments VALUES('guests','Guests')", "INSERT INTO authentication_policies(id,name,source) VALUES('oidc','OIDC','oidc')", "INSERT INTO access_policies(id,name,authentication_id,mode,segment_id,session_seconds) VALUES('guests','Guests','oidc','network','guests',600)"} {
		if e = s.Exec(t.Context(), q); e != nil {
			t.Fatal(e)
		}
	}
	guests, _ := guest.New(s, make([]byte, 32))
	guests.PublicURL = "https://border.example/portal/lab"
	h := HandlerWithOptions(s, nil, nil, false, guests)
	call := func(method, path, body, csrf string, authenticated bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://border.example"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		if authenticated {
			r.SetBasicAuth("admin", "test-password-123")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	page := call("GET", "/", "", "", true)
	csrf := strings.Split(strings.Split(page.Body.String(), `name="csrf-token" content="`)[1], `"`)[0]
	c := guest.OIDCConfiguration{OIDCProvider: store.OIDCProvider{Scope: "tenant", ID: "oidc", Name: "SSO", Issuer: "https://sso.example", ClientID: "border", AccessPolicyID: "guests", AuthStyle: "basic", Enabled: true}, ClientSecret: "never-expose-this-secret"}
	raw, _ := json.Marshal(c)
	if w := call("GET", "/api/guest/oidc?scope=tenant", "", "", false); w.Code != 401 {
		t.Fatal("anonymous read", w.Code)
	}
	if w := call("POST", "/api/guest/oidc", string(raw), "", true); w.Code != 403 {
		t.Fatal("missing CSRF", w.Code)
	}
	if w := call("POST", "/api/guest/oidc", string(raw), csrf, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w := call("GET", "/api/guest/oidc?scope=tenant", "", "", true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"HasSecret":true`) || strings.Contains(w.Body.String(), c.ClientSecret) || strings.Contains(w.Body.String(), "ClientSecret") {
		t.Fatal("secret exposure", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "https://border.example/portal/lab/api/guest/oidc/callback") {
		t.Fatal("tenant callback missing")
	}
	if w = call("POST", "/api/guest/oidc", string(raw), csrf, true); w.Code != 400 {
		t.Fatal("lost update allowed", w.Code)
	}
}
