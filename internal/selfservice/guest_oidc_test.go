package selfservice

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/guest"
	"github.com/rkislov/border/internal/pki"
	"github.com/rkislov/border/internal/store"
)

func TestOIDCCallbackHTTPBoundaryAndCleanResult(t *testing.T) {
	s, e := store.Open("sqlite", filepath.Join(t.TempDir(), "portal.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	if e = s.Migrate(t.Context()); e != nil {
		t.Fatal(e)
	}
	codes, _ := auth.New(s, make([]byte, 32), nil, 0)
	guests, _ := guest.New(s, make([]byte, 32))
	guests.PublicURL = "https://border.example/portal/lab"
	h := New(testDirectory{}, codes, &pki.Manager{Store: s, Vault: codes.Vault}, guests.PublicURL, guests).Handler()
	call := func(method, path, body, origin string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://border.example"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := call("POST", "/api/guest/oidc/start", `{"Token":"forged","Provider":"oidc"}`, "https://evil.example"); w.Code != 403 {
		t.Fatal("cross-site start", w.Code)
	}
	if w := call("POST", "/api/guest/oidc/start", `{"Token":"forged","Provider":"oidc"}`, ""); w.Code != 400 {
		t.Fatal("forged NAS token", w.Code)
	}
	w := call("GET", "/api/guest/oidc/callback?state=wrong&code=never-reflect-this-code", "", "")
	if w.Code != 303 || w.Header().Get("Location") != "/portal/lab/guest/oidc/result" || strings.Contains(w.Body.String(), "never-reflect") {
		t.Fatal("callback result leak", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/portal/lab/" {
			t.Fatal("unsafe cookie", c)
		}
	}
	result := call("GET", "/guest/oidc/result", "", "", w.Result().Cookies()...)
	if !strings.Contains(result.Body.String(), "Вход не завершён") || result.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(result.Body.String())
	}
	raw, _ := json.Marshal(oidcResult{Success: true, Until: time.Now().Unix() + 60, Grant: guest.Grant{Expires: time.Now().Unix() + 600}})
	success := &http.Cookie{Name: "__Secure-border-oidc-result", Value: guests.Vault.Seal(raw, "guest-oidc-result")}
	result = call("GET", "/guest/oidc/result", "", "", success)
	if !strings.Contains(result.Body.String(), "Вход подтверждён") {
		t.Fatal(result.Body.String())
	}
	success.Value += "tamper"
	result = call("GET", "/guest/oidc/result", "", "", success)
	if strings.Contains(result.Body.String(), "Вход подтверждён") {
		t.Fatal("forged result")
	}
}
