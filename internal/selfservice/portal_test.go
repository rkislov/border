package selfservice

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/directory"
	"github.com/rkislov/border/internal/pki"
	"github.com/rkislov/border/internal/store"
)

type testDirectory struct{}

func (testDirectory) Authenticate(ctx context.Context, user, password string) (directory.Identity, error) {
	if password != "domain-password" {
		return directory.Identity{}, errors.New("bad password")
	}
	return directory.Identity{Username: user, Email: user + "@example.test"}, nil
}

type testMail struct{}

func (testMail) Send(context.Context, string, string, string) error { return nil }
func TestPortalOwnershipAndSession(t *testing.T) {
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.DB.Close()
	if err = db.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	codes, err := auth.New(db, make([]byte, 32), testMail{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	manager := &pki.Manager{Store: db, Vault: codes.Vault}
	ca, err := manager.CreateCA(t.Context(), "Test CA")
	if err != nil {
		t.Fatal(err)
	}
	portal := New(testDirectory{}, codes, manager, "https://portal.example.test")
	h := portal.Handler()
	request := func(method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://portal.example.test"+path, strings.NewReader(body))
		r.TLS = &tls.ConnectionState{}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/api/me", "", nil, ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request("POST", "/api/login", `{"Username":"user","Password":"wrong"}`, nil, ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	login := request("POST", "/api/login", `{"Username":"user","Password":"domain-password"}`, nil, "")
	if login.Code != 200 {
		t.Fatal(login.Body.String())
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("insecure session cookie")
	}
	var session map[string]string
	if err = json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	csrf := session["csrf"]
	cookie := cookies[0]
	if w := request("POST", "/api/email-code", "{}", cookie, ""); w.Code != 403 {
		t.Fatal("CSRF missing", w.Code)
	}
	w := request("POST", "/api/certificates/issue", `{"CA":"`+ca.ID+`"}`, cookie, csrf)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var bundle struct{ Bundle pki.Bundle }
	if err = json.Unmarshal(w.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Bundle.PrivateKey == "" {
		t.Fatal("key not returned")
	}
	w = request("GET", "/api/me", "", cookie, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatal("me exposes private key")
	}
	other, err := manager.Issue(t.Context(), ca.ID, "other", "", "", "", 90)
	if err != nil {
		t.Fatal(err)
	}
	w = request("POST", "/api/certificates/revoke", `{"Serial":"`+other.Serial+`"}`, cookie, csrf)
	if w.Code != 400 {
		t.Fatal("cross-user revoke allowed")
	}
	w = request("POST", "/api/certificates/issue", `{"CA":"`+ca.ID+`","Renewal":"`+other.Serial+`"}`, cookie, csrf)
	if w.Code != 400 {
		t.Fatal("cross-user reissue allowed")
	}
	w = request("POST", "/api/certificates/revoke", `{"Serial":"`+bundle.Bundle.Serial+`"}`, cookie, csrf)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = request("GET", "/crl/"+ca.ID, "", nil, "")
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/pkix-crl" {
		t.Fatal("public CRL unavailable")
	}
	if w = request("POST", "/api/logout", "{}", cookie, csrf); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = request("GET", "/api/me", "", cookie, ""); w.Code != 401 {
		t.Fatal("logout session active")
	}
}
