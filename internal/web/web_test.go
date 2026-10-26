package web

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkislov/border/internal/store"
)

func TestAdminAPI(t *testing.T) {
	s, err := store.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
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
	h := Handler(s)
	send := func(method, path, body, csrf string, cert, auth bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://localhost"+path, strings.NewReader(body))
		if cert {
			r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}
		}
		if auth {
			r.SetBasicAuth("admin", "strong-password-123")
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := send("GET", "/", "", "", false, true); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := send("GET", "/api/state", "", "", true, false); w.Code != 401 {
		t.Fatal(w.Code)
	}
	page := send("GET", "/", "", "", true, true)
	if page.Code != 200 {
		t.Fatal(page.Code)
	}
	parts := strings.Split(page.Body.String(), `name="csrf-token" content="`)
	if len(parts) != 2 {
		t.Fatal("CSRF token missing")
	}
	csrf := strings.Split(parts[1], `"`)[0]
	if w := send("POST", "/api/vlans", `{"ID":100,"Name":"data"}`, "", true, true); w.Code != 403 {
		t.Fatal("CSRF missing", w.Code)
	}
	for _, tc := range []struct {
		path, body string
		status     int
	}{{"/api/vlans", `{"ID":4095,"Name":"bad"}`, 400}, {"/api/vlans", `{"ID":100,"Name":"data"}`, 200}, {"/api/nas", `{"Address":"127.0.0.1","Name":"switch","Secret":"0123456789abcdef"}`, 200}, {"/api/devices", `{"MAC":"aa-bb-cc-dd-ee-ff","VLAN":123,"Active":true}`, 400}, {"/api/devices", `{"MAC":"aa-bb-cc-dd-ee-ff","VLAN":100,"Active":true}`, 200}, {"/api/delete", `{"Kind":"vlans","Key":"100"}`, 400}, {"/api/settings", `{"Isolation":123}`, 400}, {"/api/settings", `{"Isolation":100}`, 200}} {
		w := send("POST", tc.path, tc.body, csrf, true, true)
		if w.Code != tc.status {
			t.Fatalf("%s: got %d want %d: %s", tc.path, w.Code, tc.status, w.Body.String())
		}
	}
	w := send("GET", "/api/state", "", "", true, true)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var data map[string]json.RawMessage
	if err = json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(w.Body.String(), "0123456789abcdef") {
		t.Fatal("NAS secret leaked")
	}
	if w.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing CSP")
	}
}
