package web

import (
	"github.com/rkislov/border/internal/guest"
	"github.com/rkislov/border/internal/store"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestRouterOSSettingsHidePasswordAndRequireCSRF(t *testing.T) {
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
	g, _ := guest.New(s, make([]byte, 32))
	h := HandlerWithOptions(s, nil, nil, false, g)
	send := func(method, path, body, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://localhost"+path, strings.NewReader(body))
		r.SetBasicAuth("admin", "strong-password-123")
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	page := send("GET", "/", "", "")
	parts := strings.Split(page.Body.String(), `name="csrf-token" content="`)
	if len(parts) != 2 {
		t.Fatal("no CSRF")
	}
	csrf := strings.Split(parts[1], `"`)[0]
	if e := s.Exec(t.Context(), "INSERT INTO nas(address,name,secret,dictionary,access_mode) VALUES('192.0.2.1','test','test-secret-12345','mikrotik','ssh')"); e != nil {
		t.Fatal(e)
	}
	body := `{"NAS":"192.0.2.1","Enabled":true,"Address":"192.0.2.1:22","Username":"service","Password":"test-secret-123456789","HostKey":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`
	if w := send("POST", "/api/routeros?nas=192.0.2.1", body, ""); w.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	if w := send("POST", "/api/routeros?nas=192.0.2.1", body, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w := send("GET", "/api/routeros?nas=192.0.2.1", "", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "test-secret") || !strings.Contains(w.Body.String(), `"HasPassword":true`) {
		t.Fatal("key leak or status failure")
	}
}
