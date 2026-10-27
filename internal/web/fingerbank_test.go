package web

import (
	"github.com/rkislov/border/internal/guest"
	"github.com/rkislov/border/internal/store"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestFingerbankSettingsHideKeyAndRequireCSRF(t *testing.T) {
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
	body := `{"Enabled":true,"Key":"test-secret-123456789","TTLHours":168}`
	if w := send("POST", "/api/fingerbank/config", body, ""); w.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	if w := send("POST", "/api/fingerbank/config", body, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w := send("GET", "/api/fingerbank/config", "", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "test-secret") || !strings.Contains(w.Body.String(), `"HasKey":true`) {
		t.Fatal("key leak or status failure")
	}
}
