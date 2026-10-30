package tenancy

import (
	"bytes"
	"crypto/tls"
	"github.com/rkislov/border/internal/identitysource"
	"github.com/rkislov/border/internal/store"
	"github.com/rkislov/border/internal/web"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsolationRestartRoutingAndCookieScope(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	driver, dsn := "sqlite", filepath.Join(dir, "root.db")
	if value := os.Getenv("BORDER_TEST_TENANCY_POSTGRES"); value != "" {
		driver, dsn = "pgx", value
	}
	root, e := store.Open(driver, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer root.DB.Close()
	if e = root.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	root.Exec(ctx, "INSERT INTO oui_prefixes VALUES('001122','Public vendor')")
	m := &Manager{Root: root, Driver: driver, DSN: dsn, Directory: filepath.Join(dir, "tenants"), Key: bytes.Repeat([]byte{42}, 32), PublicURL: "https://border.example.test"}
	if e = m.Init(ctx); e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"alpha", "bravo"} {
		if e = m.Create(ctx, web.TenantSpec{ID: id, Name: id, Admin: "admin", Password: "test-password-12345"}); e != nil {
			t.Fatal(e)
		}
	}
	a, b := m.runtimes["alpha"], m.runtimes["bravo"]
	if !a.Store.CheckAdmin(ctx, "admin", "test-password-12345") {
		t.Fatal("bootstrap")
	}
	for _, r := range []*Runtime{a, b} {
		if e = r.Options.Identities.SaveLocal(ctx, identitysource.LocalUser{Username: "same", Password: "local-password-123", Enabled: true}); e != nil {
			t.Fatal(e)
		}
	}
	a.Options.Identities.SaveLocal(ctx, identitysource.LocalUser{Username: "same", Password: "different-password-123", Enabled: true})
	if _, e = b.Options.Identities.Authenticate(ctx, "local/same", "different-password-123"); e == nil {
		t.Fatal("tenant credential leakage")
	}
	secret := a.Options.Identities.Vault.Seal([]byte("test"), "scope")
	if _, e = b.Options.Identities.Vault.Open(secret, "scope"); e == nil {
		t.Fatal("shared tenant encryption key")
	}
	a.Store.Exec(ctx, "INSERT INTO nas(address,name,secret) VALUES('192.0.2.10','NAS','a-secret')")
	selected, _, e := m.Resolve(ctx, "192.0.2.10")
	if e != nil || selected != a.Store {
		t.Fatal("NAS resolution", e)
	}
	b.Store.Exec(ctx, "INSERT INTO nas(address,name,secret) VALUES('192.0.2.10','NAS','b-secret')")
	if _, _, e = m.Resolve(ctx, "192.0.2.10"); e == nil {
		t.Fatal("ambiguous NAS allowed")
	}
	b.Store.Exec(ctx, "DELETE FROM nas")
	var n int
	b.Store.Row(ctx, "SELECT COUNT(*) FROM oui_prefixes").Scan(&n)
	if n != 1 {
		t.Fatal("public registry not copied")
	}
	b.Store.Row(ctx, "SELECT COUNT(*) FROM local_users").Scan(&n)
	if n != 1 {
		t.Fatal(n)
	}
	root.Row(ctx, "SELECT COUNT(*) FROM local_users").Scan(&n)
	if n != 0 {
		t.Fatal("tenant write reached root")
	}
	h := m.Handler(http.NotFoundHandler(), http.NotFoundHandler())
	request := httptest.NewRequest("POST", "https://border.example.test/t/alpha/api/login", strings.NewReader(`{"Username":"admin","Password":"test-password-12345"}`))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request)
	if w.Code != 200 {
		t.Fatal("tenant login", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Path != "/t/alpha/" {
		t.Fatal("cookie scope", cookies)
	}
	request = httptest.NewRequest("GET", "https://border.example.test/t/bravo/api/state", nil)
	request.AddCookie(cookies[0])
	request.TLS = &tls.ConnectionState{}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request)
	if w.Code != 401 {
		t.Fatal("cross tenant cookie", w.Code)
	}

	if e = a.Store.SaveAdminAccount(ctx, "admin", store.AdminChange{Username: "alpha-viewer", Password: "viewer-password-123", Role: "viewer", Enabled: true}); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		path string
		code int
	}{{"/t/alpha/api/sessions", 200}, {"/t/alpha/api/admins", 403}, {"/t/bravo/api/sessions", 401}} {
		request = httptest.NewRequest("GET", "https://border.example.test"+tc.path, nil)
		request.SetBasicAuth("alpha-viewer", "viewer-password-123")
		request.TLS = &tls.ConnectionState{}
		w = httptest.NewRecorder()
		h.ServeHTTP(w, request)
		if w.Code != tc.code {
			t.Fatalf("role tenant boundary %s: %d", tc.path, w.Code)
		}
	}
	m.Close()
	m.Key = bytes.Repeat([]byte{42}, 32)
	if e = m.Init(ctx); e != nil {
		t.Fatal("restart", e)
	}
	defer m.Close()
	if _, e = m.runtimes["alpha"].Options.Identities.Authenticate(ctx, "local/same", "different-password-123"); e != nil {
		t.Fatal("persisted user", e)
	}
}
