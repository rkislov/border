package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkislov/border/internal/store"
)

type backupTestPlatform struct{}

func (backupTestPlatform) List(context.Context) ([]TenantInfo, error) { return []TenantInfo{}, nil }
func (backupTestPlatform) Create(context.Context, TenantSpec) error   { return nil }

func TestBackupsRequirePlatformAdministrator(t *testing.T) {
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
	if e = s.SaveAdminAccount(ctx, "admin", store.AdminChange{Username: "viewer", Password: "test-password-123", Role: "viewer", Enabled: true}); e != nil {
		t.Fatal(e)
	}
	root := HandlerPlatform(s, nil, nil, false, backupTestPlatform{})
	tenant := HandlerWithOptions(s, nil, nil, false)
	call := func(h http.Handler, method, path, user, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://border.test"+path, strings.NewReader(body))
		if user != "" {
			r.SetBasicAuth(user, "test-password-123")
		}
		r.Header.Set("X-CSRF-Token", token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		h    http.Handler
		user string
		code int
	}{{root, "", 401}, {root, "viewer", 403}, {root, "admin", 200}, {tenant, "admin", 404}} {
		w := call(tc.h, "GET", "/api/backups", tc.user, "", "")
		if w.Code != tc.code {
			t.Fatal(tc.user, w.Code, w.Body.String())
		}
		if w.Code == 200 && (strings.Contains(w.Body.String(), "IdentityFile") || strings.Contains(w.Body.String(), "RootDB")) {
			t.Fatal("privileged config exposed")
		}
	}
	page := call(root, "GET", "/", "admin", "", "").Body.String()
	token := strings.Split(strings.Split(page, `name="csrf-token" content="`)[1], `"`)[0]
	valid := `{"Enabled":true,"Time":"03:30","Timezone":"Europe/Moscow","Keep":14}`
	for _, tc := range []struct {
		user, path, body, token string
		code                    int
	}{{"admin", "/api/backups/schedule", valid, "", 403}, {"viewer", "/api/backups/schedule", valid, token, 403}, {"admin", "/api/backups/schedule", valid, token, 200}, {"admin", "/api/backups/schedule", `{"Time":"03:30","Timezone":"UTC","Keep":1}`, token, 400}, {"admin", "/api/backups/schedule", `{"RootDB":"/etc/passwd"}`, token, 400}, {"admin", "/api/backups/jobs", `{"Kind":"verify","SourceID":"../../etc/passwd","RequestID":"10e89391-5f1c-42c2-aa86-313bb0829fc6"}`, token, 400}, {"admin", "/api/backups/jobs", `{"Kind":"backup","RequestID":"10e89391-5f1c-42c2-aa86-313bb0829fc6"}`, token, 200}} {
		w := call(root, "POST", tc.path, tc.user, tc.body, tc.token)
		if w.Code != tc.code {
			t.Fatal(tc.path, w.Code, w.Body.String())
		}
	}
	var count int
	s.Row(ctx, "SELECT COUNT(*) FROM backup_jobs").Scan(&count)
	if count != 1 {
		t.Fatal("unexpected jobs", count)
	}
	tenantPage := call(tenant, "GET", "/", "admin", "", "").Body.String()
	tenantToken := strings.Split(strings.Split(tenantPage, `name="csrf-token" content="`)[1], `"`)[0]
	if w := call(tenant, "POST", "/api/backups/jobs", "admin", `{"Kind":"backup","RequestID":"b8b1a478-3091-45e8-b9fd-de3ba4fd4baf"}`, tenantToken); w.Code != 404 {
		t.Fatal("tenant could queue platform backup", w.Code)
	}
}
