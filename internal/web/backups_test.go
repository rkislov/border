package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/rkislov/border/internal/backup"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkislov/border/internal/store"
)

type backupTestPlatform struct{ downloads string }

func (p backupTestPlatform) BackupDownloadDirectory() string { return p.downloads }

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

func TestBackupFileDownloadsAuthorizationIntegrityAndRange(t *testing.T) {
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
	dir := t.TempDir()
	root := HandlerPlatform(s, nil, nil, false, backupTestPlatform{downloads: dir})
	tenant := HandlerWithOptions(s, nil, nil, false)
	call := func(h http.Handler, method, path, user, body, token, byteRange string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://border.test"+path, strings.NewReader(body))
		if user != "" {
			r.SetBasicAuth(user, "test-password-123")
		}
		r.Header.Set("X-CSRF-Token", token)
		r.Header.Set("Range", byteRange)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	page := call(root, "GET", "/", "admin", "", "", "").Body.String()
	token := strings.Split(strings.Split(page, `name="csrf-token" content="`)[1], `"`)[0]
	archiveID := uuid.NewString()
	if e = s.Exec(ctx, "INSERT INTO backup_jobs(id,kind,state,request_key,actor,created_at,verification_state) VALUES(?,'backup','succeeded',?,'test',1,'ok')", archiveID, archiveID); e != nil {
		t.Fatal(e)
	}
	if e = s.Exec(ctx, "UPDATE backup_control SET download_target=? WHERE id=1", backup.DownloadTarget(dir)); e != nil {
		t.Fatal(e)
	}
	body := `{"BackupID":"` + archiveID + `"}`
	if w := call(root, "POST", "/api/backups/downloads", "admin", body, "", ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	w := call(root, "POST", "/api/backups/downloads", "admin", body, token, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var v struct{ ID string }
	if e = json.Unmarshal(w.Body.Bytes(), &v); e != nil {
		t.Fatal(e)
	}
	// The worker's archive verification/copy is covered by backup package tests.
	// Here an opaque encrypted-file fixture exercises the HTTP boundary.
	content := []byte("age-encryption.org/v1\nopaque-test-archive")
	hash := sha256.Sum256(content)
	digest := hex.EncodeToString(hash[:])
	name := "backup-" + archiveID + ".tar.gz.age"
	if e = os.Mkdir(filepath.Join(dir, v.ID), 0750); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, v.ID, name), content, 0640); e != nil {
		t.Fatal(e)
	}
	if e = s.Exec(ctx, "UPDATE backup_file_jobs SET state='succeeded',sha256=?,bytes=?,verified_at=?,expires_at=? WHERE id=?", digest, len(content), time.Now().Unix(), time.Now().Unix()+3600, v.ID); e != nil {
		t.Fatal(e)
	}
	url := "/api/backups/downloads/" + v.ID
	for _, tc := range []struct {
		h    http.Handler
		user string
		code int
	}{{root, "", 401}, {root, "viewer", 403}, {tenant, "admin", 404}, {root, "admin", 200}} {
		w = call(tc.h, "GET", url, tc.user, "", "", "")
		if w.Code != tc.code {
			t.Fatal(tc.user, w.Code, w.Body.String())
		}
		if w.Code == 200 && (w.Body.String() != string(content) || w.Header().Get("X-Archive-SHA256") != digest || w.Header().Get("Cache-Control") != "private, no-store") {
			t.Fatal("incorrect download", w.Header())
		}
	}
	w = call(root, "GET", url, "admin", "", "", "bytes=4-12")
	if w.Code != 206 || w.Body.String() != string(content[4:13]) {
		t.Fatal("range", w.Code, w.Body.String())
	}
	w = call(root, "GET", url+"?checksum=1", "admin", "", "", "")
	if w.Code != 200 || w.Body.String() != digest+"  "+name+"\n" {
		t.Fatal("checksum", w.Code, w.Body.String())
	}
	w = call(root, "POST", "/api/backups/file-export", "admin", `{"Enabled":true}`, token, "")
	if w.Code != 400 {
		t.Fatal("enabled unconfigured destination", w.Code)
	}
	if e = os.WriteFile(filepath.Join(dir, v.ID, name), []byte("broken"), 0640); e != nil {
		t.Fatal(e)
	}
	if w = call(root, "GET", url, "admin", "", "", ""); w.Code != 409 {
		t.Fatal("corruption served", w.Code)
	}
	if e = s.Exec(ctx, "UPDATE backup_file_jobs SET expires_at=1 WHERE id=?", v.ID); e != nil {
		t.Fatal(e)
	}
	if w = call(root, "GET", url, "admin", "", "", ""); w.Code != 404 {
		t.Fatal("expired download", w.Code)
	}
}
