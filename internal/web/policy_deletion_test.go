package web

import (
	"encoding/json"
	"github.com/rkislov/border/internal/store"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeletionAPIStagesPublishesAndRestores(t *testing.T) {
	s, e := store.Open("sqlite", filepath.Join(t.TempDir(), "delete.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	ctx := t.Context()
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	s.Admin(ctx, "admin", "test-password-123", false)
	s.SaveUserGroup(ctx, store.UserGroup{ID: "staff", Name: "Staff", Enabled: true, Members: []string{"local/alice"}})
	h := HandlerWithOptions(s, nil, nil, false)
	send := func(method, path, body, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://localhost"+path, strings.NewReader(body))
		r.SetBasicAuth("admin", "test-password-123")
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	page := send("GET", "/", "", "")
	csrf := strings.Split(strings.Split(page.Body.String(), `name="csrf-token" content="`)[1], `"`)[0]
	body := `{"Kind":"group","PolicyID":"staff","Operation":"delete"}`
	if w := send("POST", "/api/policy-drafts", body, ""); w.Code != 403 {
		t.Fatal("deletion CSRF", w.Code)
	}
	if w := send("POST", "/api/policy-drafts", body, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	groups, _ := s.UserGroups(ctx)
	if len(groups) != 1 {
		t.Fatal("staging deleted group")
	}
	ds, _ := s.PolicyDrafts(ctx)
	if ds[0].Operation != "delete" || string(ds[0].Payload) != "null" {
		t.Fatal(ds)
	}
	batch := `{"Drafts":[{"Kind":"group","PolicyID":"staff","Revision":1}]}`
	if w := send("POST", "/api/policy-drafts/batch/publish", batch, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	groups, _ = s.UserGroups(ctx)
	if len(groups) != 0 {
		t.Fatal("publication did not delete")
	}
	history, _ := s.PolicyReleases(ctx)
	rollback, _ := json.Marshal(map[string]string{"BatchID": history[0].BatchID})
	if w := send("POST", "/api/policy-drafts/batch/rollback", string(rollback), csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	groups, _ = s.UserGroups(ctx)
	if len(groups) != 0 {
		t.Fatal("rollback staged changed live")
	}
	batch = `{"Drafts":[{"Kind":"group","PolicyID":"staff","Revision":2}]}`
	if w := send("POST", "/api/policy-drafts/batch/publish", batch, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	groups, _ = s.UserGroups(ctx)
	if len(groups) != 1 || groups[0].Members[0] != "local/alice" {
		t.Fatal("group not restored")
	}
}
