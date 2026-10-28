package web

import (
	"github.com/rkislov/border/internal/guest"
	"github.com/rkislov/border/internal/store"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccessFormsAndScopedNotificationAPI(t *testing.T) {
	s, e := store.Open("sqlite", filepath.Join(t.TempDir(), "web.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	if e = s.Migrate(t.Context()); e != nil {
		t.Fatal(e)
	}
	s.Admin(t.Context(), "admin", "strong-password-123", false)
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
	csrf := strings.Split(strings.Split(page.Body.String(), `name="csrf-token" content="`)[1], `"`)[0]
	for _, v := range []struct{ path, body string }{
		{"domains", `{"ID":"corp","Name":"AD","Enabled":true,"Endpoints":["ldaps://corp.example.test"],"BaseDN":"dc=corp","BindDN":"cn=reader","BindPassword":"secret-ldap-password","UserAttribute":"uid"}`},
		{"local-users", `{"Username":"alice","Password":"local-password-123","Email":"alice@example.test","Enabled":true}`},
		{"locations", `{"ID":"office","Name":"Office"}`}, {"network_segments", `{"ID":"staff","Name":"Staff"}`},
		{"authentication-policies", `{"ID":"mfa","Name":"MFA","Source":"directory","DomainID":"corp","RequireTOTP":true,"Enabled":true}`},
		{"access-policies", `{"ID":"staff","Name":"Staff","AuthenticationID":"mfa","Mode":"network","SegmentID":"staff","SessionSeconds":3600,"Enabled":true,"Subjects":["corp/alice"]}`},
		{"segment-mappings", `{"LocationID":"office","SegmentID":"staff","VLAN":200}`},
		{"nas", `{"Address":"192.0.2.1","Name":"NAS","Secret":"nas-secret-123456789","LocationID":"office","AccessPolicyID":"staff"}`},
		{"user-groups", `{"ID":"staff","Name":"Staff","Enabled":true,"Members":["corp/alice"]}`},
		{"access-rules", `{"PolicyID":"staff","Version":0,"Enabled":true,"Rules":[{"ID":"staff","Name":"Staff","Enabled":true,"Effect":"allow","Priority":10,"Groups":["staff"]}]}`},
		{"notifications", `{"Scope":"corp","SMTP":{"Mode":"custom","Address":"smtp.example.test:465","From":"border@example.test","Username":"sender","Password":"secret-smtp-password"},"SMS":{"Mode":"disabled"},"Push":{"Mode":"custom","Contact":"admin@example.test"}}`},
	} {
		if w := send("POST", "/api/"+v.path, v.body, ""); w.Code != 403 {
			t.Fatal("CSRF", v.path, w.Code)
		}
		if w := send("POST", "/api/"+v.path, v.body, csrf); w.Code != 200 {
			t.Fatal(v.path, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/api/access-model", "/api/notifications?scope=corp"} {
		w := send("GET", path, "", "")
		if w.Code != 200 || strings.Contains(w.Body.String(), "secret-") || strings.Contains(w.Body.String(), "local-password") {
			t.Fatal("secret leakage", path, w.Code)
		}
	}
	b, e := s.BoundPolicy(t.Context(), "192.0.2.1")
	if e != nil || b.VLAN != 200 || b.Authentication.DomainID != "corp" {
		t.Fatal("binding", e)
	}
}
