package web

import (
	"encoding/json"
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
		{"domains", `{"ID":"corp","Name":"AD","Enabled":true,"RevokeMissingUsers":true,"Endpoints":["ldaps://corp.example.test"],"BaseDN":"dc=corp","BindDN":"cn=reader","BindPassword":"secret-ldap-password","UserAttribute":"uid"}`},
		{"local-users", `{"Username":"alice","Password":"local-password-123","Email":"alice@example.test","Enabled":true}`},
		{"locations", `{"ID":"office","Name":"Office"}`}, {"network_segments", `{"ID":"staff","Name":"Staff"}`},
		{"authentication-policies", `{"ID":"mfa","Name":"MFA","Source":"directory","DomainID":"corp","RequireTOTP":true,"Steps":["device","primary","totp"],"Enabled":true}`},
		{"access-policies", `{"ID":"staff","Name":"Staff","AuthenticationID":"mfa","Mode":"network","SegmentID":"staff","SessionSeconds":3600,"Enabled":true,"Subjects":["corp/alice"]}`},
		{"segment-mappings", `{"LocationID":"office","SegmentID":"staff","VLAN":200}`},
		{"nas", `{"Address":"192.0.2.1","Name":"NAS","Secret":"nas-secret-123456789","LocationID":"office","AccessPolicyID":"staff"}`},
		{"nas-policies", `{"NAS":"192.0.2.1","Version":0,"Enabled":true,"Bindings":[{"ID":"corp","PolicyID":"staff","Priority":100,"Protocol":"pap","IdentitySource":"corp","Enabled":true}]}`},
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
	for _, path := range []string{"/api/access-model", "/api/notifications?scope=corp", "/api/nas-policies?nas=192.0.2.1"} {
		w := send("GET", path, "", "")
		if w.Code != 200 || strings.Contains(w.Body.String(), "secret-") || strings.Contains(w.Body.String(), "local-password") {
			t.Fatal("secret leakage", path, w.Code)
		}
	}
	if w := send("GET", "/api/access-model", "", ""); !strings.Contains(w.Body.String(), `"RevokeMissingUsers":true`) {
		t.Fatal("missing user setting not persisted")
	}
	// Interval edits validate the pair and preserve omitted fields for old clients.
	for _, body := range []string{
		`{"Address":"192.0.2.1","Name":"NAS","InterimSeconds":59,"StaleSeconds":900}`,
		`{"Address":"192.0.2.1","Name":"NAS","InterimSeconds":600,"StaleSeconds":900}`,
		`{"Address":"192.0.2.1","Name":"NAS","InterimSeconds":86401,"StaleSeconds":604800}`,
	} {
		if w := send("POST", "/api/nas", body, csrf); w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	for _, body := range []string{
		`{"Address":"192.0.2.1","Name":"NAS","LocationID":"office","AccessPolicyID":"staff","InterimSeconds":600,"StaleSeconds":1800}`,
		`{"Address":"192.0.2.1","Name":"NAS","LocationID":"office","AccessPolicyID":"staff"}`,
	} {
		if w := send("POST", "/api/nas", body, csrf); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	nas, err := s.NASList(t.Context())
	if err != nil || len(nas) != 1 || nas[0].InterimSeconds != 600 || nas[0].StaleSeconds != 1800 {
		t.Fatal(nas, err)
	}
	for _, path := range []string{"/api/retention", "/api/retention/preview"} {
		if w := send("POST", path, `{"AuditDays":7}`, ""); w.Code != 403 {
			t.Fatal("retention CSRF", w.Code)
		}
		if w := send("POST", path, `{"AuditDays":1}`, csrf); w.Code != 400 {
			t.Fatal("retention validation", w.Code)
		}
	}
	if w := send("POST", "/api/retention/preview", `{"AuditDays":7,"SessionDays":7}`, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	retention, err := s.Retention(t.Context())
	if err != nil || retention.AuditDays != 0 || retention.SessionDays != 0 {
		t.Fatal("preview changed settings", retention, err)
	}
	if w := send("POST", "/api/retention", `{"AuditDays":7,"SessionDays":30,"LastRun":9999999999}`, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	retention, err = s.Retention(t.Context())
	if err != nil || retention.AuditDays != 7 || retention.SessionDays != 30 || retention.LastRun != 0 {
		t.Fatal(retention, err)
	}
	// Diagnostics are authenticated, CSRF protected, and do not issue access.
	body := `{"NAS":"192.0.2.1","Protocol":"pap","Username":"corp/alice"}`
	if w := send("POST", "/api/policy-diagnostic", body, ""); w.Code != 403 {
		t.Fatal("diagnostic CSRF", w.Code)
	}
	w := send("POST", "/api/policy-diagnostic", body, csrf)
	var diagnostic struct {
		Status   string
		PolicyID string
		VLAN     int
		Steps    []string
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &diagnostic) != nil || diagnostic.Status != "selected" || diagnostic.PolicyID != "staff" || diagnostic.VLAN != 200 || len(diagnostic.Steps) != 3 {
		t.Fatal("diagnostic", w.Code, w.Body.String())
	}
	for _, tc := range []struct {
		body string
		code int
	}{
		{`{"NAS":"192.0.2.99","Protocol":"pap"}`, 404},
		{`{"NAS":"192.0.2.1","Protocol":"invalid"}`, 400},
		{`{"NAS":"192.0.2.1","Protocol":"pap","NASPortType":-1}`, 400},
	} {
		if w := send("POST", "/api/policy-diagnostic", tc.body, csrf); w.Code != tc.code {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if err := s.Exec(t.Context(), "UPDATE access_policies SET valid_until=1 WHERE id='staff'"); err != nil {
		t.Fatal(err)
	}
	w = send("POST", "/api/policy-diagnostic", body, csrf)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"Status":"inactive"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	var grants int
	if err := s.Row(t.Context(), "SELECT COUNT(*) FROM access_grants").Scan(&grants); err != nil || grants != 0 {
		t.Fatal("diagnostic created grant", grants, err)
	}
	b, e := s.BoundPolicy(t.Context(), "192.0.2.1")
	if e != nil || b.VLAN != 200 || b.Authentication.DomainID != "corp" {
		t.Fatal("binding", e)
	}
}
