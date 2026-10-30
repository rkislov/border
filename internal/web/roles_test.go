package web

import (
	"bytes"
	"encoding/json"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRolesScopeAndLiveSessionInvalidation(t *testing.T) {
	s, err := store.Open("sqlite", filepath.Join(t.TempDir(), "roles.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	ctx := t.Context()
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.Admin(ctx, "admin", "test-password-123", false); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"INSERT INTO locations VALUES('east','East'),('west','West')", "INSERT INTO nas(address,name,secret,location_id) VALUES('192.0.2.1','East','secret','east'),('192.0.2.2','West','secret','west')", "INSERT INTO sessions(nas,session_id,mac,username,status,updated_at,generation) VALUES('192.0.2.1','east-session','','east-user','active',1,'east-generation'),('192.0.2.2','west-session','','west-user','active',1,'west-generation')"} {
		if err = s.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []store.AdminChange{{Username: "op", Password: "test-password-123", Role: "operator", LocationID: "east", Enabled: true}, {Username: "view", Password: "test-password-123", Role: "viewer", Enabled: true}} {
		if err = s.SaveAdminAccount(ctx, "admin", c); err != nil {
			t.Fatal(err)
		}
	}
	h := HandlerWithOptions(s, nil, nil, false)
	send := func(method, path, user string, body []byte, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://border.test"+path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		if user != "" {
			r.SetBasicAuth(user, "test-password-123")
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		user, path string
		code       int
	}{{"op", "/api/sessions?LocationID=west", 200}, {"op", "/api/events", 403}, {"op", "/api/state", 403}, {"op", "/api/notifications?scope=default", 403}, {"op", "/api/admins", 403}, {"op", "/api/metrics", 403}, {"op", "/metrics", 403}, {"op", "/api/tenants", 403}, {"view", "/api/sessions", 200}, {"view", "/api/events", 200}, {"view", "/api/portal-design?scope=tenant", 403}, {"view", "/api/access-model", 403}, {"view", "/api/admins", 403}} {
		w := send("GET", tc.path, tc.user, nil, nil, "")
		if w.Code != tc.code {
			t.Fatalf("%s %s: %d", tc.user, tc.path, w.Code)
		}
		if tc.user == "op" && strings.Contains(w.Body.String(), "west-") {
			t.Fatal("location data leaked")
		}
	}
	for _, user := range []string{"op", "view"} {
		w := send("GET", "/", user, nil, nil, "")
		if !strings.Contains(w.Body.String(), "operations.js") {
			t.Fatal("wrong shell")
		}
		csrf := strings.Split(strings.Split(w.Body.String(), `name="csrf-token" content="`)[1], `"`)[0]
		for _, path := range []string{"/api/settings", "/api/admins", "/api/delete", "/api/portal-design", "/api/tenants"} {
			if w = send("POST", path, user, []byte(`{}`), nil, csrf); w.Code != 403 {
				t.Fatal("write allowed", user, path, w.Code)
			}
		}
		for _, body := range []string{`{"NAS":"192.0.2.2","ID":"west-session","Action":"disconnect","Generation":"west-generation"}`, `{"NAS":"192.0.2.1","ID":"east-session","Action":"vlan","Generation":"east-generation","VLAN":10}`} {
			if w = send("POST", "/api/sessions/action", user, []byte(body), nil, csrf); w.Code != 403 {
				t.Fatal("unauthorized action", w.Code, w.Body.String())
			}
		}
	}

	// An operator can disconnect its own location through the same protected API.
	conn, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	// The fixture NAS is a documentation address, so use a real local NAS for this request.
	if e = s.Exec(ctx, "INSERT INTO nas(address,name,secret,location_id,coa_port) VALUES('127.0.0.1','Local','long-test-secret','east',?)", conn.LocalAddr().(*net.UDPAddr).Port); e != nil {
		t.Fatal(e)
	}
	if e = s.Exec(ctx, "INSERT INTO sessions(nas,session_id,mac,username,status,updated_at,generation) VALUES('127.0.0.1','own-session','','own-user','active',1,'own-generation')"); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var raw [4096]byte
		n, remote, e := conn.ReadFrom(raw[:])
		if e != nil {
			done <- e
			return
		}
		packet, e := radius.Parse(raw[:n], []byte("long-test-secret"))
		if e != nil {
			done <- e
			return
		}
		wire, e := packet.Response(radius.CodeDisconnectACK).Encode()
		if e == nil {
			_, e = conn.WriteTo(wire, remote)
		}
		done <- e
	}()
	shell := send("GET", "/", "op", nil, nil, "")
	csrf := strings.Split(strings.Split(shell.Body.String(), `name="csrf-token" content="`)[1], `"`)[0]
	own := send("POST", "/api/sessions/action", "op", []byte(`{"NAS":"127.0.0.1","ID":"own-session","Action":"disconnect","Generation":"own-generation","Username":"own-user","Updated":1}`), nil, csrf)
	if own.Code != 200 {
		t.Fatal("own session action failed", own.Code, own.Body.String())
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	login := send("POST", "/api/login", "", []byte(`{"Username":"op","Password":"test-password-123"}`), nil, "")
	if login.Code != 200 {
		t.Fatal(login.Body.String())
	}
	cookie := login.Result().Cookies()[0]
	if w := send("GET", "/api/me", "", nil, cookie, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if err = s.SaveAdminAccount(ctx, "admin", store.AdminChange{Username: "op", Role: "operator", LocationID: "west", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if w := send("GET", "/api/sessions", "", nil, cookie, ""); w.Code != 401 {
		t.Fatal("stale cookie accepted", w.Code)
	}
	w := send("GET", "/api/sessions", "op", nil, nil, "")
	var page store.ListPage[store.Session]
	if err = json.Unmarshal(w.Body.Bytes(), &page); err != nil || page.Total != 1 || page.Items[0].NAS != "192.0.2.2" {
		t.Fatal("scope not refreshed", w.Body.String())
	}
	if err = s.SaveAdminAccount(ctx, "admin", store.AdminChange{Username: "op", Role: "operator", LocationID: "west", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if w = send("GET", "/api/sessions", "op", nil, nil, ""); w.Code != 401 {
		t.Fatal("disabled basic auth accepted")
	}
	if err = s.SaveAdminAccount(ctx, "admin", store.AdminChange{Username: "admin", Role: "viewer", Enabled: true}); err == nil {
		t.Fatal("last admin removed")
	}
}
