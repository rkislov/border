// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkislov/border/internal/guest"
	"github.com/rkislov/border/internal/netcraze"
	"github.com/rkislov/border/internal/store"
)

func TestNetcrazeSettingsSecretsRolesAndCSRF(t *testing.T) {
	s, e := store.Open("sqlite", filepath.Join(t.TempDir(), "web.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(s.Migrate(t.Context()))
	must(s.Admin(t.Context(), "admin", "test-password-123", false))
	must(s.Exec(t.Context(), "INSERT INTO locations VALUES('lab','Lab')"))
	for _, role := range []string{"viewer", "operator"} {
		location := ""
		if role == "operator" {
			location = "lab"
		}
		must(s.SaveAdminAccount(t.Context(), "admin", store.AdminChange{Username: role, Password: "test-password-123", Role: role, LocationID: location, Enabled: true}))
	}
	must(s.Exec(t.Context(), "INSERT INTO nas(address,name,secret,dictionary,access_mode,portal_enabled) VALUES('192.0.2.1','Netcraze','test-radius-secret','keenetic','network',1)"))
	must(s.Exec(t.Context(), "INSERT INTO network_segments VALUES('guest','Guest')"))
	g, e := guest.New(s, make([]byte, 32))
	must(e)
	defer g.Close()
	g.PublicURL = "https://border.example/portal/tenant-a"
	h := HandlerWithOptions(s, nil, nil, false, g)
	send := func(method, path, body, user, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://border.example"+path, strings.NewReader(body))
		r.SetBasicAuth(user, "test-password-123")
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	page := send("GET", "/", "", "admin", "")
	parts := strings.Split(page.Body.String(), `name="csrf-token" content="`)
	if len(parts) != 2 {
		t.Fatal("CSRF missing")
	}
	csrf := strings.Split(parts[1], `"`)[0]
	if !strings.Contains(page.Body.String(), `id="netcraze-form"`) {
		t.Fatal("adapter form absent")
	}
	body := `{"NAS":"192.0.2.1","Enabled":true,"Address":"https://192.0.2.1","Username":"border","Password":"private-management-secret","CertificateSHA256":"` + strings.Repeat("a", 64) + `","Chilli":"Chilli0","Bridge":"Bridge2","Subnet":"192.0.2.0/24","SegmentID":"guest","VLAN":231,"NASIdentifier":"guest-test","RadiusServer":"198.51.100.1","AuthPort":1812,"AccountingPort":1813,"UAMSecret":"private-uam-secret"}`
	for _, path := range []string{"/api/netcraze", "/api/netcraze/check"} {
		if w := send("POST", path, body, "admin", ""); w.Code != 403 {
			t.Fatal("CSRF bypass", w.Code)
		}
	}
	if w := send("POST", "/api/netcraze", body, "admin", csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w := send("GET", "/api/netcraze?nas=192.0.2.1", "", "admin", "")
	var result struct {
		netcraze.Config
		HasPassword, HasUAMSecret bool
		UAMURL                    string
	}
	must(json.Unmarshal(w.Body.Bytes(), &result))
	if w.Code != 200 || result.Password != "" || result.UAMSecret != "" || !result.HasPassword || !result.HasUAMSecret || strings.Contains(w.Body.String(), "private-") {
		t.Fatal("secret disclosure")
	}
	if result.UAMURL != "https://border.example/portal/tenant-a/uam/netcraze/192.0.2.1" {
		t.Fatal("tenant URL", result.UAMURL)
	}
	for _, role := range []string{"viewer", "operator"} {
		if w := send("GET", "/api/netcraze?nas=192.0.2.1", "", role, ""); w.Code != 403 {
			t.Fatal("read role bypass", role, w.Code)
		}
		shell := send("GET", "/", "", role, "")
		token := strings.Split(strings.Split(shell.Body.String(), `name="csrf-token" content="`)[1], `"`)[0]
		for _, path := range []string{"/api/netcraze", "/api/netcraze/check"} {
			if w := send("POST", path, body, role, token); w.Code != 403 {
				t.Fatal("write role bypass", role, path, w.Code)
			}
		}
	}
	// Unknown NAS probes fail before initiating a management connection.
	if w := send("POST", "/api/netcraze/check", `{"NAS":"192.0.2.99"}`, "admin", csrf); w.Code != 400 {
		t.Fatal(w.Code)
	}
}
