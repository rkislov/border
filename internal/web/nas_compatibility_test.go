// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"encoding/json"
	"github.com/rkislov/border/internal/store"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestNASCompatibility(t *testing.T) {
	s, e := store.Open("sqlite", filepath.Join(t.TempDir(), "nas.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	ctx := t.Context()
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if e = s.Admin(ctx, "admin", "strong-password-123", false); e != nil {
		t.Fatal(e)
	}
	if e = s.Exec(ctx, "INSERT INTO nas(address,name,secret,dictionary,access_mode) VALUES('192.0.2.1','test','private-secret','strongswan','vpn')"); e != nil {
		t.Fatal(e)
	}
	if e = s.Exec(ctx, "INSERT INTO sessions(nas,session_id,mac,username,status,updated_at,last_seen,revoke_cause) VALUES('192.0.2.1','one','','private-user','active',1,1,406)"); e != nil {
		t.Fatal(e)
	}
	h := HandlerWithOptions(s, nil, nil, false)
	for _, tc := range []struct {
		url  string
		auth bool
		code int
	}{{"/api/nas/compatibility?nas=192.0.2.1", false, 401}, {"/api/nas/compatibility?nas=bad", true, 400}, {"/api/nas/compatibility?nas=192.0.2.2", true, 404}, {"/api/nas/compatibility?nas=192.0.2.1", true, 200}, {"/api/dictionaries", true, 200}} {
		r := httptest.NewRequest("GET", "https://localhost"+tc.url, nil)
		if tc.auth {
			r.SetBasicAuth("admin", "strong-password-123")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatalf("%s: %d %s", tc.url, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "private-secret") || strings.Contains(w.Body.String(), "private-user") {
			t.Fatal("secret or identity leaked")
		}
		if tc.code == 200 && strings.Contains(tc.url, "compatibility") {
			var d struct {
				UnlinkedSessions, UnsupportedDisconnects int
				Findings                                 []compatibilityFinding
			}
			if e = json.Unmarshal(w.Body.Bytes(), &d); e != nil {
				t.Fatal(e)
			}
			if d.UnlinkedSessions != 1 || d.UnsupportedDisconnects != 1 {
				t.Fatal(d)
			}
			codes := map[string]bool{}
			for _, f := range d.Findings {
				codes[f.Code] = true
			}
			for _, code := range []string{"unlinked_sessions", "unsupported_disconnect", "no_policy", "passive_check"} {
				if !codes[code] {
					t.Fatal("missing", code)
				}
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("diagnostics cached")
			}
		}
	}
	// A saved policy incompatible with the vendor must be diagnosed, not accepted silently.
	for _, q := range []string{
		"INSERT INTO authentication_policies(id,name,source) VALUES('auth','auth','local')",
		"INSERT INTO access_policies(id,name,authentication_id,mode,session_seconds,enabled) VALUES('ssh','ssh','auth','ssh',600,0)",
		"UPDATE nas SET access_policy_id='ssh' WHERE address='192.0.2.1'",
	} {
		if e = s.Exec(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	r := httptest.NewRequest("GET", "https://localhost/api/nas/compatibility?nas=192.0.2.1", nil)
	r.SetBasicAuth("admin", "strong-password-123")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, code := range []string{"policy_mode", "mode_mismatch", "inactive_policy"} {
		if !strings.Contains(w.Body.String(), code) {
			t.Fatal("missing policy diagnostic", code, w.Body.String())
		}
	}

}
