// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestSessionAuthorizationListing(t *testing.T) {
	s, err := Open("sqlite", filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	ctx := t.Context()
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	must := func(q string, args ...any) {
		t.Helper()
		if e := s.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	must("INSERT INTO access_grants(token,nas,username,policy_id,expires_at) VALUES(?,?,?,?,?)", "secret-token", "nas-a", "local/user", "vpn-policy", 9999999999)
	// A token from another NAS and an orphan must not imply managed access.
	for _, v := range []struct{ nas, id, token string }{{"nas-a", "linked", "secret-token"}, {"nas-b", "foreign", "secret-token"}, {"nas-a", "orphan", "missing"}, {"nas-a", "lost-start", ""}} {
		must("INSERT INTO sessions(nas,session_id,mac,username,status,updated_at,grant_token) VALUES(?,?,?,?,?,?,?)", v.nas, v.id, "", "local/user", "active", 1, v.token)
	}
	for _, tc := range []struct {
		filter string
		total  int64
	}{{"", 4}, {"linked", 1}, {"unlinked", 3}} {
		page, e := s.SessionsPage(ctx, ListFilter{Authorization: tc.filter, Status: "active", Page: 1, Limit: 2})
		if e != nil || page.Total != tc.total {
			t.Fatalf("%s: %+v %v", tc.filter, page, e)
		}
		for _, row := range page.Items {
			want := row.ID == "linked"
			if row.AuthorizationLinked != want || (row.AccessPolicyID != "") != want {
				t.Fatalf("incorrect linkage: %+v", row)
			}
		}
		raw, e := json.Marshal(page)
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(raw), "secret-token") || strings.Contains(string(raw), "GrantToken") {
			t.Fatal("grant token exposed")
		}
	}
	if _, e := s.SessionsPage(ctx, ListFilter{Authorization: "invalid", Page: 1, Limit: 50}); e == nil {
		t.Fatal("invalid filter accepted")
	}
}
