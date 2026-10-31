// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"github.com/rkislov/border/internal/store"
	"path/filepath"
	"testing"
)

func TestResetAdminMFACommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.db")
	s, e := store.Open("sqlite", path)
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
	if e = s.Exec(ctx, "UPDATE admins SET mfa_secret='fixture',mfa_pending='pending',mfa_failures=5,mfa_blocked_until=9999999999 WHERE username='admin'"); e != nil {
		t.Fatal(e)
	}
	if s.CheckAdmin(ctx, "admin", "test-password-123") {
		t.Fatal("password-only check bypassed MFA")
	}
	c := command()
	c.SetArgs([]string{"--db", path, "--db-driver", "sqlite", "reset-admin-mfa", "admin"})
	if e = c.ExecuteContext(ctx); e != nil {
		t.Fatal(e)
	}
	p, e := s.AdminAccount(ctx, "admin")
	if e != nil || p.MFAEnabled || p.Revision != 1 || !s.CheckAdmin(ctx, "admin", "test-password-123") {
		t.Fatal("incorrect reset", p, e)
	}
	var n int
	if e = s.Row(ctx, "SELECT COUNT(*) FROM auth_log WHERE source='admin_security' AND identity='admin' AND reason='mfa_reset_cli'").Scan(&n); e != nil || n != 1 {
		t.Fatal("missing recovery audit", n, e)
	}
}
