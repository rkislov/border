package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSQLiteLifecycle(t *testing.T) {
	s, err := Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	checkStore(t, s)
}
func TestPostgresLifecycle(t *testing.T) {
	dsn := os.Getenv("BORDER_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("set BORDER_TEST_POSTGRES to a dedicated empty test database")
	}
	s, err := Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	checkStore(t, s)
}
func checkStore(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Admin(ctx, "admin", "short", false); err == nil {
		t.Fatal("weak password accepted")
	}
	if err := s.Admin(ctx, "admin", "correct-password-123", false); err != nil {
		t.Fatal(err)
	}
	if !s.CheckAdmin(ctx, "admin", "correct-password-123") || s.CheckAdmin(ctx, "admin", "wrong") {
		t.Fatal("password verification")
	}
	if err := s.Admin(ctx, "missing", "replacement-password", true); err == nil {
		t.Fatal("reset nonexistent admin")
	}
	if err := s.Admin(ctx, "admin", "replacement-password", true); err != nil {
		t.Fatal(err)
	}
	if s.CheckAdmin(ctx, "admin", "correct-password-123") || !s.CheckAdmin(ctx, "admin", "replacement-password") {
		t.Fatal("password reset")
	}
	if err := s.Exec(ctx, "INSERT INTO mac_auth(mac,vlan) VALUES (?,?)", "aa:bb:cc:dd:ee:ff", 123); err == nil {
		t.Fatal("unknown VLAN accepted")
	}
	if err := s.Exec(ctx, "INSERT INTO vlan_catalog VALUES (?,?)", 123, "data"); err != nil {
		t.Fatal(err)
	}
	if err := s.Exec(ctx, "INSERT INTO mac_auth(mac,vlan) VALUES (?,?)", "aa:bb:cc:dd:ee:ff", 123); err != nil {
		t.Fatal(err)
	}
	if err := s.Exec(ctx, "DELETE FROM vlan_catalog WHERE id=?", 123); err == nil {
		t.Fatal("referenced VLAN deleted")
	}
	if err := s.Audit(ctx, "test", "device", "accept", "policy"); err != nil {
		t.Fatal(err)
	}
	events, err := s.Events(ctx)
	if err != nil || len(events) != 1 {
		t.Fatal("audit")
	}
	devices, err := s.DeviceList(ctx)
	if err != nil || len(devices) != 1 || !devices[0].Active {
		t.Fatal("devices")
	}
}
func TestTransferToPostgres(t *testing.T) {
	dsn := os.Getenv("BORDER_TEST_TRANSFER")
	if dsn == "" {
		t.Skip("set BORDER_TEST_TRANSFER to a separate empty PostgreSQL test database")
	}
	ctx := context.Background()
	src, err := Open("sqlite", filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.DB.Close()
	checkStore(t, src)
	for _, q := range []string{
		"INSERT INTO identities(username,email,totp_secret) VALUES ('user','user@example.test','encrypted-test-secret')",
		"INSERT INTO user_codes VALUES ('digest','user','recovery',9999999999)",
		"INSERT INTO certificate_authorities VALUES ('ca','root','certificate','encrypted-test-key',1)",
		"INSERT INTO certificates VALUES ('serial','ca','user','client-certificate',9999999999,0)",
	} {
		if err = src.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	dst, err := Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer dst.DB.Close()
	if err = dst.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = Transfer(ctx, src, dst); err != nil {
		t.Fatal(err)
	}
	if !dst.CheckAdmin(ctx, "admin", "replacement-password") {
		t.Fatal("password not transferred")
	}
	d, err := dst.Device(ctx, "aa:bb:cc:dd:ee:ff")
	if err != nil || d.VLAN != 123 {
		t.Fatal("device not transferred")
	}
	var encrypted string
	if err = dst.Row(ctx, "SELECT private_key FROM certificate_authorities WHERE id='ca'").Scan(&encrypted); err != nil || encrypted != "encrypted-test-key" {
		t.Fatal("encrypted CA not transferred", err)
	}
	if err = Transfer(ctx, src, dst); err == nil {
		t.Fatal("overwrote populated target")
	}
}
