package store

import (
	"context"
	"github.com/pressly/goose/v3"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
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
	token, e := s.NewAccessGrant(ctx, "192.0.2.1", "user", "", 1)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.RefreshRevocations(ctx); e != nil {
		t.Fatal(e)
	}
	var reason string
	if e = s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason); e != nil || reason == "" {
		t.Fatal(reason, e)
	}
	if e = s.ApplyAccounting(ctx, AccountingEvent{NAS: "192.0.2.1", ID: "session", Kind: "start", At: 1000, Timed: true, Classes: []string{token}}); e != nil {
		t.Fatal(e)
	}
	if e = s.ApplyAccounting(ctx, AccountingEvent{NAS: "192.0.2.1", Kind: "off", At: 2000, Timed: true}); e != nil {
		t.Fatal(e)
	}
	sessions, e := s.Sessions(ctx)
	if e != nil || len(sessions) != 1 || sessions[0].Status != "nas-off" {
		t.Fatal(sessions, e)
	}
	devices, err := s.DeviceList(ctx)
	if err != nil || len(devices) != 1 || !devices[0].Active {
		t.Fatal("devices")
	}
	if e = s.Exec(ctx, "INSERT INTO nas(address,name,secret) VALUES('192.0.2.22','Chain NAS','secret')"); e != nil {
		t.Fatal(e)
	}
	if e = s.SaveAuthentication(ctx, AuthenticationPolicy{ID: "chain-auth", Name: "Chain", Source: "local", Enabled: true, Steps: []string{"device", "primary", "totp"}}); e != nil {
		t.Fatal(e)
	}
	if e = s.SaveAccess(ctx, AccessPolicy{ID: "chain-access", Name: "Chain", AuthenticationID: "chain-auth", Mode: "ssh", SessionSeconds: 300, Enabled: true}); e != nil {
		t.Fatal(e)
	}
	set := NASPolicySet{NAS: "192.0.2.22", Enabled: true, Bindings: []PolicyBinding{{ID: "chain", PolicyID: "chain-access", Protocol: "pap", Priority: 1, Enabled: true}}}
	if e = s.SaveNASPolicies(ctx, set); e != nil {
		t.Fatal(e)
	}
	if e = s.SaveNASPolicies(ctx, set); e == nil {
		t.Fatal("stale version accepted")
	}
	policy, configured, e := s.SelectPolicy(ctx, set.NAS, PolicyRequest{Protocol: "pap"})
	if e != nil || !configured || policy.BindingVersion != 1 || len(policy.Authentication.Chain()) != 3 {
		t.Fatal(policy, e)
	}
	if _, e = s.NewPolicyGrant(ctx, set.NAS, "local/user", policy, 9999999999); e != nil {
		t.Fatal(e)
	}
	if e = s.RefreshRevocations(ctx); e != nil {
		t.Fatal(e)
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
		"INSERT INTO nas(address,name,secret,portal_enabled,dictionary,access_mode) VALUES ('192.0.2.1','test','test-secret-123456789',1,'cisco','ssh')",
		"INSERT INTO nas_grants(nas,username,mode,privilege) VALUES('192.0.2.1','user','ssh',3)",
		"UPDATE guest_policy SET vlan=123,enabled=1",
		"INSERT INTO guest_sessions(nas,mac,masked_phone,vlan,expires_at) VALUES('192.0.2.1','00:11:22:33:44:55','+7*******4567',123,9999999999)",
		"INSERT INTO device_fingerprints(mac,source,first_seen,last_seen) VALUES('00:11:22:33:44:55','admin',1,2)",
		"INSERT INTO fingerprint_history(id,mac,observed_at,source,detail) VALUES('fp','00:11:22:33:44:55',2,'admin','{}')",
		"INSERT INTO oui_prefixes VALUES('001122','test vendor')",
		"INSERT INTO identities(username,email,totp_secret) VALUES ('user','user@example.test','encrypted-test-secret')",
		"INSERT INTO user_codes VALUES ('digest','user','recovery',9999999999)",
		"INSERT INTO certificate_authorities VALUES ('ca','root','certificate','encrypted-test-key',1)",
		"INSERT INTO certificates VALUES ('serial','ca','user','client-certificate',9999999999,0)",
	} {
		if err = src.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if err = src.SaveAuthentication(ctx, AuthenticationPolicy{ID: "groups-auth", Name: "Groups", Source: "local", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err = src.SaveAccess(ctx, AccessPolicy{ID: "groups-access", Name: "Groups", AuthenticationID: "groups-auth", Mode: "ssh", SessionSeconds: 300, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err = src.SaveUserGroup(ctx, UserGroup{ID: "staff", Name: "Staff", Enabled: true, Members: []string{"local/alice"}}); err != nil {
		t.Fatal(err)
	}
	if err = src.SaveRules(ctx, RuleSet{PolicyID: "groups-access", Enabled: true, Rules: []AccessRule{{ID: "staff", Name: "Staff", Effect: "allow", Priority: 10, Enabled: true, Groups: []string{"staff"}}}}); err != nil {
		t.Fatal(err)
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
	chain, configured, e := dst.SelectPolicy(ctx, "192.0.2.22", PolicyRequest{Protocol: "pap"})
	if e != nil || !configured || len(chain.Authentication.Chain()) != 3 {
		t.Fatal("chain transfer", e)
	}
	rules, err := dst.Rules(ctx, "groups-access")
	if err != nil || !rules.Enabled || len(rules.Rules) != 1 {
		t.Fatal("rules transfer", err)
	}
	b := &BoundPolicy{Rules: rules}
	if ok, _, err := dst.EvaluateAccess(ctx, b, AccessContext{Username: "local/alice"}); err != nil || !ok {
		t.Fatal("group membership transfer", err)
	}
	if err = dst.SaveRules(ctx, rules); err != nil {
		t.Fatal("PostgreSQL rule save", err)
	}
	if err = dst.SaveRules(ctx, rules); err == nil {
		t.Fatal("PostgreSQL version conflict not detected")
	}
	if g, err := dst.NASGrant(ctx, "192.0.2.1", "user", "ssh"); err != nil || g.Privilege != 3 {
		t.Fatalf("grant transfer: %+v %v", g, err)
	}
	if f, err := dst.Fingerprints(ctx); err != nil || len(f) != 1 || f[0].OUIManufacturer != "test vendor" {
		t.Fatalf("fingerprint transfer: %+v %v", f, err)
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

func TestEAPPolicyReferences(t *testing.T) {
	s, err := Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	ctx := t.Context()
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	enabled, vlan, err := s.EAPPolicy(ctx)
	if err != nil || enabled || vlan != 0 {
		t.Fatal("EAP must default to disabled")
	}
	if err = s.SetEAPPolicy(ctx, true, 100); err == nil {
		t.Fatal("unknown VLAN accepted")
	}
	if err = s.Exec(ctx, "INSERT INTO vlan_catalog VALUES (?,?)", 100, "enterprise"); err != nil {
		t.Fatal(err)
	}
	if err = s.SetEAPPolicy(ctx, true, 100); err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteVLAN(ctx, 100); err == nil {
		t.Fatal("EAP VLAN deleted")
	}
	enabled, vlan, err = s.EAPPolicy(ctx)
	if err != nil || !enabled || vlan != 100 {
		t.Fatal("EAP policy not saved")
	}
	if err = s.SetEAPPolicy(ctx, false, 0); err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteVLAN(ctx, 100); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeFromFirstRelease(t *testing.T) {
	s, err := Open("sqlite", filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	old := fstest.MapFS{}
	for _, name := range []string{"00001_initial.sql", "00002_selfservice.sql"} {
		b, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		old[name] = &fstest.MapFile{Data: b}
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, s.DB, old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = s.Exec(t.Context(), "INSERT INTO nas(address,name,secret) VALUES ('127.0.0.1','old NAS','test-only-secret-123')"); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	nas, err := s.NASList(t.Context())
	if err != nil || len(nas) != 1 || nas[0].CoAPort != 3799 {
		t.Fatal("NAS upgrade failed", err)
	}
	enabled, vlan, err := s.EAPPolicy(t.Context())
	if err != nil || enabled || vlan != 0 {
		t.Fatal("EAP must remain disabled after upgrade", err)
	}
}
