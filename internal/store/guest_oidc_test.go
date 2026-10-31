package store

import (
	"github.com/pressly/goose/v3"
	"path/filepath"
	"testing"
)

func TestOIDCMigrationPreservesExistingPolicyReferences(t *testing.T) {
	s, e := Open("sqlite", filepath.Join(t.TempDir(), "upgrade.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	provider, e := goose.NewProvider(goose.DialectSQLite3, s.DB, migrationFS())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = provider.UpTo(t.Context(), 35); e != nil {
		t.Fatal(e)
	}
	for _, q := range []string{
		"INSERT INTO network_segments VALUES('segment','Segment')",
		"INSERT INTO authentication_policies(id,name,source,steps,eap_method) VALUES('auth','Existing AD password','directory','[\"primary\"]','peap')",
		"INSERT INTO access_policies(id,name,authentication_id,mode,segment_id,session_seconds) VALUES('access','Existing access','auth','network','segment',600)",
		"INSERT INTO policy_subjects VALUES('access','corp/alice')",
		"INSERT INTO nas(address,name,secret,access_policy_id) VALUES('192.0.2.1','Existing NAS','test-secret-123456','access')",
		"INSERT INTO nas_segments VALUES('192.0.2.1','segment',100)",
	} {
		if e = s.Exec(t.Context(), q); e != nil {
			t.Fatal(e)
		}
	}
	if e = s.Migrate(t.Context()); e != nil {
		t.Fatal(e)
	}
	b, e := s.BoundPolicy(t.Context(), "192.0.2.1")
	if e != nil || b == nil || b.Authentication.Source != "directory" || b.Authentication.EAPMethod != "peap" || b.VLAN != 100 || !s.PolicySubject(t.Context(), "access", "corp/alice") {
		t.Fatalf("policy damaged %+v %v", b, e)
	}
	rows, e := s.DB.QueryContext(t.Context(), "PRAGMA foreign_key_check")
	if e != nil {
		t.Fatal(e)
	}
	if rows.Next() {
		t.Fatal("foreign keys damaged")
	}
	rows.Close()
	if e = s.SaveAuthentication(t.Context(), AuthenticationPolicy{ID: "guest", Name: "OIDC", Source: "oidc", Enabled: true}); e != nil {
		t.Fatal(e)
	}
}
