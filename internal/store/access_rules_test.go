package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func ruleStore(t *testing.T) *Store {
	t.Helper()
	s, e := Open("sqlite", filepath.Join(t.TempDir(), "rules.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	if e = s.Migrate(t.Context()); e != nil {
		t.Fatal(e)
	}
	ctx := t.Context()
	s.SaveAuthentication(ctx, AuthenticationPolicy{ID: "auth", Name: "Auth", Source: "local", Enabled: true})
	if e = s.SaveAccess(ctx, AccessPolicy{ID: "access", Name: "Access", AuthenticationID: "auth", Mode: "ssh", Enabled: true, SessionSeconds: 3600}); e != nil {
		t.Fatal(e)
	}
	return s
}
func TestRuleOrderConditionsGroupsAndVersion(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	if e := s.SaveUserGroup(ctx, UserGroup{ID: "staff", Name: "Staff", Enabled: true, Members: []string{"local/alice"}}); e != nil {
		t.Fatal(e)
	}
	s.Exec(ctx, "INSERT INTO locations VALUES('office','Office')")
	s.Exec(ctx, "INSERT INTO nas(address,name,secret,location_id,access_policy_id) VALUES('192.0.2.1','NAS','secret','office','access')")
	allow := AccessRule{ID: "staff", Name: "Staff", Priority: 100, Effect: "allow", Enabled: true, Groups: []string{"staff"}, NAS: []string{"192.0.2.1"}, Locations: []string{"office"}, SSIDs: []string{"Corp"}, OS: []string{"Windows"}, DeviceTypes: []string{"Laptop"}, Manufacturers: []string{"Vendor"}}
	deny := AccessRule{ID: "block", Name: "Block", Priority: 10, Effect: "deny", Enabled: true, Subjects: []string{"local/alice"}, SSIDs: []string{"Guest"}}
	set := RuleSet{PolicyID: "access", Enabled: true, Rules: []AccessRule{allow, deny}}
	if e := s.SaveRules(ctx, set); e != nil {
		t.Fatal(e)
	}
	if e := s.SaveRules(ctx, set); e == nil {
		t.Fatal("stale update accepted")
	}
	b, e := s.BoundPolicy(ctx, "192.0.2.1")
	if e != nil {
		t.Fatal(e)
	}
	if b.Rules.Rules[0].ID != "block" {
		t.Fatal("not sorted")
	}
	c := AccessContext{Username: "local/alice", NAS: "192.0.2.1", Location: "office", SSID: "Corp", OS: "windows", DeviceType: "Laptop", Manufacturer: "Vendor"}
	ok, why, e := s.EvaluateAccess(ctx, b, c)
	if e != nil || !ok || why != "rule staff" {
		t.Fatal(ok, why, e)
	}
	for _, change := range []func(*AccessContext){func(c *AccessContext) { c.SSID = "Guest" }, func(c *AccessContext) { c.SSID = "corp" }, func(c *AccessContext) { c.OS = "" }, func(c *AccessContext) { c.Username = "other/alice" }, func(c *AccessContext) { c.NAS = "192.0.2.2" }} {
		copy := c
		change(&copy)
		if ok, _, e = s.EvaluateAccess(ctx, b, copy); e != nil || ok {
			t.Fatal("mismatched context accepted", copy, e)
		}
	}
	s.SaveUserGroup(ctx, UserGroup{ID: "staff", Name: "Staff", Enabled: false, Members: []string{"local/alice"}})
	if ok, _, _ := s.EvaluateAccess(ctx, b, c); ok {
		t.Fatal("disabled group accepted")
	}
	current, _ := s.Rules(ctx, "access")
	current.Rules[1].Priority = 10
	if e := s.SaveRules(ctx, current); e == nil {
		t.Fatal("duplicate priority accepted")
	}
	current, _ = s.Rules(ctx, "access")
	current.Enabled = false
	if e := s.SaveRules(ctx, current); e != nil {
		t.Fatal(e)
	}
	b, _ = s.BoundPolicy(ctx, "192.0.2.1")
	s.Exec(ctx, "INSERT INTO policy_subjects VALUES('access','local/alice')")
	if ok, _, _ := s.EvaluateAccess(ctx, b, c); !ok {
		t.Fatal("legacy explicit list changed")
	}
}
func TestLDAPGroupsBoundToAuthenticationDomain(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	s.Exec(ctx, "INSERT INTO domains(id,name,config) VALUES('corp','Corp','opaque')")
	s.Exec(ctx, "UPDATE authentication_policies SET source='directory',domain_id='corp'")
	set := RuleSet{PolicyID: "access", Enabled: true, Rules: []AccessRule{{ID: "ldap", Name: "LDAP", Priority: 10, Enabled: true, Effect: "allow", DirectoryGroups: []string{"cn=Net\\, Admins,ou=Groups,dc=example,dc=test"}}}}
	if e := s.SaveRules(ctx, set); e != nil {
		t.Fatal(e)
	}
	saved, _ := s.Rules(ctx, "access")
	b := &BoundPolicy{Authentication: AuthenticationPolicy{Source: "directory", DomainID: "corp"}, Rules: saved}
	for _, test := range []struct {
		user, group string
		want        bool
	}{{"corp/alice", "CN=net\\, admins,OU=groups,DC=example,DC=test", true}, {"other/alice", "CN=net\\, admins,OU=groups,DC=example,DC=test", false}, {"corp/alice", "cn=other,dc=test", false}, {"corp/alice", "", false}} {
		ok, _, e := s.EvaluateAccess(ctx, b, AccessContext{Username: test.user, DirectoryGroups: []string{test.group}})
		if e != nil || ok != test.want {
			t.Fatal(test, ok, e)
		}
	}
	s.Exec(ctx, "UPDATE authentication_policies SET source='local',domain_id=NULL")
	set.Version = saved.Version
	if e := s.SaveRules(ctx, set); e == nil || !strings.Contains(e.Error(), "directory") {
		t.Fatal("LDAP groups allowed without password bind", e)
	}
}
