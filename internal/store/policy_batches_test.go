package store

import (
	"encoding/json"
	"testing"
	"time"
)

func stageBatch(t *testing.T, s *Store, values []struct {
	kind, id string
	payload  any
}) []DraftRef {
	t.Helper()
	for _, v := range values {
		if e := s.SavePolicyDraft(t.Context(), PolicyDraft{Kind: v.kind, PolicyID: v.id, Payload: policyJSON(v.payload)}, "admin"); e != nil {
			t.Fatal(v.kind, e)
		}
	}
	ds, e := s.PolicyDrafts(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	out := []DraftRef{}
	for _, d := range ds {
		out = append(out, DraftRef{d.Kind, d.PolicyID, d.Revision})
	}
	return out
}
func TestBatchPublishesNewDependenciesAtomically(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(s.Exec(ctx, "INSERT INTO locations VALUES('east','East')"))
	must(s.Exec(ctx, "INSERT INTO nas(address,name,secret,location_id) VALUES('192.0.2.1','NAS','secret','east')"))
	refs := stageBatch(t, s, []struct {
		kind, id string
		payload  any
	}{
		{"nas-policies", "192.0.2.1", NASPolicySet{NAS: "192.0.2.1", Enabled: true, Bindings: []PolicyBinding{{ID: "staff", PolicyID: "staff", Protocol: "pap", Enabled: true}}}},
		{"rules", "staff", RuleSet{PolicyID: "staff", Enabled: true, Rules: []AccessRule{{ID: "staff", Name: "Staff", Effect: "allow", Enabled: true, Groups: []string{"staff"}}}}},
		{"access", "staff", AccessPolicy{ID: "staff", Name: "Staff", AuthenticationID: "new-auth", Mode: "network", SegmentID: "staff", SessionSeconds: 3600, Enabled: true}},
		{"mapping", "location/east/staff", SegmentMapping{LocationID: "east", SegmentID: "staff", VLAN: 200}},
		{"group", "staff", UserGroup{ID: "staff", Name: "Staff", Enabled: true, Members: []string{"local/alice"}}},
		{"authentication", "new-auth", AuthenticationPolicy{ID: "new-auth", Name: "New", Source: "local", Enabled: true}},
		{"segment", "staff", Named{ID: "staff", Name: "Staff"}},
	})
	only := []DraftRef{}
	for _, r := range refs {
		if r.Kind == "access" {
			only = append(only, r)
		}
	}
	impact, e := s.PolicyBatchImpact(ctx, only)
	must(e)
	if len(impact.Errors) == 0 {
		t.Fatal("missing dependency accepted")
	}
	impact, e = s.PolicyBatchImpact(ctx, refs)
	must(e)
	if len(impact.Errors) > 0 || len(impact.Devices) != 1 {
		t.Fatal(impact)
	}
	var n int
	must(s.Row(ctx, "SELECT count(*) FROM network_segments").Scan(&n))
	if n != 0 {
		t.Fatal("preview leaked configuration")
	}
	must(s.PublishPolicyBatch(ctx, refs, "publisher"))
	b, matched, e := s.SelectPolicy(ctx, "192.0.2.1", PolicyRequest{Protocol: "pap"})
	must(e)
	if !matched || b == nil || b.VLAN != 200 {
		t.Fatalf("binding %+v %v", b, matched)
	}
	history, e := s.PolicyReleases(ctx)
	must(e)
	if len(history) != 7 {
		t.Fatal(history)
	}
	batch := history[0].BatchID
	for _, r := range history {
		if r.BatchID == "" || r.BatchID != batch || r.Actor != "publisher" {
			t.Fatal(r)
		}
	}
	if e = s.PublishPolicyBatch(ctx, refs, "publisher"); e == nil {
		t.Fatal("double publish")
	}
	must(s.RollbackPolicyBatch(ctx, batch, "admin"))
	ds, _ := s.PolicyDrafts(ctx)
	undo := []DraftRef{}
	for _, d := range ds {
		if !isDeletion(d.Payload) {
			t.Fatal("new object not deleted by rollback", d.Kind)
		}
		undo = append(undo, DraftRef{d.Kind, d.PolicyID, d.Revision})
	}
	impact, e = s.PolicyBatchImpact(ctx, undo)
	must(e)
	if len(impact.Errors) > 0 {
		t.Fatal(impact.Errors)
	}
	must(s.PublishPolicyBatch(ctx, undo, "admin"))
	for _, table := range []string{"network_segments", "user_groups", "access_rule_sets", "location_segments", "nas_policy_sets"} {
		must(s.Row(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n))
		if n != 0 {
			t.Fatal("rollback left objects", table, n)
		}
	}
	// Roll back the deletion package: it must restore the complete new configuration.
	history, _ = s.PolicyReleases(ctx)
	var deletedBatch string
	for _, r := range history {
		if r.BatchID != batch {
			deletedBatch = r.BatchID
			break
		}
	}
	must(s.RollbackPolicyBatch(ctx, deletedBatch, "admin"))
	ds, _ = s.PolicyDrafts(ctx)
	undo = nil
	for _, d := range ds {
		undo = append(undo, DraftRef{d.Kind, d.PolicyID, d.Revision})
	}
	must(s.PublishPolicyBatch(ctx, undo, "admin"))
	b, matched, e = s.SelectPolicy(ctx, "192.0.2.1", PolicyRequest{Protocol: "pap"})
	must(e)
	if !matched || b == nil || b.VLAN != 200 {
		t.Fatal("restore failed", b)
	}
	set, e := s.NASPolicies(ctx, "192.0.2.1")
	must(e)
	if set.Version <= 1 {
		t.Fatal("NAS version reused", set.Version)
	}

}
func TestBatchLateFailureAndRevisionConflict(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	s.Exec(ctx, "INSERT INTO nas(address,name,secret) VALUES('192.0.2.1','NAS','secret')")
	auths, _ := s.Authentications(ctx)
	a := auths[0]
	a.Name = "Changed"
	refs := stageBatch(t, s, []struct {
		kind, id string
		payload  any
	}{{"authentication", a.ID, a}, {"nas-policies", "192.0.2.1", NASPolicySet{NAS: "192.0.2.1", Enabled: true, Bindings: []PolicyBinding{{ID: "missing", PolicyID: "missing", Protocol: "pap", Enabled: true}}}}})
	if e := s.PublishPolicyBatch(ctx, refs, "admin"); e == nil {
		t.Fatal("invalid batch published")
	}
	auths, _ = s.Authentications(ctx)
	if auths[0].Name == "Changed" {
		t.Fatal("partial commit")
	}
	history, _ := s.PolicyReleases(ctx)
	if len(history) != 0 {
		t.Fatal(history)
	}
	ds, _ := s.PolicyDrafts(ctx)
	for _, d := range ds {
		if d.Kind == "nas-policies" {
			d.Payload = policyJSON(NASPolicySet{NAS: d.PolicyID, Enabled: false})
			if e := s.SavePolicyDraft(ctx, d, "admin"); e != nil {
				t.Fatal(e)
			}
		}
	}
	if e := s.PublishPolicyBatch(ctx, refs, "admin"); e == nil {
		t.Fatal("stale batch accepted")
	}
	auths, _ = s.Authentications(ctx)
	if auths[0].Name == "Changed" {
		t.Fatal("stale partial commit")
	}
}
func TestMappingBatchScopesRevocationAndRollback(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(s.Exec(ctx, "INSERT INTO locations VALUES('east','East'),('west','West')"))
	must(s.Exec(ctx, "INSERT INTO network_segments VALUES('staff','Staff')"))
	must(s.SaveAccess(ctx, AccessPolicy{ID: "staff", Name: "Staff", AuthenticationID: "auth", Mode: "network", SegmentID: "staff", SessionSeconds: 3600, Enabled: true}))
	must(s.Exec(ctx, "INSERT INTO nas(address,name,secret,location_id,access_policy_id) VALUES('192.0.2.1','East','secret','east','staff'),('192.0.2.2','West','secret','west','staff'),('192.0.2.3','Override','secret','east','staff')"))
	for _, m := range []SegmentMapping{{LocationID: "east", SegmentID: "staff", VLAN: 100}, {LocationID: "west", SegmentID: "staff", VLAN: 200}, {NAS: "192.0.2.3", SegmentID: "staff", VLAN: 300}} {
		must(s.SaveMapping(ctx, m))
	}
	tokens := map[string]string{}
	for _, nas := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		token, e := s.NewAccessGrant(ctx, nas, "local/alice", "staff", time.Now().Unix()+3600)
		must(e)
		tokens[nas] = token
		must(s.Accounting(ctx, nas, "vpn", "", "alice", "active", token))
	}
	refs := stageBatch(t, s, []struct {
		kind, id string
		payload  any
	}{{"mapping", "location/east/staff", SegmentMapping{LocationID: "east", SegmentID: "staff", VLAN: 101}}})
	impact, e := s.PolicyBatchImpact(ctx, refs)
	must(e)
	if len(impact.Sessions) != 1 || impact.Sessions[0].NAS != "192.0.2.1" {
		t.Fatal(impact)
	}
	must(s.PublishPolicyBatch(ctx, refs, "admin"))
	for nas, token := range tokens {
		var reason string
		must(s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason))
		if (reason != "") != (nas == "192.0.2.1") {
			t.Fatal(nas, reason)
		}
	}
	history, _ := s.PolicyReleases(ctx)
	must(s.RollbackPolicyBatch(ctx, history[0].BatchID, "admin"))
	ds, _ := s.PolicyDrafts(ctx)
	var m SegmentMapping
	json.Unmarshal(ds[0].Payload, &m)
	if m.VLAN != 100 {
		t.Fatal(m)
	}
	must(s.PublishPolicyBatch(ctx, []DraftRef{{ds[0].Kind, ds[0].PolicyID, ds[0].Revision}}, "admin"))
	var vlan int
	must(s.Row(ctx, "SELECT vlan FROM location_segments WHERE location_id='east' AND segment_id='staff'").Scan(&vlan))
	if vlan != 100 {
		t.Fatal(vlan)
	}
}
func TestBatchGroupImpactRollbackAndTenantIsolation(t *testing.T) {
	s := ruleStore(t)
	other := ruleStore(t)
	ctx := t.Context()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	for _, db := range []*Store{s, other} {
		must(db.SaveUserGroup(ctx, UserGroup{ID: "staff", Name: "Staff", Enabled: true, Members: []string{"local/alice"}}))
		must(db.SaveRules(ctx, RuleSet{PolicyID: "access", Enabled: true, Rules: []AccessRule{{ID: "staff", Name: "Staff", Effect: "allow", Enabled: true, Groups: []string{"staff"}}}}))
	}
	token, e := s.NewAccessGrant(ctx, "192.0.2.1", "local/alice", "access", time.Now().Unix()+3600)
	must(e)
	refs := stageBatch(t, s, []struct {
		kind, id string
		payload  any
	}{{"group", "staff", UserGroup{ID: "staff", Name: "Staff", Enabled: true, Members: []string{"local/bob"}}}})
	must(s.PublishPolicyBatch(ctx, refs, "admin"))
	var reason string
	must(s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason))
	if reason == "" {
		t.Fatal("group grant not revoked")
	}
	groups, _ := other.UserGroups(ctx)
	if groups[0].Members[0] != "local/alice" {
		t.Fatal("tenant leaked")
	}
	history, _ := s.PolicyReleases(ctx)
	must(s.RollbackPolicyBatch(ctx, history[0].BatchID, "admin"))
	if e = s.RollbackPolicyBatch(ctx, history[0].BatchID, "admin"); e == nil {
		t.Fatal("rollback overwrote draft")
	}
}

func TestNASMetadataPreservesPublishedAssignment(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	if e := s.Exec(ctx, "INSERT INTO nas(address,name,secret,access_mode,access_policy_id) VALUES('192.0.2.1','NAS','secret','ssh','access')"); e != nil {
		t.Fatal(e)
	}
	n := NAS{Address: "192.0.2.1", Name: "Renamed", Mode: "ssh", Dictionary: "standard", Credential: "codes", CoAPort: 3799, InterimSeconds: 300, StaleSeconds: 900}
	if e := s.SaveNASMetadata(ctx, n, "secret"); e != nil {
		t.Fatal(e)
	}
	var p string
	if e := s.Row(ctx, "SELECT access_policy_id FROM nas WHERE address=?", n.Address).Scan(&p); e != nil || p != "access" {
		t.Fatal(p, e)
	}
	n.Mode = "network"
	if e := s.SaveNASMetadata(ctx, n, "secret"); e == nil {
		t.Fatal("incompatible NAS mode accepted")
	}
}
func TestBatchRejectsMissingNetworkMappingAndNoOpPreservesGrant(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	s.Exec(ctx, "INSERT INTO network_segments VALUES('staff','Staff')")
	s.Exec(ctx, "INSERT INTO nas(address,name,secret) VALUES('192.0.2.1','NAS','secret')")
	if e := s.SaveAccess(ctx, AccessPolicy{ID: "staff", Name: "Staff", AuthenticationID: "auth", Mode: "network", SegmentID: "staff", SessionSeconds: 3600, Enabled: true}); e != nil {
		t.Fatal(e)
	}
	refs := stageBatch(t, s, []struct {
		kind, id string
		payload  any
	}{{"nas-assignment", "192.0.2.1", NASAssignment{NAS: "192.0.2.1", AccessPolicyID: "staff"}}})
	v, e := s.PolicyBatchImpact(ctx, refs)
	if e != nil || len(v.Errors) == 0 {
		t.Fatal(v, e)
	}
	if e = s.PublishPolicyBatch(ctx, refs, "admin"); e == nil {
		t.Fatal("missing VLAN accepted")
	}
	s.DiscardPolicyDraft(ctx, refs[0].Kind, refs[0].PolicyID, refs[0].Revision)
	token, e := s.NewAccessGrant(ctx, "192.0.2.1", "local/alice", "access", time.Now().Unix()+100)
	if e != nil {
		t.Fatal(e)
	}
	access, _ := s.Accesses(ctx)
	var p AccessPolicy
	for _, a := range access {
		if a.ID == "access" {
			p = a
		}
	}
	refs = stageBatch(t, s, []struct {
		kind, id string
		payload  any
	}{{"access", "access", p}})
	if e = s.PublishPolicyBatch(ctx, refs, "admin"); e != nil {
		t.Fatal(e)
	}
	var reason string
	if e = s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason); e != nil || reason != "" {
		t.Fatal("no-op revoked grant", reason, e)
	}
}
