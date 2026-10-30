package store

import (
	"encoding/json"
	"testing"
	"time"
)

func deletionRefs(t *testing.T, s *Store, keys ...[2]string) []DraftRef {
	t.Helper()
	for _, k := range keys {
		if e := s.SavePolicyDraft(t.Context(), PolicyDraft{Kind: k[0], PolicyID: k[1], Operation: "delete"}, "admin"); e != nil {
			t.Fatal(e)
		}
	}
	ds, e := s.PolicyDrafts(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	refs := []DraftRef{}
	for _, d := range ds {
		refs = append(refs, DraftRef{d.Kind, d.PolicyID, d.Revision})
	}
	return refs
}
func TestDeletionRequiresExplicitDependentsAndRestoresOwnedData(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(s.SaveUserGroup(ctx, UserGroup{ID: "staff", Name: "Staff", Enabled: true, Members: []string{"local/alice"}}))
	must(s.SaveRules(ctx, RuleSet{PolicyID: "access", Enabled: true, Rules: []AccessRule{{ID: "staff", Name: "Staff", Effect: "allow", Enabled: true, Groups: []string{"staff"}}}}))
	policies, _ := s.Accesses(ctx)
	p := policies[0]
	p.Subjects = []string{"local/alice"}
	must(s.SaveAccess(ctx, p))
	token, e := s.NewAccessGrant(ctx, "192.0.2.1", "local/alice", "access", time.Now().Unix()+100)
	must(e)
	refs := deletionRefs(t, s, [2]string{"access", "access"}, [2]string{"group", "staff"})
	impact, e := s.PolicyBatchImpact(ctx, refs)
	must(e)
	if len(impact.Errors) == 0 {
		t.Fatal("implicit rules cascade allowed")
	}
	if e = s.PublishPolicyBatch(ctx, refs, "admin"); e == nil {
		t.Fatal("dependent deletion accepted")
	}
	live, _ := s.Accesses(ctx)
	if len(live) != 1 {
		t.Fatal("failed deletion changed live")
	}
	var reason string
	must(s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason))
	if reason != "" {
		t.Fatal("failed deletion revoked grant")
	}
	must(s.SavePolicyDraft(ctx, PolicyDraft{Kind: "rules", PolicyID: "access", Operation: "delete"}, "admin"))
	ds, _ := s.PolicyDrafts(ctx)
	refs = nil
	for _, d := range ds {
		refs = append(refs, DraftRef{d.Kind, d.PolicyID, d.Revision})
	}
	must(s.PublishPolicyBatch(ctx, refs, "admin"))
	must(s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason))
	if reason == "" {
		t.Fatal("deleted policy did not revoke")
	}
	history, _ := s.PolicyReleases(ctx)
	batch := history[0].BatchID
	must(s.RollbackPolicyBatch(ctx, batch, "admin"))
	ds, _ = s.PolicyDrafts(ctx)
	refs = nil
	for _, d := range ds {
		refs = append(refs, DraftRef{d.Kind, d.PolicyID, d.Revision})
	}
	must(s.PublishPolicyBatch(ctx, refs, "admin"))
	live, _ = s.Accesses(ctx)
	if len(live) != 1 || len(live[0].Subjects) != 1 {
		t.Fatal("subjects not restored", live)
	}
	groups, _ := s.UserGroups(ctx)
	if len(groups) != 1 || len(groups[0].Members) != 1 {
		t.Fatal("members not restored")
	}
	rules, _ := s.Rules(ctx, "access")
	if rules.Version <= 1 || !rules.Enabled {
		t.Fatal("rules not restored with new version", rules)
	}
	must(s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason))
	if reason == "" {
		t.Fatal("restore resurrected grant")
	}
}
func TestDeletionBlockedByDisabledJSONReferenceAndForeignKeys(t *testing.T) {
	for _, kind := range []string{"group", "access", "authentication", "segment"} {
		t.Run(kind, func(t *testing.T) {
			s := ruleStore(t)
			ctx := t.Context()
			s.Exec(ctx, "INSERT INTO network_segments VALUES('staff','Staff')")
			s.Exec(ctx, "INSERT INTO locations VALUES('office','Office')")
			s.SaveMapping(ctx, SegmentMapping{LocationID: "office", SegmentID: "staff", VLAN: 100})
			s.SaveUserGroup(ctx, UserGroup{ID: "staff", Name: "Staff", Enabled: false})
			s.SaveRules(ctx, RuleSet{PolicyID: "access", Rules: []AccessRule{{ID: "staff", Name: "Staff", Effect: "allow", Groups: []string{"staff"}}}})
			id := map[string]string{"group": "staff", "access": "access", "authentication": "auth", "segment": "staff"}[kind]
			refs := deletionRefs(t, s, [2]string{kind, id})
			if e := s.PublishPolicyBatch(ctx, refs, "admin"); e == nil {
				t.Fatal("reference was ignored", kind)
			}
		})
	}
}
func TestMixedRollbackCannotPartiallyApplyWhenNewObjectGainsDependents(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	s.SaveUserGroup(ctx, UserGroup{ID: "staff", Name: "Before", Enabled: true})
	refs := stageBatch(t, s, []struct {
		kind, id string
		payload  any
	}{{"group", "staff", UserGroup{ID: "staff", Name: "After", Enabled: true}}, {"segment", "new-segment", Named{ID: "new-segment", Name: "New"}}})
	if e := s.PublishPolicyBatch(ctx, refs, "admin"); e != nil {
		t.Fatal(e)
	}
	history, _ := s.PolicyReleases(ctx)
	s.Exec(ctx, "INSERT INTO locations VALUES('office','Office')")
	s.SaveMapping(ctx, SegmentMapping{LocationID: "office", SegmentID: "new-segment", VLAN: 200})
	if e := s.RollbackPolicyBatch(ctx, history[0].BatchID, "admin"); e != nil {
		t.Fatal(e)
	}
	ds, _ := s.PolicyDrafts(ctx)
	refs = nil
	for _, d := range ds {
		refs = append(refs, DraftRef{d.Kind, d.PolicyID, d.Revision})
	}
	if e := s.PublishPolicyBatch(ctx, refs, "admin"); e == nil {
		t.Fatal("rollback removed referenced segment")
	}
	groups, _ := s.UserGroups(ctx)
	if groups[0].Name != "After" {
		t.Fatal("rollback partially applied")
	}
}
func TestLegacyAbsentSnapshotsAndSingleFirstPublicationRollback(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	p := AuthenticationPolicy{ID: "new", Name: "New", Source: "local", Enabled: true}
	refs := stageBatch(t, s, []struct {
		kind, id string
		payload  any
	}{{"authentication", "new", p}})
	if e := s.PublishPolicyBatch(ctx, refs, "admin"); e != nil {
		t.Fatal(e)
	}
	history, _ := s.PolicyReleases(ctx)
	if e := s.RollbackPolicyDraft(ctx, history[0].ID, "admin"); e != nil {
		t.Fatal(e)
	}
	ds, _ := s.PolicyDrafts(ctx)
	if ds[0].Operation != "delete" {
		t.Fatal(ds)
	}
	if e := s.PublishPolicyDraft(ctx, "authentication", "new", ds[0].Revision, "admin"); e != nil {
		t.Fatal(e)
	}
	// An unmodified draft created by the previous binary remains publishable.
	c := RuleSet{PolicyID: "access", Enabled: true, Rules: []AccessRule{{ID: "allow", Name: "Allow", Effect: "allow", Enabled: true, AllAuthenticated: true}}}
	if e := s.SavePolicyDraft(ctx, PolicyDraft{Kind: "rules", PolicyID: "access", Payload: policyJSON(c)}, "admin"); e != nil {
		t.Fatal(e)
	}
	old := policyJSON(RuleSet{PolicyID: "access", Rules: []AccessRule{}})
	if e := s.Exec(ctx, "UPDATE policy_drafts SET base=? WHERE kind='rules'", string(old)); e != nil {
		t.Fatal(e)
	}
	if e := s.PublishPolicyDraft(ctx, "rules", "access", 1, "admin"); e != nil {
		t.Fatal(e)
	}
	var raw json.RawMessage = old
	if !isDeletion(normalizeSnapshot("rules", raw)) {
		t.Fatal("legacy absent set not recognized")
	}
}

func TestDeletionRequiresDisabledNASBindingRemoval(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	s.Exec(ctx, "INSERT INTO nas(address,name,secret) VALUES('192.0.2.1','NAS','secret')")
	set := NASPolicySet{NAS: "192.0.2.1", Bindings: []PolicyBinding{{ID: "old", PolicyID: "access", Protocol: "pap"}}}
	if e := s.SaveNASPolicies(ctx, set); e != nil {
		t.Fatal(e)
	}
	refs := deletionRefs(t, s, [2]string{"access", "access"})
	if e := s.PublishPolicyBatch(ctx, refs, "admin"); e == nil {
		t.Fatal("disabled NAS reference ignored")
	}
	if e := s.SavePolicyDraft(ctx, PolicyDraft{Kind: "nas-policies", PolicyID: set.NAS, Operation: "delete"}, "admin"); e != nil {
		t.Fatal(e)
	}
	ds, _ := s.PolicyDrafts(ctx)
	refs = nil
	for _, d := range ds {
		refs = append(refs, DraftRef{d.Kind, d.PolicyID, d.Revision})
	}
	if e := s.PublishPolicyBatch(ctx, refs, "admin"); e != nil {
		t.Fatal(e)
	}
}
