package store

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestPolicyDraftLifecycleAndSessionIsolation(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(s.Exec(ctx, "INSERT INTO nas(address,name,secret,access_policy_id) VALUES('192.0.2.1','NAS','secret','access')"))
	access, _ := s.Accesses(ctx)
	p := access[0]
	p.ID = "other"
	must(s.SaveAccess(ctx, p))
	token, e := s.NewAccessGrant(ctx, "192.0.2.1", "local/alice", "access", time.Now().Unix()+3600)
	must(e)
	other, e := s.NewAccessGrant(ctx, "192.0.2.1", "local/alice", "other", time.Now().Unix()+3600)
	must(e)
	must(s.Accounting(ctx, "192.0.2.1", "vpn", "", "alice", "active", token))
	must(s.Accounting(ctx, "192.0.2.1", "ssh", "", "alice", "active", other))
	must(s.Accounting(ctx, "192.0.2.1", "unknown", "", "bob", "active", ""))
	p = access[0]
	p.Enabled = false
	d := PolicyDraft{Kind: "access", PolicyID: p.ID, Payload: policyJSON(p)}
	must(s.SavePolicyDraft(ctx, d, "admin"))
	live, _ := s.Accesses(ctx)
	if !live[0].Enabled {
		t.Fatal("draft changed live policy")
	}
	impact, e := s.PolicyDraftImpact(ctx, "access", p.ID)
	must(e)
	if impact.Conflict || len(impact.Devices) != 1 || len(impact.Sessions) != 1 || impact.Sessions[0].ID != "vpn" || len(impact.UnlinkedSessions) != 1 {
		t.Fatalf("impact %+v", impact)
	}
	if e = s.SavePolicyDraft(ctx, d, "second-admin"); e == nil {
		t.Fatal("lost update allowed")
	}
	if e = s.PublishPolicyDraft(ctx, "access", p.ID, 2, "admin"); e == nil {
		t.Fatal("stale publish allowed")
	}
	must(s.PublishPolicyDraft(ctx, "access", p.ID, 1, "admin"))
	var reason string
	must(s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason))
	if reason == "" {
		t.Fatal("grant not revoked")
	}
	must(s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", other).Scan(&reason))
	if reason != "" {
		t.Fatal("unrelated grant revoked")
	}
	releases, e := s.PolicyReleases(ctx)
	must(e)
	if len(releases) != 1 || releases[0].Actor != "admin" {
		t.Fatal(releases)
	}
	must(s.RollbackPolicyDraft(ctx, releases[0].ID, "rollback-admin"))
	live, _ = s.Accesses(ctx)
	if live[0].Enabled {
		t.Fatal("rollback draft changed live policy")
	}
	must(s.PublishPolicyDraft(ctx, "access", p.ID, 2, "rollback-admin"))
	live, _ = s.Accesses(ctx)
	if !live[0].Enabled {
		t.Fatal("rollback failed")
	}
	must(s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason))
	if reason == "" {
		t.Fatal("rollback resurrected grant")
	}
	drafts, e := s.PolicyDrafts(ctx)
	must(e)
	if len(drafts) != 0 {
		t.Fatal(drafts)
	}
}
func TestPolicyDraftConflictValidationAndAtomicity(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	policies, _ := s.Accesses(ctx)
	p := policies[0]
	p.Subjects = []string{"duplicate", "duplicate"}
	if e := s.SavePolicyDraft(ctx, PolicyDraft{Kind: "access", PolicyID: p.ID, Payload: policyJSON(p)}, "admin"); e == nil {
		t.Fatal("invalid draft accepted")
	}
	policies, _ = s.Accesses(ctx)
	if len(policies[0].Subjects) != 0 {
		t.Fatal("partial validation leaked")
	}
	p = policies[0]
	p.Name = "Draft"
	d := PolicyDraft{Kind: "access", PolicyID: p.ID, Payload: policyJSON(p)}
	if e := s.SavePolicyDraft(ctx, d, "admin"); e != nil {
		t.Fatal(e)
	}
	p.Name = "Concurrent change"
	if e := s.SaveAccess(ctx, p); e != nil {
		t.Fatal(e)
	}
	impact, e := s.PolicyDraftImpact(ctx, "access", p.ID)
	if e != nil || !impact.Conflict {
		t.Fatal(impact, e)
	}
	if e = s.PublishPolicyDraft(ctx, "access", p.ID, 1, "admin"); e == nil {
		t.Fatal("live conflict ignored")
	}
	history, _ := s.PolicyReleases(ctx)
	if len(history) != 0 {
		t.Fatal("failed publish recorded")
	}
	if e = s.DiscardPolicyDraft(ctx, "access", p.ID, 2); e == nil {
		t.Fatal("stale discard allowed")
	}
	if e = s.DiscardPolicyDraft(ctx, "access", p.ID, 1); e != nil {
		t.Fatal(e)
	}
}
func TestAuthenticationDraftImpactAndConcurrentPublish(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	auths, _ := s.Authentications(ctx)
	a := auths[0]
	a.Name = "Updated"
	if e := s.SavePolicyDraft(ctx, PolicyDraft{Kind: "authentication", PolicyID: a.ID, Payload: policyJSON(a)}, "admin"); e != nil {
		t.Fatal(e)
	}
	token, e := s.NewAccessGrant(ctx, "192.0.2.9", "local/bob", "access", time.Now().Unix()+100)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- s.PublishPolicyDraft(ctx, "authentication", a.ID, 1, "admin") }()
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
	var reason string
	if e = s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason); e != nil || reason == "" {
		t.Fatal(reason, e)
	}
}
func TestRulesDraftRollbackVersions(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	c := RuleSet{PolicyID: "access", Enabled: true, Rules: []AccessRule{{ID: "allow", Name: "Allow", Effect: "allow", Enabled: true, AllAuthenticated: true}}}
	d := PolicyDraft{Kind: "rules", PolicyID: "access", Payload: policyJSON(c)}
	if e := s.SavePolicyDraft(ctx, d, "admin"); e != nil {
		t.Fatal(e)
	}
	live, _ := s.Rules(ctx, "access")
	if live.Version != 0 || live.Enabled {
		t.Fatal("draft leaked", live)
	}
	if e := s.PublishPolicyDraft(ctx, "rules", "access", 1, "admin"); e != nil {
		t.Fatal(e)
	}
	history, _ := s.PolicyReleases(ctx)
	if e := s.RollbackPolicyDraft(ctx, history[0].ID, "admin"); e != nil {
		t.Fatal(e)
	}
	drafts, _ := s.PolicyDrafts(ctx)
	var saved RuleSet
	json.Unmarshal(drafts[0].Payload, &saved)
	if saved.Version != 1 {
		t.Fatal(saved)
	}
	if e := s.PublishPolicyDraft(ctx, "rules", "access", 2, "admin"); e != nil {
		t.Fatal(e)
	}
	live, _ = s.Rules(ctx, "access")
	if live.Enabled || live.Version != 2 {
		t.Fatal(live)
	}
}

func TestRecreatedDraftCannotBePublishedByOldPreview(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	policies, _ := s.Accesses(ctx)
	p := policies[0]
	d := PolicyDraft{Kind: "access", PolicyID: p.ID, Payload: policyJSON(p)}
	if e := s.SavePolicyDraft(ctx, d, "admin"); e != nil {
		t.Fatal(e)
	}
	if e := s.DiscardPolicyDraft(ctx, d.Kind, d.PolicyID, 1); e != nil {
		t.Fatal(e)
	}
	p.Enabled = false
	d.Payload = policyJSON(p)
	if e := s.SavePolicyDraft(ctx, d, "admin"); e != nil {
		t.Fatal(e)
	}
	if e := s.PublishPolicyDraft(ctx, d.Kind, d.PolicyID, 1, "admin"); e == nil {
		t.Fatal("old preview published different draft")
	}
	if e := s.PublishPolicyDraft(ctx, d.Kind, d.PolicyID, 2, "admin"); e != nil {
		t.Fatal(e)
	}
}
func TestAuthenticationPublicationValidatesDependentAccess(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	auths, _ := s.Authentications(ctx)
	a := auths[0]
	a.Source = "mab"
	if e := s.SavePolicyDraft(ctx, PolicyDraft{Kind: "authentication", PolicyID: a.ID, Payload: policyJSON(a)}, "admin"); e != nil {
		t.Fatal(e)
	}
	if e := s.PublishPolicyDraft(ctx, "authentication", a.ID, 1, "admin"); e == nil {
		t.Fatal("MAB published under SSH policy")
	}
	auths, _ = s.Authentications(ctx)
	if auths[0].Source != "local" {
		t.Fatal("failed publication not atomic")
	}
}
