package store

import (
	"sync"
	"testing"
)

func reviewStore(t *testing.T) *Store {
	t.Helper()
	s := ruleStore(t)
	if e := s.Exec(t.Context(), "INSERT INTO admins(username,password_hash,role,enabled) VALUES('alice','','admin',1),('bob','','admin',1),('carol','','admin',1),('viewer','','viewer',1)"); e != nil {
		t.Fatal(e)
	}
	return s
}
func reviewDraft(t *testing.T, s *Store, name, actor string) DraftRef {
	t.Helper()
	id := "staff"
	ds, _ := s.PolicyDrafts(t.Context())
	var revision int64
	for _, d := range ds {
		if d.Kind == "group" && d.PolicyID == id {
			revision = d.Revision
		}
	}
	if e := s.SavePolicyDraft(t.Context(), PolicyDraft{Kind: "group", PolicyID: id, Revision: revision, Payload: policyJSON(UserGroup{ID: id, Name: name, Enabled: true})}, actor); e != nil {
		t.Fatal(e)
	}
	ds, _ = s.PolicyDrafts(t.Context())
	for _, d := range ds {
		if d.Kind == "group" && d.PolicyID == id {
			return DraftRef{d.Kind, d.PolicyID, d.Revision}
		}
	}
	t.Fatal("draft missing")
	return DraftRef{}
}
func TestReviewExactPackageAndCompleteRollback(t *testing.T) {
	s := reviewStore(t)
	ctx := t.Context()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	cfg, e := s.ReviewSettings(ctx)
	must(e)
	if cfg.Required {
		t.Fatal("enabled by default")
	}
	cfg.Required = true
	must(s.SaveReviewSettings(ctx, cfg, "alice"))
	first := reviewDraft(t, s, "Staff", "alice")
	must(s.SavePolicyDraft(ctx, PolicyDraft{Kind: "segment", PolicyID: "staff", Payload: policyJSON(Named{ID: "staff", Name: "Staff"})}, "alice"))
	refs := []DraftRef{first, {Kind: "segment", PolicyID: "staff", Revision: 1}}
	if e = s.PublishPolicyBatch(ctx, refs, "alice"); e == nil {
		t.Fatal("published without approval")
	}
	id, e := s.SubmitPolicyReview(ctx, refs, "Ready for review", "alice")
	must(e)
	if e = s.DecidePolicyReview(ctx, id, true, "", "alice"); e == nil {
		t.Fatal("self approval")
	}
	if e = s.DecidePolicyReview(ctx, id, true, "", "viewer"); e == nil {
		t.Fatal("viewer approval")
	}
	if e = s.DecidePolicyReview(ctx, id, false, "", "bob"); e == nil {
		t.Fatal("empty rejection")
	}
	must(s.DecidePolicyReview(ctx, id, true, "Checked", "bob"))
	if e = s.PublishPolicyDraft(ctx, "group", "staff", first.Revision, "alice"); e == nil {
		t.Fatal("subset bypass")
	}
	must(s.PublishPolicyBatch(ctx, []DraftRef{refs[1], refs[0]}, "alice"))
	r, e := s.PolicyReview(ctx, id)
	must(e)
	if r.State != "published" || r.BatchID == "" || r.Reviewer != "bob" || r.DecisionComment != "Checked" {
		t.Fatal(r)
	}
	must(s.RollbackPolicyBatch(ctx, r.BatchID, "alice"))
	ds, _ := s.PolicyDrafts(ctx)
	undo := []DraftRef{}
	for _, d := range ds {
		undo = append(undo, DraftRef{d.Kind, d.PolicyID, d.Revision})
	}
	if e = s.PublishPolicyBatch(ctx, undo, "alice"); e == nil {
		t.Fatal("rollback bypass")
	}
	undoID, e := s.SubmitPolicyReview(ctx, undo, "Undo", "alice")
	must(e)
	must(s.DecidePolicyReview(ctx, undoID, true, "", "bob"))
	must(s.PublishPolicyBatch(ctx, undo, "alice"))
	groups, _ := s.UserGroups(ctx)
	if len(groups) != 0 {
		t.Fatal(groups)
	}
}
func TestReviewInvalidationAndAllAuthorsExcluded(t *testing.T) {
	for _, approved := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "approved"}[approved], func(t *testing.T) {
			s := reviewStore(t)
			ctx := t.Context()
			s.SaveReviewSettings(ctx, ReviewSettings{Required: true}, "alice")
			ref := reviewDraft(t, s, "Before", "alice")
			id, e := s.SubmitPolicyReview(ctx, []DraftRef{ref}, "", "alice")
			if e != nil {
				t.Fatal(e)
			}
			if approved {
				if e = s.DecidePolicyReview(ctx, id, true, "", "bob"); e != nil {
					t.Fatal(e)
				}
			}
			ref = reviewDraft(t, s, "After", "carol")
			r, e := s.PolicyReview(ctx, id)
			if e != nil || r.State != "stale" {
				t.Fatal(r, e)
			}
			if e = s.PublishPolicyBatch(ctx, []DraftRef{ref}, "carol"); e == nil {
				t.Fatal("old approval reused")
			}
			next, e := s.SubmitPolicyReview(ctx, []DraftRef{ref}, "", "carol")
			if e != nil {
				t.Fatal(e)
			}
			if e = s.DecidePolicyReview(ctx, next, true, "", "alice"); e == nil {
				t.Fatal("previous author approved")
			}
			if e = s.DecidePolicyReview(ctx, next, true, "", "carol"); e == nil {
				t.Fatal("last author approved")
			}
			if e = s.DecidePolicyReview(ctx, next, true, "", "bob"); e != nil {
				t.Fatal(e)
			}
			if e = s.DiscardPolicyDraft(ctx, ref.Kind, ref.PolicyID, ref.Revision); e != nil {
				t.Fatal(e)
			}
			r, _ = s.PolicyReview(ctx, next)
			if r.State != "stale" {
				t.Fatal("discard did not invalidate")
			}
		})
	}
}
func TestReviewRejectionSettingsAndReviewerRevocation(t *testing.T) {
	s := reviewStore(t)
	ctx := t.Context()
	s.SaveReviewSettings(ctx, ReviewSettings{Required: true}, "alice")
	ref := reviewDraft(t, s, "Staff", "alice")
	id, e := s.SubmitPolicyReview(ctx, []DraftRef{ref}, "", "alice")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.DecidePolicyReview(ctx, id, false, "Fix the group", "bob"); e != nil {
		t.Fatal(e)
	}
	if e = s.PublishPolicyBatch(ctx, []DraftRef{ref}, "alice"); e == nil {
		t.Fatal("rejected published")
	}
	next, e := s.SubmitPolicyReview(ctx, []DraftRef{ref}, "Rechecked", "alice")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.DecidePolicyReview(ctx, next, true, "", "bob"); e != nil {
		t.Fatal(e)
	}
	// Even if the account becomes admin again, the old approval is not restored.
	s.Exec(ctx, "UPDATE admins SET revision=revision+1 WHERE username='bob'")
	if e = s.PublishPolicyBatch(ctx, []DraftRef{ref}, "alice"); e == nil {
		t.Fatal("changed reviewer approval used")
	}
	reviews, e := s.PolicyReviews(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range reviews {
		if r.ID == next && r.State != "stale" {
			t.Fatal(r)
		}
	}
	third, e := s.SubmitPolicyReview(ctx, []DraftRef{ref}, "", "alice")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.DecidePolicyReview(ctx, third, true, "", "carol"); e != nil {
		t.Fatal(e)
	}
	cfg, _ := s.ReviewSettings(ctx)
	cfg.Required = false
	if e = s.SaveReviewSettings(ctx, cfg, "alice"); e != nil {
		t.Fatal(e)
	}
	r, _ := s.PolicyReview(ctx, third)
	if r.State != "stale" {
		t.Fatal("mode change did not reset")
	}
	if e = s.PublishPolicyBatch(ctx, []DraftRef{ref}, "alice"); e != nil {
		t.Fatal("disabled mode blocked", e)
	}
}
func TestReviewTenantIsolationAndConcurrentEdit(t *testing.T) {
	s := reviewStore(t)
	other := reviewStore(t)
	ctx := t.Context()
	s.SaveReviewSettings(ctx, ReviewSettings{Required: true}, "alice")
	other.SaveReviewSettings(ctx, ReviewSettings{Required: true}, "alice")
	ref := reviewDraft(t, s, "Staff", "alice")
	otherRef := reviewDraft(t, other, "Staff", "alice")
	id, e := s.SubmitPolicyReview(ctx, []DraftRef{ref}, "", "alice")
	if e != nil {
		t.Fatal(e)
	}
	if e = other.DecidePolicyReview(ctx, id, true, "", "bob"); e == nil {
		t.Fatal("cross tenant decision")
	}
	if e = other.PublishPolicyBatch(ctx, []DraftRef{otherRef}, "alice"); e == nil {
		t.Fatal("cross tenant publish")
	}
	var wg sync.WaitGroup
	wg.Add(2)
	results := make(chan error, 2)
	go func() { defer wg.Done(); results <- s.DecidePolicyReview(ctx, id, true, "", "bob") }()
	go func() {
		defer wg.Done()
		results <- s.SavePolicyDraft(ctx, PolicyDraft{Kind: ref.Kind, PolicyID: ref.PolicyID, Revision: ref.Revision, Payload: policyJSON(UserGroup{ID: "staff", Name: "Concurrent", Enabled: true})}, "alice")
	}()
	wg.Wait()
	close(results)
	for range results {
	}
	r, e := s.PolicyReview(ctx, id)
	if e != nil || r.State != "stale" {
		t.Fatal(r, e)
	}
}
func TestReviewModeNeedsTwoAdminsAndProtectsSettingsRevision(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	s.Exec(ctx, "INSERT INTO admins(username,password_hash) VALUES('alice','')")
	if e := s.SaveReviewSettings(ctx, ReviewSettings{Required: true}, "alice"); e == nil {
		t.Fatal("single admin mode enabled")
	}
	s.Exec(ctx, "INSERT INTO admins(username,password_hash) VALUES('bob','')")
	if e := s.SaveReviewSettings(ctx, ReviewSettings{Required: true}, "alice"); e != nil {
		t.Fatal(e)
	}
	if e := s.SaveReviewSettings(ctx, ReviewSettings{Required: false, Revision: 0}, "alice"); e == nil {
		t.Fatal("stale mode update")
	}
}

func TestApprovalBindsPayloadAsWellAsRevision(t *testing.T) {
	s := reviewStore(t)
	ctx := t.Context()
	s.SaveReviewSettings(ctx, ReviewSettings{Required: true}, "alice")
	ref := reviewDraft(t, s, "Original", "alice")
	id, e := s.SubmitPolicyReview(ctx, []DraftRef{ref}, "", "alice")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.DecidePolicyReview(ctx, id, true, "", "bob"); e != nil {
		t.Fatal(e)
	}
	// Defend against a writer that failed to bump the draft revision.
	if e = s.Exec(ctx, "UPDATE policy_drafts SET payload=? WHERE kind='group' AND policy_id='staff'", string(policyJSON(UserGroup{ID: "staff", Name: "Different", Enabled: true}))); e != nil {
		t.Fatal(e)
	}
	if e = s.PublishPolicyBatch(ctx, []DraftRef{ref}, "alice"); e == nil {
		t.Fatal("payload not included in approval")
	}
}
