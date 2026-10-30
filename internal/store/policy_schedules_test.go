// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"sync"
	"testing"
	"time"
)

func scheduledFixture(t *testing.T) (*Store, string, int64) {
	t.Helper()
	s := reviewStore(t)
	ctx := t.Context()
	if e := s.SaveReviewSettings(ctx, ReviewSettings{Required: true}, "alice"); e != nil {
		t.Fatal(e)
	}
	ref := reviewDraft(t, s, "Staff", "alice")
	id, e := s.SubmitPolicyReview(ctx, []DraftRef{ref}, "", "alice")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.DecidePolicyReview(ctx, id, true, "", "bob"); e != nil {
		t.Fatal(e)
	}
	return s, id, time.Now().Add(time.Hour).Unix()
}
func TestPolicyScheduleExactlyOnceAndDueTime(t *testing.T) {
	s, review, due := scheduledFixture(t)
	ctx := t.Context()
	id, e := s.SchedulePolicyReview(ctx, review, due, "alice")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.SchedulePolicyReview(ctx, review, due, "alice"); e == nil {
		t.Fatal("duplicate accepted")
	}
	if e = s.RunPolicySchedules(ctx, time.Unix(due-1, 0)); e != nil {
		t.Fatal(e)
	}
	rs, _ := s.PolicyReleases(ctx)
	if len(rs) != 0 {
		t.Fatal("early publication")
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := s.RunPolicySchedules(ctx, time.Unix(due, 0)); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	rs, _ = s.PolicyReleases(ctx)
	jobs, _ := s.PolicySchedules(ctx)
	if len(rs) != 1 || len(jobs) != 1 || jobs[0].ID != id || jobs[0].State != "published" || jobs[0].BatchID != rs[0].BatchID {
		t.Fatal(rs, jobs)
	}
	if e = s.RunPolicySchedules(ctx, time.Unix(due+60, 0)); e != nil {
		t.Fatal(e)
	}
	rs, _ = s.PolicyReleases(ctx)
	if len(rs) != 1 {
		t.Fatal("duplicate publication")
	}
}
func TestPolicyScheduleRechecksApprovalAndDrafts(t *testing.T) {
	for _, mutation := range []string{"draft", "discard", "mode", "reviewer", "publisher", "live", "manual"} {
		t.Run(mutation, func(t *testing.T) {
			s, review, due := scheduledFixture(t)
			ctx := t.Context()
			if _, e := s.SchedulePolicyReview(ctx, review, due, "alice"); e != nil {
				t.Fatal(e)
			}
			var e error
			switch mutation {
			case "draft":
				reviewDraft(t, s, "Changed", "alice")
			case "discard":
				e = s.DiscardPolicyDraft(ctx, "group", "staff", 1)
			case "mode":
				e = s.SaveReviewSettings(ctx, ReviewSettings{Required: false, Revision: 1}, "alice")
			case "reviewer":
				e = s.Exec(ctx, "UPDATE admins SET enabled=0 WHERE username='bob'")
			case "publisher":
				e = s.Exec(ctx, "UPDATE admins SET revision=revision+1 WHERE username='alice'")
			case "live":
				e = s.Exec(ctx, "INSERT INTO user_groups(id,name,enabled) VALUES('staff','Other',1)")
			case "manual":
				e = s.PublishPolicyBatch(ctx, []DraftRef{{Kind: "group", PolicyID: "staff", Revision: 1}}, "alice")
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = s.RunPolicySchedules(ctx, time.Unix(due, 0)); e != nil {
				t.Fatal(e)
			}
			jobs, _ := s.PolicySchedules(ctx)
			if len(jobs) != 1 || jobs[0].State != "blocked" || jobs[0].Reason == "" {
				t.Fatal(jobs)
			}
			rs, _ := s.PolicyReleases(ctx)
			expected := 0
			if mutation == "manual" {
				expected = 1
			}
			if len(rs) != expected {
				t.Fatal("unexpected publication", rs)
			}
		})
	}
}
func TestPolicyScheduleCancellationAndValidation(t *testing.T) {
	s, review, due := scheduledFixture(t)
	ctx := t.Context()
	for _, at := range []int64{0, time.Now().Unix() - 1, due + 367*86400} {
		if _, e := s.SchedulePolicyReview(ctx, review, at, "alice"); e == nil {
			t.Fatal("bad time")
		}
	}
	if _, e := s.SchedulePolicyReview(ctx, review, due, "viewer"); e == nil {
		t.Fatal("viewer scheduled")
	}
	id, e := s.SchedulePolicyReview(ctx, review, due, "alice")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CancelPolicySchedule(ctx, id, "viewer"); e == nil {
		t.Fatal("viewer cancelled")
	}
	if e = s.CancelPolicySchedule(ctx, id, "bob"); e != nil {
		t.Fatal(e)
	}
	if e = s.RunPolicySchedules(ctx, time.Unix(due, 0)); e != nil {
		t.Fatal(e)
	}
	rs, _ := s.PolicyReleases(ctx)
	if len(rs) != 0 {
		t.Fatal(rs)
	}
	if _, e = s.SchedulePolicyReview(ctx, review, due+60, "alice"); e != nil {
		t.Fatal(e)
	}
}

func TestPolicyScheduleRollbackOnPublicationFailure(t *testing.T) {
	s, review, due := scheduledFixture(t)
	ctx := t.Context()
	if _, e := s.SchedulePolicyReview(ctx, review, due, "alice"); e != nil {
		t.Fatal(e)
	}
	if e := s.Exec(ctx, "CREATE TRIGGER reject_release BEFORE INSERT ON policy_releases BEGIN SELECT RAISE(ABORT,'test publication failure'); END"); e != nil {
		t.Fatal(e)
	}
	if e := s.RunPolicySchedules(ctx, time.Unix(due, 0)); e != nil {
		t.Fatal(e)
	}
	groups, _ := s.UserGroups(ctx)
	drafts, _ := s.PolicyDrafts(ctx)
	r, _ := s.PolicyReview(ctx, review)
	jobs, _ := s.PolicySchedules(ctx)
	if len(groups) != 0 || len(drafts) != 1 || r.State != "approved" || jobs[0].State != "blocked" {
		t.Fatal(groups, drafts, r, jobs)
	}
}
func TestPolicyScheduleRestartAndTenantIsolation(t *testing.T) {
	s, review, due := scheduledFixture(t)
	ctx := t.Context()
	if _, e := s.SchedulePolicyReview(ctx, review, due, "alice"); e != nil {
		t.Fatal(e)
	}
	var seq int
	var name, path string
	if e := s.DB.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); e != nil {
		t.Fatal(e)
	}
	other := reviewStore(t)
	if _, e := other.SchedulePolicyReview(ctx, review, due, "alice"); e == nil {
		t.Fatal("cross tenant approval")
	}
	if e := other.RunPolicySchedules(ctx, time.Unix(due, 0)); e != nil {
		t.Fatal(e)
	}
	if e := s.DB.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.DB.Close()
	if e = reopened.RunPolicySchedules(ctx, time.Unix(due+300, 0)); e != nil {
		t.Fatal(e)
	}
	jobs, _ := reopened.PolicySchedules(ctx)
	if len(jobs) != 1 || jobs[0].State != "published" {
		t.Fatal(jobs)
	}
}
