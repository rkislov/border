package store

import (
	"context"
	"sync"
	"testing"
	"time"
)

func notificationTarget(t *testing.T, s *Store, channel string) {
	t.Helper()
	if e := s.SavePolicyNotificationTarget(t.Context(), PolicyNotificationTarget{Username: "bob", Channel: channel, Scope: "default", Destination: "test", Enabled: true}); e != nil {
		t.Fatal(e)
	}
}
func notificationEvent(t *testing.T, s *Store, key string) {
	t.Helper()
	tx, e := s.policyTx(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = s.enqueuePolicyEvent(t.Context(), tx, key, "Test notification"); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
}
func TestPolicyNotificationDedupLeasesAndRetries(t *testing.T) {
	s := reviewStore(t)
	ctx := t.Context()
	notificationTarget(t, s, "email")
	notificationTarget(t, s, "sms")
	notificationEvent(t, s, "event")
	notificationEvent(t, s, "event")
	ds, _ := s.PolicyDeliveries(ctx)
	if len(ds) != 2 {
		t.Fatal(ds)
	}
	now := time.Now().Unix()
	var wg sync.WaitGroup
	var mu sync.Mutex
	jobs := []PolicyDeliveryJob{}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j, e := s.ClaimPolicyDelivery(ctx, now)
			if e != nil {
				t.Error(e)
				return
			}
			if j != nil {
				mu.Lock()
				jobs = append(jobs, *j)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(jobs) != 2 || jobs[0].ID == jobs[1].ID {
		t.Fatal(jobs)
	}
	if e := s.FinishPolicyDelivery(ctx, jobs[0], true, "", now); e != nil {
		t.Fatal(e)
	}
	if e := s.FinishPolicyDelivery(ctx, jobs[1], false, "safe failure", now); e != nil {
		t.Fatal(e)
	}
	if j, _ := s.ClaimPolicyDelivery(ctx, now+29); j != nil {
		t.Fatal("early retry")
	}
	for attempt := 2; attempt <= 6; attempt++ {
		now += 2000
		j, e := s.ClaimPolicyDelivery(ctx, now)
		if e != nil || j == nil || j.ID != jobs[1].ID {
			t.Fatal(j, e)
		}
		if e = s.FinishPolicyDelivery(ctx, *j, false, "failure", now); e != nil {
			t.Fatal(e)
		}
	}
	ds, _ = s.PolicyDeliveries(ctx)
	for _, d := range ds {
		if d.ID == jobs[0].ID && d.State != "sent" {
			t.Fatal(d)
		}
		if d.ID == jobs[1].ID && (d.State != "failed" || d.Attempts != 6) {
			t.Fatal(d)
		}
	}
	if e := s.RetryPolicyDelivery(ctx, jobs[0].ID, "alice"); e == nil {
		t.Fatal("resent successful delivery")
	}
	if e := s.RetryPolicyDelivery(ctx, jobs[1].ID, "viewer"); e == nil {
		t.Fatal("viewer retry")
	}
	if e := s.RetryPolicyDelivery(ctx, jobs[1].ID, "alice"); e != nil {
		t.Fatal(e)
	}
}
func TestPolicyNotificationCrashRecoveryAndFencing(t *testing.T) {
	s := reviewStore(t)
	notificationTarget(t, s, "email")
	notificationEvent(t, s, "event")
	ctx := t.Context()
	now := time.Now().Unix()
	first, e := s.ClaimPolicyDelivery(ctx, now)
	if e != nil || first == nil {
		t.Fatal(e)
	}
	if j, _ := s.ClaimPolicyDelivery(ctx, now+119); j != nil {
		t.Fatal("lease bypass")
	}
	second, e := s.ClaimPolicyDelivery(ctx, now+120)
	if e != nil || second == nil || second.Token == first.Token {
		t.Fatal(second, e)
	}
	if e = s.FinishPolicyDelivery(ctx, *first, true, "", now+121); e != nil {
		t.Fatal(e)
	}
	ds, _ := s.PolicyDeliveries(ctx)
	if ds[0].State != "sending" {
		t.Fatal("stale completion", ds)
	}
	if e = s.FinishPolicyDelivery(ctx, *second, true, "", now+122); e != nil {
		t.Fatal(e)
	}
}
func TestPolicyNotificationAtomicEventsAndRecipientRevocation(t *testing.T) {
	s := reviewStore(t)
	notificationTarget(t, s, "email")
	ctx := t.Context()
	tx, e := s.policyTx(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.enqueuePolicyEvent(ctx, tx, "rolled back", "test"); e != nil {
		t.Fatal(e)
	}
	tx.Rollback()
	ds, _ := s.PolicyDeliveries(ctx)
	if len(ds) != 0 {
		t.Fatal("event survived rollback")
	}
	notificationEvent(t, s, "event")
	if e = s.Exec(ctx, "UPDATE admins SET enabled=0 WHERE username='bob'"); e != nil {
		t.Fatal(e)
	}
	j, e := s.ClaimPolicyDelivery(ctx, time.Now().Unix())
	if e != nil || j != nil {
		t.Fatal(j, e)
	}
	ds, _ = s.PolicyDeliveries(ctx)
	if ds[0].State != "cancelled" {
		t.Fatal(ds)
	}
}
func TestPolicyNotificationReviewEvents(t *testing.T) {
	s := reviewStore(t)
	ctx := t.Context()
	notificationTarget(t, s, "email")
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
	reviewDraft(t, s, "Changed", "alice")
	ds, _ := s.PolicyDeliveries(ctx)
	if len(ds) != 3 {
		t.Fatal("submit approve stale", ds)
	}
	reviewDraft(t, s, "Changed again", "alice")
	ds, _ = s.PolicyDeliveries(ctx)
	if len(ds) != 3 {
		t.Fatal("duplicate stale event", ds)
	}
	other := reviewStore(t)
	ds, _ = other.PolicyDeliveries(context.Background())
	if len(ds) != 0 {
		t.Fatal("cross tenant event")
	}
}
func TestPolicyNotificationChangedRecipientAndPushOwnership(t *testing.T) {
	s := reviewStore(t)
	ctx := t.Context()
	notificationTarget(t, s, "email")
	notificationEvent(t, s, "event")
	if e := s.SavePolicyNotificationTarget(ctx, PolicyNotificationTarget{Username: "bob", Channel: "email", Scope: "default", Destination: "changed", Enabled: true}); e != nil {
		t.Fatal(e)
	}
	ds, _ := s.PolicyDeliveries(ctx)
	if ds[0].State != "cancelled" {
		t.Fatal(ds)
	}
	first := PolicyNotificationTarget{Username: "alice", Channel: "push", Scope: "default", Destination: "encrypted", EndpointHash: "endpoint", Enabled: true}
	if e := s.SavePolicyNotificationTarget(ctx, first); e != nil {
		t.Fatal(e)
	}
	first.Username = "bob"
	if e := s.SavePolicyNotificationTarget(ctx, first); e == nil {
		t.Fatal("push subscription reassigned to another account")
	}
}
