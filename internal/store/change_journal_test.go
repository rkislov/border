package store

import (
	"encoding/json"
	"github.com/pressly/goose/v3"
	"strings"
	"testing"
	"time"
)

func TestChangeJournalLifecycleAndCycles(t *testing.T) {
	s := reviewStore(t)
	ctx := t.Context()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(s.SaveReviewSettings(ctx, ReviewSettings{Required: true}, "alice"))
	reviewDraft(t, s, "First", "alice")
	ref := reviewDraft(t, s, "Final", "carol")
	id, e := s.SubmitPolicyReview(ctx, []DraftRef{ref}, "Please review", "alice")
	must(e)
	must(s.DecidePolicyReview(ctx, id, true, "Checked", "bob"))
	must(s.PublishPolicyBatch(ctx, []DraftRef{ref}, "alice"))
	page, e := s.ChangeJournal(ctx, "", "", "published", 0, 50)
	must(e)
	if len(page.Items) != 1 {
		t.Fatal(page)
	}
	detail, e := s.ChangeJournalDetail(ctx, page.Items[0].ID)
	must(e)
	var snapshot PublicationSnapshot
	must(json.Unmarshal(detail.Event.Detail, &snapshot))
	if !snapshot.ImpactAvailable || snapshot.Requester != "alice" || snapshot.Reviewer != "bob" || snapshot.DecisionComment != "Checked" || len(snapshot.Changes) != 1 || strings.Join(snapshot.Changes[0].Authors, ",") != "alice,carol" {
		t.Fatal(snapshot)
	}
	actions := map[string]int{}
	for _, event := range detail.Timeline {
		actions[event.Action]++
	}
	if actions["draft_saved"] != 2 || actions["review_approved"] != 1 || actions["review_requested"] != 1 || actions["published"] != 1 {
		t.Fatal(actions)
	}
	reviewDraft(t, s, "Another lifecycle", "alice")
	newPage, e := s.ChangeJournal(ctx, "staff", "alice", "draft_saved", 0, 1)
	must(e)
	newDetail, e := s.ChangeJournalDetail(ctx, newPage.Items[0].ID)
	must(e)
	if len(newDetail.Timeline) != 1 {
		t.Fatal("mixed independent draft lifecycles", newDetail.Timeline)
	}
	must(s.DiscardPolicyDraft(ctx, "group", "staff", 3, "carol"))
	discards, _ := s.ChangeJournal(ctx, "", "carol", "draft_discarded", 0, 10)
	if len(discards.Items) != 1 {
		t.Fatal(discards)
	}
}
func TestChangeJournalSnapshotAndAtomicFailure(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	p := AccessPolicy{ID: "vpn", Name: "VPN", AuthenticationID: "auth", Mode: "vpn", Enabled: true, SessionSeconds: 3600}
	must(s.SaveAccess(ctx, p))
	must(s.Exec(ctx, "INSERT INTO nas(address,name,secret,access_policy_id) VALUES('192.0.2.1','Router','NAS-SUPER-SECRET','vpn')"))
	token, e := s.NewAccessGrant(ctx, "192.0.2.1", "local/alice", "vpn", time.Now().Unix()+3600)
	must(e)
	must(s.Accounting(ctx, "192.0.2.1", "vpn-1", "", "alice", "active", token))
	must(s.Accounting(ctx, "192.0.2.1", "unlinked", "", "guest", "active", ""))
	other := p
	other.ID = "other-policy"
	must(s.SaveAccess(ctx, other))
	otherToken, e := s.NewAccessGrant(ctx, "192.0.2.1", "local/alice", other.ID, time.Now().Unix()+3600)
	must(e)
	must(s.Accounting(ctx, "192.0.2.1", "unaffected", "", "alice", "active", otherToken))
	p.Name = "Changed"
	must(s.SavePolicyDraft(ctx, PolicyDraft{Kind: "access", PolicyID: "vpn", Payload: policyJSON(p)}, "admin"))
	must(s.Exec(ctx, "CREATE TRIGGER reject_journal_publish BEFORE INSERT ON policy_releases BEGIN SELECT RAISE(ABORT,'failure'); END"))
	if e = s.PublishPolicyDraft(ctx, "access", "vpn", 1, "admin"); e == nil {
		t.Fatal("expected failure")
	}
	page, _ := s.ChangeJournal(ctx, "", "", "published", 0, 50)
	if len(page.Items) != 0 {
		t.Fatal("uncommitted publication logged")
	}
	var tracked int
	must(s.Row(ctx, "SELECT COUNT(*) FROM publication_results").Scan(&tracked))
	if tracked != 0 {
		t.Fatal("uncommitted publication tracked")
	}
	must(s.Exec(ctx, "DROP TRIGGER reject_journal_publish"))
	must(s.PublishPolicyDraft(ctx, "access", "vpn", 1, "admin"))
	page, _ = s.ChangeJournal(ctx, "", "", "published", 0, 50)
	d, e := s.ChangeJournalDetail(ctx, page.Items[0].ID)
	must(e)
	raw := string(d.Event.Detail)
	if strings.Contains(raw, token) || strings.Contains(raw, "NAS-SUPER-SECRET") {
		t.Fatal("secret exposed")
	}
	var snapshot PublicationSnapshot
	must(json.Unmarshal(d.Event.Detail, &snapshot))
	if len(snapshot.Devices) != 1 || len(snapshot.Sessions) != 1 || len(snapshot.UnlinkedSessions) != 1 || snapshot.GrantCount != 1 || !snapshot.Sessions[0].ReauthenticationRequested || snapshot.Sessions[0].Generation == "" {
		t.Fatal(snapshot)
	}
	if snapshot.Sessions[0].ID != "vpn-1" {
		t.Fatal("matched another session of the same user", snapshot.Sessions)
	}
	must(s.Exec(ctx, "DELETE FROM sessions"))
	must(s.Exec(ctx, "UPDATE nas SET name='Renamed'"))
	again, e := s.ChangeJournalDetail(ctx, page.Items[0].ID)
	must(e)
	if string(again.Event.Detail) != raw {
		t.Fatal("historical impact changed")
	}
}
func TestChangeJournalPaginationAndTenantIsolation(t *testing.T) {
	s := reviewStore(t)
	ctx := t.Context()
	reviewDraft(t, s, "First", "alice")
	reviewDraft(t, s, "Second", "carol")
	page, e := s.ChangeJournal(ctx, "staff", "", "draft_saved", 0, 1)
	if e != nil || len(page.Items) != 1 || page.NextBefore == 0 {
		t.Fatal(page, e)
	}
	reviewDraft(t, s, "Third", "alice")
	older, e := s.ChangeJournal(ctx, "staff", "", "draft_saved", page.NextBefore, 1)
	if e != nil || len(older.Items) != 1 || older.Items[0].Seq >= page.Items[0].Seq {
		t.Fatal(older, e)
	}
	escaped, e := s.ChangeJournal(ctx, "%", "", "", 0, 50)
	if e != nil || len(escaped.Items) != 0 {
		t.Fatal("wildcard not escaped", escaped, e)
	}
	other := reviewStore(t)
	if _, e = other.ChangeJournalDetail(ctx, page.Items[0].ID); e == nil {
		t.Fatal("cross tenant journal")
	}
}

func TestChangeJournalLegacyMigration(t *testing.T) {
	s, review, _ := scheduledFixture(t)
	ctx := t.Context()
	if e := s.PublishPolicyDraft(ctx, "group", "staff", 1, "alice"); e != nil {
		t.Fatal(e)
	}
	provider, e := goose.NewProvider(goose.DialectSQLite3, s.DB, migrationFS())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = provider.DownTo(ctx, 30); e != nil {
		t.Fatal(e)
	}
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	page, e := s.ChangeJournal(ctx, "", "", "published_legacy", 0, 50)
	if e != nil || len(page.Items) != 1 || page.Items[0].ReviewID != review {
		t.Fatal(page, e)
	}
	d, e := s.ChangeJournalDetail(ctx, page.Items[0].ID)
	if e != nil || !d.Event.Legacy || !strings.Contains(string(d.Event.Detail), "ImpactAvailable\":false") {
		t.Fatal(d, e)
	}
	if len(d.Timeline) != 2 {
		t.Fatal("missing historical review", d.Timeline)
	}
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	again, _ := s.ChangeJournal(ctx, "", "", "", 0, 50)
	if len(again.Items) != 2 {
		t.Fatal("duplicate import", again)
	}
}
