// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func publicationFixture(t *testing.T, unlinked bool) (*Store, string, Session) {
	t.Helper()
	s := reviewStore(t)
	ctx := t.Context()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(s.SaveAuthentication(ctx, AuthenticationPolicy{ID: "auth", Name: "Auth", Source: "local", Enabled: true}))
	p := AccessPolicy{ID: "vpn", Name: "VPN", AuthenticationID: "auth", Mode: "vpn", Enabled: true, SessionSeconds: 3600}
	must(s.SaveAccess(ctx, p))
	must(s.Exec(ctx, "INSERT INTO nas(address,name,secret,access_policy_id) VALUES('192.0.2.1','Gateway','private-secret-value','vpn')"))
	token, e := s.NewAccessGrant(ctx, "192.0.2.1", "local/alice", "vpn", time.Now().Unix()+3600)
	must(e)
	must(s.ApplyAccounting(ctx, AccountingEvent{NAS: "192.0.2.1", ID: "vpn-1", Username: "alice", Kind: "start", At: time.Now().Unix() - 100, Timed: true, Classes: []string{token}}))
	if unlinked {
		must(s.Accounting(ctx, "192.0.2.1", "guest", "", "guest", "active"))
	}
	p.Name = "New VPN"
	must(s.SavePolicyDraft(ctx, PolicyDraft{Kind: "access", PolicyID: "vpn", Payload: policyJSON(p)}, "alice"))
	must(s.PublishPolicyDraft(ctx, "access", "vpn", 1, "alice"))
	events, e := s.ChangeJournal(ctx, "", "", "published", 0, 1)
	must(e)
	list, e := s.Sessions(ctx)
	must(e)
	var v Session
	for _, r := range list {
		if r.ID == "vpn-1" {
			v = r
		}
	}
	v.GrantToken = token
	return s, events.Items[0].BatchID, v
}
func resultState(t *testing.T, s *Store, batch, state string) *PublicationResult {
	t.Helper()
	if e := s.RunPublicationResults(t.Context(), time.Now()); e != nil {
		t.Fatal(e)
	}
	v, e := s.PublicationResult(t.Context(), batch)
	if e != nil || v == nil || v.State != state {
		t.Fatalf("state %s: %+v %v", state, v, e)
	}
	return v
}
func TestPublicationResultACKStopNotificationsAndRecovery(t *testing.T) {
	s, b, v := publicationFixture(t, false)
	ctx := t.Context()
	if e := s.SavePolicyNotificationTarget(ctx, PolicyNotificationTarget{Username: "alice", Channel: "email", Scope: "default", Destination: "alice@example.test", Enabled: true}); e != nil {
		t.Fatal(e)
	}
	if e := s.BeginPublicationRevocation(ctx, v); e != nil {
		t.Fatal(e)
	}
	if e := s.RecordRevocation(ctx, v, "Disconnect-NAK", 503, "", time.Now().Unix()+60); e != nil {
		t.Fatal(e)
	}
	r := resultState(t, s, b, "attention")
	if r.Sessions[0].Response != "Disconnect-NAK" || r.Sessions[0].ErrorCause != 503 || len(r.Attempts) != 1 {
		t.Fatal(r)
	}
	resultState(t, s, b, "attention")
	if e := s.ConfirmDisconnect(ctx, v); e != nil {
		t.Fatal(e)
	}
	if e := s.RecordRevocation(ctx, v, "Disconnect-ACK", 0, "", 0); e != nil {
		t.Fatal(e)
	}
	r = resultState(t, s, b, "in_progress")
	if r.Sessions[0].State != "awaiting_stop" {
		t.Fatal(r)
	}
	if e := s.RunPublicationResults(ctx, time.Unix(r.Sessions[0].DeadlineAt, 0)); e != nil {
		t.Fatal(e)
	}
	r, _ = s.PublicationResult(ctx, b)
	if r.State != "attention" || r.Sessions[0].State != "timeout" {
		t.Fatal(r)
	}
	// A real Stop after ACK is accepted; a duplicate cannot send another completion.
	event := AccountingEvent{NAS: v.NAS, ID: v.ID, Username: v.Username, Kind: "stop", At: time.Now().Unix(), Timed: true, Classes: []string{v.GrantToken}, Key: "stop"}
	if e := s.ApplyAccounting(ctx, event); e != nil {
		t.Fatal(e)
	}
	resultState(t, s, b, "completed")
	if e := s.ApplyAccounting(ctx, event); e != nil {
		t.Fatal(e)
	}
	resultState(t, s, b, "completed")
	var n int
	if e := s.Row(ctx, "SELECT COUNT(*) FROM policy_notification_events WHERE event_key LIKE 'publication result %'").Scan(&n); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	deliveries, e := s.PolicyDeliveries(ctx)
	if e != nil || len(deliveries) != 2 {
		t.Fatal(deliveries, e)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), v.GrantToken) || strings.Contains(string(raw), "private-secret-value") {
		t.Fatal("secret leaked")
	}
	// Completion persists when the live session is cleaned up.
	if e = s.Exec(ctx, "DELETE FROM sessions"); e != nil {
		t.Fatal(e)
	}
	resultState(t, s, b, "completed")
}
func TestPublicationResultGenerationsAndLateOldStop(t *testing.T) {
	s, b, old := publicationFixture(t, false)
	ctx := t.Context()
	fresh, e := s.NewAccessGrant(ctx, old.NAS, "local/alice", "vpn", time.Now().Unix()+3600)
	if e != nil {
		t.Fatal(e)
	}
	event := AccountingEvent{NAS: old.NAS, ID: old.ID, Username: old.Username, Kind: "start", At: time.Now().Unix(), Timed: true, Classes: []string{fresh}}
	if e = s.ApplyAccounting(ctx, event); e != nil {
		t.Fatal(e)
	}
	r := resultState(t, s, b, "attention")
	if r.Sessions[0].State != "superseded" {
		t.Fatal(r)
	}
	if e = s.RecordRevocation(ctx, old, "Disconnect-ACK", 0, "", 0); e != nil {
		t.Fatal(e)
	}
	r = resultState(t, s, b, "attention")
	if r.Sessions[0].Generation != old.Generation || r.Sessions[0].State != "superseded" {
		t.Fatal(r)
	}
	// A delayed but valid Stop closes only the old publication target.
	event.Kind = "stop"
	event.Classes = []string{old.GrantToken}
	event.At--
	if e = s.ApplyAccounting(ctx, event); e != nil {
		t.Fatal(e)
	}
	resultState(t, s, b, "completed")
	var status, token string
	if e = s.Row(ctx, "SELECT status,grant_token FROM sessions WHERE nas=? AND session_id=?", old.NAS, old.ID).Scan(&status, &token); e != nil || status != "active" || token != fresh {
		t.Fatal(status, token, e)
	}
}
func TestPublicationResultUnlinkedRestartAndIsolation(t *testing.T) {
	s, b, v := publicationFixture(t, true)
	ctx := t.Context()
	r := resultState(t, s, b, "attention")
	if len(r.Sessions) != 2 {
		t.Fatal(r)
	}
	if e := s.ApplyAccounting(ctx, AccountingEvent{NAS: v.NAS, Kind: "off", At: time.Now().Unix(), Timed: true}); e != nil {
		t.Fatal(e)
	}
	resultState(t, s, b, "completed")
	other := reviewStore(t)
	if r, e := other.PublicationResult(ctx, b); e != nil || r != nil {
		t.Fatal("tenant leak", r, e)
	}
}
func TestPublicationResultMissingAccountingAndRestart(t *testing.T) {
	s, b, v := publicationFixture(t, false)
	ctx := t.Context()
	// Add a second publication with one already-revoked active session and a new
	// grant that has not yet sent Accounting-Start.
	token, e := s.NewAccessGrant(ctx, v.NAS, "local/alice", "vpn", time.Now().Unix()+3600)
	if e != nil {
		t.Fatal(e)
	}
	p := AccessPolicy{ID: "vpn", Name: "Third", AuthenticationID: "auth", Mode: "vpn", Enabled: true, SessionSeconds: 3600}
	if e = s.SavePolicyDraft(ctx, PolicyDraft{Kind: "access", PolicyID: "vpn", Payload: policyJSON(p)}, "alice"); e != nil {
		t.Fatal(e)
	}
	if e = s.PublishPolicyDraft(ctx, "access", "vpn", 2, "alice"); e != nil {
		t.Fatal(e)
	}
	page, _ := s.ChangeJournal(ctx, "", "", "published", 0, 1)
	b = page.Items[0].BatchID
	r := resultState(t, s, b, "in_progress")
	if r.WaitingAccounting != 1 {
		t.Fatal(r)
	}
	if e = s.RunPublicationResults(ctx, time.Now().Add(11*time.Minute)); e != nil {
		t.Fatal(e)
	}
	r, _ = s.PublicationResult(ctx, b)
	if r.AccountingTimeout != 1 || r.State != "attention" {
		t.Fatal(r)
	}
	// Recovery by Interim without Start attaches exactly to its original grant.
	if e = s.ApplyAccounting(ctx, AccountingEvent{NAS: v.NAS, ID: "late", Username: "alice", Kind: "interim", At: time.Now().Unix(), Classes: []string{token}}); e != nil {
		t.Fatal(e)
	}
	r, _ = s.PublicationResult(ctx, b)
	if len(r.Sessions) != 2 || r.AccountingTimeout != 0 {
		t.Fatal(r)
	}
	// Reopen the same store and run two concurrent reconciliations; no duplicate notice.
	var path string
	rows, e := s.DB.Query("PRAGMA database_list")
	if e != nil {
		t.Fatal(e)
	}
	for rows.Next() {
		var seq int
		var name string
		if e = rows.Scan(&seq, &name, &path); e != nil {
			t.Fatal(e)
		}
	}
	rows.Close()
	if filepath.Base(path) == "" {
		t.Fatal("missing db path")
	}
	reopened, e := Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.DB.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, db := range []*Store{s, reopened} {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- db.RunPublicationResults(ctx, time.Now()) }()
	}
	wg.Wait()
	close(errs)
	for e = range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var n int
	if e = s.Row(ctx, "SELECT COUNT(*) FROM policy_notification_events WHERE event_key=?", "publication result attention "+b).Scan(&n); e != nil || n != 1 {
		t.Fatal(n, e)
	}
}

func TestPublicationResultWorkerRotationAndJournalLinks(t *testing.T) {
	s, b, _ := publicationFixture(t, true)
	ctx := t.Context()
	resultState(t, s, b, "attention")
	page, e := s.ChangeJournal(ctx, "vpn", "", "revocation_attention", 0, 10)
	if e != nil || len(page.Items) != 1 {
		t.Fatal(page, e)
	}
	detail, e := s.ChangeJournalDetail(ctx, page.Items[0].ID)
	if e != nil || len(detail.Objects) != 1 || len(detail.Timeline) != 3 {
		t.Fatal(detail, e)
	}
	// Already problematic packages must not starve later work in the bounded scan.
	for i := 0; i < 101; i++ {
		if e = s.Exec(ctx, "INSERT INTO publication_results(batch_id,created_at,updated_at,state) VALUES(?,?,?,'attention')", fmt.Sprintf("queue-%03d", i), 1, 1); e != nil {
			t.Fatal(e)
		}
	}
	for i := 0; i < 2; i++ {
		if e = s.RunPublicationResults(ctx, time.Now().Add(time.Duration(i)*time.Second)); e != nil {
			t.Fatal(e)
		}
	}
	var n int
	if e = s.Row(ctx, "SELECT COUNT(*) FROM publication_results WHERE batch_id LIKE 'queue-%' AND state<>'completed'").Scan(&n); e != nil || n != 0 {
		t.Fatal(n, e)
	}
}
