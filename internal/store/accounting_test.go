package store

import (
	"testing"
	"time"
)

func TestAccountingOrderingRestartAndGenerations(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	base := time.Now().Unix() - 1000
	first, e := s.NewAccessGrant(ctx, "192.0.2.1", "user", "access", base+10000)
	if e != nil {
		t.Fatal(e)
	}
	second, e := s.NewAccessGrant(ctx, "192.0.2.1", "user", "access", base+10000)
	if e != nil {
		t.Fatal(e)
	}
	apply := func(kind, key, token string, at, seconds int64) {
		t.Helper()
		e := AccountingEvent{NAS: "192.0.2.1", ID: "reused", Username: "user", Kind: kind, Key: key, At: at, Timed: true, HasSeconds: true, Seconds: seconds, Classes: []string{token}}
		if err := s.ApplyAccounting(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	state := func(want string, at int64) {
		t.Helper()
		var status string
		var event int64
		if err := s.Row(ctx, "SELECT status,event_at FROM sessions WHERE nas='192.0.2.1' AND session_id='reused'").Scan(&status, &event); err != nil {
			t.Fatal(err)
		}
		if status != want || event != at {
			t.Fatalf("got %s/%d want %s/%d", status, event, want, at)
		}
	}
	apply("start", "start-1", first, base, 0)
	apply("interim", "interim-1", first, base+30, 30)
	apply("start", "start-1", first, base, 0)
	state("active", base+30)
	apply("stop", "stop-1", first, base+40, 40)
	state("stopped", base+40)
	apply("interim", "late-interim", first, base+45, 45)
	state("stopped", base+40)
	apply("start", "start-2", second, base+100, 0)
	state("active", base+100)
	apply("stop", "old-stop", first, base+150, 150)
	state("active", base+100)
	apply("start", "old-start", first, base+150, 0)
	state("active", base+100)
	// Delayed On must not close a session that started after that boot.
	apply("on", "on-old", "", base+90, 0)
	state("active", base+100)
	apply("off", "off", "", base+160, 0)
	state("nas-off", base+100)
	apply("interim", "after-off", second, base+170, 70)
	state("nas-off", base+100)
	apply("start", "before-boot", "", base+150, 0)
	state("nas-off", base+100)
}
func TestAccountingStaleRecoveryAndTerminalACK(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	base := time.Now().Unix() - 100
	token, e := s.NewAccessGrant(ctx, "192.0.2.1", "user", "access", base+10000)
	if e != nil {
		t.Fatal(e)
	}
	event := AccountingEvent{NAS: "192.0.2.1", ID: "s", Username: "user", Kind: "start", Key: "first", At: base, Timed: true, Classes: []string{token}}
	if e = s.ApplyAccounting(ctx, event); e != nil {
		t.Fatal(e)
	}
	if e = s.Exec(ctx, "UPDATE sessions SET last_seen=?", time.Now().Unix()-901); e != nil {
		t.Fatal(e)
	}
	if e = s.MarkStaleSessions(ctx); e != nil {
		t.Fatal(e)
	}
	sessions, e := s.Sessions(ctx)
	if e != nil || sessions[0].Status != "stale" {
		t.Fatal(sessions, e)
	}
	// A retry is not fresh evidence of reachability.
	if e = s.ApplyAccounting(ctx, event); e != nil {
		t.Fatal(e)
	}
	sessions, _ = s.Sessions(ctx)
	if sessions[0].Status != "stale" {
		t.Fatal("duplicate revived session")
	}
	event.Kind = "interim"
	event.Key = "second"
	event.At = base + 30
	event.Seconds = 30
	event.HasSeconds = true
	if e = s.ApplyAccounting(ctx, event); e != nil {
		t.Fatal(e)
	}
	sessions, _ = s.Sessions(ctx)
	if sessions[0].Status != "active" {
		t.Fatal("fresh Interim did not recover session")
	}
	current := sessions[0]
	current.GrantToken = token
	if e = s.ConfirmDisconnect(ctx, current); e != nil {
		t.Fatal(e)
	}
	event.Key = "third"
	event.At = base + 60
	event.Seconds = 60
	if e = s.ApplyAccounting(ctx, event); e != nil {
		t.Fatal(e)
	}
	sessions, _ = s.Sessions(ctx)
	if sessions[0].Status != "disconnect-ack" {
		t.Fatal("Interim resurrected ACK")
	}
}
func TestAccountingUntrackedOldStopAndRetryCAS(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	base := time.Now().Unix() - 1000
	for _, e := range []AccountingEvent{
		{NAS: "nas", ID: "s", Kind: "start", At: base, Timed: true},
		{NAS: "nas", ID: "s", Kind: "start", At: base + 500, Timed: true},
		{NAS: "nas", ID: "s", Kind: "stop", At: base + 510, Timed: true, HasSeconds: true, Seconds: 510},
	} {
		if err := s.ApplyAccounting(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	rows, e := s.Sessions(ctx)
	if e != nil || rows[0].Status != "active" {
		t.Fatal(rows, e)
	}
	if e = s.RetryRevocation(ctx, Session{NAS: "nas", ID: "s", Generation: "stale-generation"}); e == nil {
		t.Fatal("stale retry accepted")
	}
}
func TestRevocationDiagnosticsAndGenerationCAS(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	base := time.Now().Unix() - 100
	token, e := s.NewAccessGrant(ctx, "nas", "user", "access", base+500)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.ApplyAccounting(ctx, AccountingEvent{NAS: "nas", ID: "s", Kind: "start", At: base, Timed: true, Classes: []string{token}}); e != nil {
		t.Fatal(e)
	}
	list, _ := s.Sessions(ctx)
	old := list[0]
	if e = s.RevokeIdentity(ctx, "user"); e != nil {
		t.Fatal(e)
	}
	if e = s.RecordRevocation(ctx, old, "Disconnect-NAK", 503, "", base+500); e != nil {
		t.Fatal(e)
	}
	list, _ = s.Sessions(ctx)
	v := list[0]
	if v.RevocationAttempts != 1 || v.RevocationCause != 503 || v.RevocationNext != base+500 || v.RevocationLast == 0 {
		t.Fatal(v)
	}
	if e = s.RetryRevocation(ctx, v); e != nil {
		t.Fatal(e)
	}
	list, _ = s.Sessions(ctx)
	if list[0].RevocationNext != 0 {
		t.Fatal("retry not queued")
	}
	fresh, e := s.NewAccessGrant(ctx, "nas", "user", "access", base+500)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.ApplyAccounting(ctx, AccountingEvent{NAS: "nas", ID: "s", Kind: "start", At: base + 50, Timed: true, Classes: []string{fresh}}); e != nil {
		t.Fatal(e)
	}
	if e = s.RecordRevocation(ctx, old, "Disconnect-ACK", 0, "", 0); e != nil {
		t.Fatal(e)
	}
	if e = s.RetryRevocation(ctx, old); e == nil {
		t.Fatal("stale retry accepted")
	}
	list, _ = s.Sessions(ctx)
	if list[0].RevocationAttempts != 0 || list[0].Status != "active" {
		t.Fatal("old result affected new generation")
	}
}
func TestAccountingStartInRestartSecond(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	if e := s.ApplyAccounting(ctx, AccountingEvent{NAS: "nas", Kind: "on", At: now, Timed: true}); e != nil {
		t.Fatal(e)
	}
	token, e := s.NewAccessGrant(ctx, "nas", "user", "access", now+3600)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.ApplyAccounting(ctx, AccountingEvent{NAS: "nas", ID: "fresh", Kind: "start", At: now, Timed: true, Classes: []string{token}}); e != nil {
		t.Fatal(e)
	}
	rows, e := s.Sessions(ctx)
	if e != nil || len(rows) != 1 || rows[0].Status != "active" {
		t.Fatal(rows, e)
	}
	// A repeated On with the same timestamp must not close this fresh session.
	if e = s.ApplyAccounting(ctx, AccountingEvent{NAS: "nas", Kind: "on", At: now, Timed: true}); e != nil {
		t.Fatal(e)
	}
	rows, _ = s.Sessions(ctx)
	if rows[0].Status != "active" {
		t.Fatal("duplicate On closed fresh session")
	}
}

func TestPerNASStaleThresholds(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	for _, n := range []struct {
		ip              string
		interval, stale int
	}{{"192.0.2.1", 60, 180}, {"192.0.2.2", 600, 1800}} {
		if err := s.Exec(ctx, "INSERT INTO nas(address,name,secret,interim_seconds,stale_seconds) VALUES(?,?,?,?,?)", n.ip, "NAS", "secret", n.interval, n.stale); err != nil {
			t.Fatal(err)
		}
		if err := s.ApplyAccounting(ctx, AccountingEvent{NAS: n.ip, ID: "s", Kind: "start", At: now - 600, Timed: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.MarkStaleSessions(ctx); err != nil {
		t.Fatal(err)
	}
	list, err := s.Sessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range list {
		want := "active"
		if session.NAS == "192.0.2.1" {
			want = "stale"
		}
		if session.Status != want {
			t.Fatal(session)
		}
	}
	if err := s.ApplyAccounting(ctx, AccountingEvent{NAS: "192.0.2.1", ID: "s", Kind: "interim", At: now, Timed: true}); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := s.Row(ctx, "SELECT status FROM sessions WHERE nas='192.0.2.1'").Scan(&status); err != nil || status != "active" {
		t.Fatal(status, err)
	}
}
