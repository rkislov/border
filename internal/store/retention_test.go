package store

import (
	"fmt"
	"testing"
	"time"
)

func TestRetentionOffPreviewPruneAndReplay(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	now := time.Now()
	old := now.Add(-8 * 24 * time.Hour).Unix()
	grant, err := s.NewAccessGrant(ctx, "192.0.2.1", "local/alice", "", now.Unix()+3600)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"active", "stale", "stopped", "disconnect-ack", "nas-off", "nas-on"} {
		if err = s.Exec(ctx, "INSERT INTO sessions(nas,session_id,mac,username,status,updated_at,event_at,generation,grant_token) VALUES(?,?,?,?,?,?,?,?,?)", "192.0.2.1", status, "aa:bb:cc:dd:ee:ff", "local/alice", status, old, old, "generation-"+status, grant); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Audit(ctx, "test", "user", "result", "reason"); err != nil {
		t.Fatal(err)
	}
	if err = s.Exec(ctx, "UPDATE auth_log SET occurred_at=?", old); err != nil {
		t.Fatal(err)
	}
	count := func(table string) int {
		t.Helper()
		var n int
		if err := s.Row(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if err = s.PruneHistory(ctx, now); err != nil || count("sessions") != 6 || count("auth_log") != 1 {
		t.Fatal("default must not delete", err)
	}
	p := RetentionPolicy{AuditDays: 7, SessionDays: 7}
	preview, err := s.PreviewRetention(ctx, p, now)
	if err != nil || preview.AuditEvents != 1 || preview.ClosedSessions != 2 || count("sessions") != 6 {
		t.Fatal(preview, err)
	}
	if err = s.SaveRetention(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err = s.PruneHistory(ctx, now); err != nil {
		t.Fatal(err)
	}
	if count("sessions") != 4 || count("auth_log") != 0 || count("session_tombstones") != 2 || count("access_grants") != 1 {
		t.Fatal("unexpected cleanup")
	}
	current, err := s.Retention(ctx)
	if err != nil || current.LastSessionsDeleted != 2 || current.LastAuditDeleted != 1 {
		t.Fatal(current, err)
	}
	for _, kind := range []string{"start", "interim", "stop"} {
		if err = s.ApplyAccounting(ctx, AccountingEvent{NAS: "192.0.2.1", ID: "stopped", Kind: kind, At: now.Unix(), Timed: true, Classes: []string{grant}}); err != nil {
			t.Fatal(err)
		}
		if count("sessions") != 4 {
			t.Fatal("retention allowed old grant to resurrect session")
		}
	}
	next, err := s.NewAccessGrant(ctx, "192.0.2.1", "local/alice", "", now.Unix()+3600)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyAccounting(ctx, AccountingEvent{NAS: "192.0.2.1", ID: "stopped", Kind: "start", At: now.Unix(), Timed: true, Classes: []string{next}}); err != nil {
		t.Fatal(err)
	}
	if count("sessions") != 5 || count("session_tombstones") != 1 {
		t.Fatal("new generation rejected")
	}
	// Disabling never removes more history.
	if err = s.SaveRetention(ctx, RetentionPolicy{}); err != nil {
		t.Fatal(err)
	}
	before := count("auth_log")
	if err = s.PruneHistory(ctx, now.Add(30*24*time.Hour)); err != nil || count("auth_log") != before {
		t.Fatal(err)
	}
}

func TestRetentionBoundsAndBatch(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	now := time.Now()
	for _, days := range []int{-1, 1, 6, 3651} {
		if err := s.SaveRetention(ctx, RetentionPolicy{AuditDays: days}); err == nil {
			t.Fatal("accepted invalid days", days)
		}
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 501; i++ {
		if _, err = tx.ExecContext(ctx, "INSERT INTO auth_log VALUES(?,?,?,?,?,?)", fmt.Sprint(i), now.Add(-8*24*time.Hour).Unix(), "test", "test", "test", "test"); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveRetention(ctx, RetentionPolicy{AuditDays: 7}); err != nil {
		t.Fatal(err)
	}
	if err = s.PruneHistory(ctx, now); err != nil {
		t.Fatal(err)
	}
	p, err := s.Retention(ctx)
	if err != nil || p.LastAuditDeleted != 500 {
		t.Fatal(p, err)
	}
	if err = s.PruneHistory(ctx, now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	var n int
	if err = s.Row(ctx, "SELECT COUNT(*) FROM auth_log").Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if err = s.PruneHistory(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = s.Row(ctx, "SELECT COUNT(*) FROM auth_log").Scan(&n); err != nil || n != 0 {
		t.Fatal(n, err)
	}
}
