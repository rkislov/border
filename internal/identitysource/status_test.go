package identitysource

import (
	"github.com/rkislov/border/internal/store"
	"path/filepath"
	"testing"
	"time"
)

func TestStatusSyncRevokesAndDoesNotRestoreOldGrant(t *testing.T) {
	s, e := store.Open("sqlite", filepath.Join(t.TempDir(), "status.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	ctx := t.Context()
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	service := &Service{Store: s}
	if e = s.Exec(ctx, "INSERT INTO local_users(username,email,password_hash,enabled) VALUES('alice','','',0)"); e != nil {
		t.Fatal(e)
	}
	token, e := s.NewAccessGrant(ctx, "192.0.2.1", "local/alice", "", time.Now().Unix()+3600)
	if e != nil {
		t.Fatal(e)
	}
	if e = service.SyncAccountStatus(ctx); e != nil {
		t.Fatal(e)
	}
	if enabled, e := s.IdentityEnabled(ctx, "local/alice"); e != nil || enabled {
		t.Fatal(enabled, e)
	}
	if e = s.Exec(ctx, "UPDATE local_users SET enabled=1"); e != nil {
		t.Fatal(e)
	}
	if e = s.Exec(ctx, "UPDATE identity_status SET checked_at=0"); e != nil {
		t.Fatal(e)
	}
	if e = service.SyncAccountStatus(ctx); e != nil {
		t.Fatal(e)
	}
	if enabled, e := s.IdentityEnabled(ctx, "local/alice"); e != nil || !enabled {
		t.Fatal(enabled, e)
	}
	var reason string
	if e = s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason); e != nil || reason == "" {
		t.Fatal(reason, e)
	}
	// An unavailable provider preserves a prior block instead of clearing it.
	if e = s.Exec(ctx, "INSERT INTO identity_status VALUES('unknown/alice',1,0)"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.NewAccessGrant(ctx, "192.0.2.1", "unknown/alice", "", time.Now().Unix()+3600); e != nil {
		t.Fatal(e)
	}
	if e = service.SyncAccountStatus(ctx); e != nil {
		t.Fatal(e)
	}
	var blocked int
	if e = s.Row(ctx, "SELECT blocked FROM identity_status WHERE username='unknown/alice'").Scan(&blocked); e != nil || blocked != 1 {
		t.Fatal(blocked, e)
	}
}
