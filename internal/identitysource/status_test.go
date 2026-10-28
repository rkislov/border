package identitysource

import (
	"fmt"
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

func TestMissingAccountRequiresAllServersAndOptIn(t *testing.T) {
	for _, tc := range []struct {
		opt            bool
		missing, total int
		known          bool
	}{
		{false, 2, 2, false}, {true, 2, 2, true}, {true, 1, 2, false}, {true, 0, 2, false}, {true, 0, 0, false},
	} {
		enabled, err := missingAccountResult(tc.opt, tc.missing, tc.total, fmt.Errorf("search failed"))
		if enabled || (err == nil) != tc.known {
			t.Fatal(tc, enabled, err)
		}
	}
}

func TestRemovedLocalAccountRevokesGrant(t *testing.T) {
	s, e := store.Open("sqlite", filepath.Join(t.TempDir(), "deleted.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	ctx := t.Context()
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	token, e := s.NewAccessGrant(ctx, "192.0.2.1", "local/deleted", "", time.Now().Unix()+3600)
	if e != nil {
		t.Fatal(e)
	}
	service := &Service{Store: s}
	if e = service.SyncAccountStatus(ctx); e != nil {
		t.Fatal(e)
	}
	var reason string
	if e = s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason); e != nil || reason == "" {
		t.Fatal(reason, e)
	}
}
