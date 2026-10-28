package store

import (
	"testing"
	"time"
)

func TestRevocationIsolationAndExpiry(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	if e := s.Exec(ctx, "INSERT INTO local_users(username,email,password_hash,enabled) VALUES('alice','','',0),('bob','','',1)"); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		user, policy string
		expiry       int64
		revoked      bool
	}{
		{"local/alice", "access", time.Now().Unix() + 100, true},
		{"local/bob", "access", time.Now().Unix() + 100, false},
		{"local/bob", "access", time.Now().Unix() - 1, true},
		{"local/bob", "deleted", time.Now().Unix() + 100, true},
	} {
		token, e := s.NewAccessGrant(ctx, "192.0.2.1", tc.user, tc.policy, tc.expiry)
		if e != nil {
			t.Fatal(e)
		}
		if e = s.RefreshRevocations(ctx); e != nil {
			t.Fatal(e)
		}
		var reason string
		if e = s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason); e != nil {
			t.Fatal(e)
		}
		if (reason != "") != tc.revoked {
			t.Fatalf("%+v reason %q", tc, reason)
		}
	}
}
func TestAccountingDoesNotReuseOldGrant(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	token, e := s.NewAccessGrant(ctx, "192.0.2.1", "local/alice", "access", time.Now().Unix()+100)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ nas, token, want string }{{"192.0.2.1", token, token}, {"192.0.2.1", "", token}, {"192.0.2.2", token, ""}} {
		if e = s.Accounting(ctx, tc.nas, "same-id", "", "alice", "active", tc.token); e != nil {
			t.Fatal(e)
		}
		var got string
		if e = s.Row(ctx, "SELECT grant_token FROM sessions WHERE nas=? AND session_id='same-id'", tc.nas).Scan(&got); e != nil {
			t.Fatal(e)
		}
		if got != tc.want {
			t.Fatal("wrong grant association")
		}
	}
}
func TestPolicyShorteningAndRevocationLatch(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	token, e := s.NewAccessGrant(ctx, "192.0.2.1", "user", "access", time.Now().Unix()+3600)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Exec(ctx, "UPDATE access_policies SET valid_until=? WHERE id='access'", time.Now().Unix()-1); e != nil {
		t.Fatal(e)
	}
	if e = s.RefreshRevocations(ctx); e != nil {
		t.Fatal(e)
	}
	if e = s.Exec(ctx, "UPDATE access_policies SET valid_until=0 WHERE id='access'"); e != nil {
		t.Fatal(e)
	}
	if e = s.RefreshRevocations(ctx); e != nil {
		t.Fatal(e)
	}
	var reason string
	if e = s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason); e != nil {
		t.Fatal(e)
	}
	if reason == "" {
		t.Fatal("expired grant restored")
	}
}
func TestGrantCanonicalIdentity(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	token, e := s.NewAccessGrant(ctx, "192.0.2.1", "local/ALICE", "access", 9999999999)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.RevokeIdentity(ctx, "local/alice"); e != nil {
		t.Fatal(e)
	}
	var reason string
	if e = s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason); e != nil || reason == "" {
		t.Fatal(reason, e)
	}
}
