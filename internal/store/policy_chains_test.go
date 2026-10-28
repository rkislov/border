package store

import (
	"testing"
	"time"
)

func TestChainValidation(t *testing.T) {
	for _, tc := range []struct {
		source string
		steps  []string
		ok     bool
	}{
		{"local", []string{"device", "primary", "totp"}, true},
		{"directory", []string{"primary", "totp", "device"}, true},
		{"eap_tls", []string{"primary", "device"}, true},
		{"eap_tls", []string{"device", "primary"}, false},
		{"local", []string{"totp", "primary"}, false},
		{"local", []string{"device"}, false},
		{"codes", []string{"primary", "totp"}, false},
		{"mab", []string{"device", "primary"}, false},
		{"local", []string{"primary", "primary"}, false},
	} {
		if e := (AuthenticationPolicy{Source: tc.source, Steps: tc.steps}).ValidateChain(); (e == nil) != tc.ok {
			t.Fatal(tc, e)
		}
	}
}
func TestNASPoliciesPriorityCASAndRevocation(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	if e := s.Exec(ctx, "INSERT INTO nas(address,name,secret) VALUES('192.0.2.1','NAS','secret')"); e != nil {
		t.Fatal(e)
	}
	set := NASPolicySet{NAS: "192.0.2.1", Enabled: true, Bindings: []PolicyBinding{{ID: "fallback", PolicyID: "access", Priority: 200, Protocol: "pap", Enabled: true}, {ID: "local", PolicyID: "access", Priority: 10, Protocol: "pap", IdentitySource: "local", SSID: "Corp", Enabled: true}}}
	if e := s.SaveNASPolicies(ctx, set); e != nil {
		t.Fatal(e)
	}
	if e := s.SaveNASPolicies(ctx, set); e == nil {
		t.Fatal("stale save accepted")
	}
	b, configured, e := s.SelectPolicy(ctx, set.NAS, PolicyRequest{Protocol: "pap", Username: "local/alice", SSID: "Corp"})
	if e != nil || !configured || b.BindingID != "local" {
		t.Fatal(b, configured, e)
	}
	token, e := s.NewPolicyGrant(ctx, set.NAS, "local/alice", b, time.Now().Unix()+3600)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.RefreshRevocations(ctx); e != nil {
		t.Fatal(e)
	}
	var reason string
	if e = s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason); e != nil || reason != "" {
		t.Fatal(reason, e)
	}
	b, _, e = s.SelectPolicy(ctx, set.NAS, PolicyRequest{Protocol: "pap", Username: "alice"})
	if e != nil || b.BindingID != "fallback" {
		t.Fatal(b, e)
	}
	b, configured, e = s.SelectPolicy(ctx, set.NAS, PolicyRequest{Protocol: "eap"})
	if e != nil || !configured || b != nil {
		t.Fatal("unexpected fallback", b, e)
	}
	set.Version = 1
	set.Bindings = nil
	if e = s.SaveNASPolicies(ctx, set); e != nil {
		t.Fatal(e)
	}
	if e = s.RefreshRevocations(ctx); e != nil {
		t.Fatal(e)
	}
	if e = s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason); e != nil || reason == "" {
		t.Fatal("old grant not revoked", e)
	}
	b, configured, e = s.SelectPolicy(ctx, set.NAS, PolicyRequest{Protocol: "pap"})
	if e != nil || b != nil || !configured {
		t.Fatal("empty enabled set must deny")
	}
}
