package store

import (
	"reflect"
	"testing"
)

func TestPolicyDiagnosticMatchesLiveSelection(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	if err := s.Exec(ctx, "INSERT INTO nas(address,name,secret) VALUES('192.0.2.1','NAS','secret')"); err != nil {
		t.Fatal(err)
	}
	zero := 0
	set := NASPolicySet{NAS: "192.0.2.1", Enabled: true, Bindings: []PolicyBinding{
		{ID: "disabled", PolicyID: "access", Priority: 1, Protocol: "pap"},
		{ID: "corp", PolicyID: "access", Priority: 2, Protocol: "pap", SSID: "Corp", IdentitySource: "local", NASPortType: &zero, Enabled: true},
		{ID: "fallback", PolicyID: "access", Priority: 3, Protocol: "pap", Enabled: true},
	}}
	if err := s.SaveNASPolicies(ctx, set); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		request PolicyRequest
		binding string
		reason  string
	}{
		{PolicyRequest{Protocol: "pap", Username: "local/alice", SSID: "Corp", NASPortType: &zero}, "corp", "selected"},
		{PolicyRequest{Protocol: "pap", Username: "local/alice", SSID: "Corp"}, "fallback", "nas_port_type"},
		{PolicyRequest{Protocol: "pap", Username: "alice", SSID: "Corp", NASPortType: &zero}, "fallback", "identity_source"},
		{PolicyRequest{Protocol: "pap", Username: "local/alice", SSID: "Guest"}, "fallback", "ssid"},
		{PolicyRequest{Protocol: "eap"}, "", "protocol"},
	} {
		p, c, trace, err := s.ExplainPolicy(ctx, set.NAS, tc.request)
		live, configured, e := s.SelectPolicy(ctx, set.NAS, tc.request)
		if err != nil || e != nil || c != configured || !reflect.DeepEqual(p, live) {
			t.Fatal(p, live, err, e)
		}
		if trace[0].Reason != "disabled" || trace[1].Reason != tc.reason {
			t.Fatal(trace)
		}
		if tc.binding == "" {
			if p != nil {
				t.Fatal(p)
			}
		} else if p == nil || p.BindingID != tc.binding || trace[len(trace)-1].ID != tc.binding {
			t.Fatal(p, trace)
		}
	}
	// An invalid selected policy must not fall through to another binding.
	if err := s.Exec(ctx, "UPDATE access_policies SET mode='network',segment_id=NULL WHERE id='access'"); err != nil {
		t.Fatal(err)
	}
	_, _, trace, err := s.ExplainPolicy(ctx, set.NAS, PolicyRequest{Protocol: "pap", Username: "local/alice", SSID: "Corp", NASPortType: &zero})
	if err == nil || trace[len(trace)-1].ID != "corp" {
		t.Fatal(trace, err)
	}
	var grants int
	if err = s.Row(ctx, "SELECT COUNT(*) FROM access_grants").Scan(&grants); err != nil || grants != 0 {
		t.Fatal("diagnostic wrote grant", err, grants)
	}
}
