package aaa

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2868"
)

func TestOIDCRADIUSPolicyAccountingAndRevocation(t *testing.T) {
	checkGuestRADIUSRevocation(t, "oidc", "oidc", "blocked")
}

func TestUnifiedGuestRADIUSDisconnect(t *testing.T) {
	for _, method := range []string{"sms", "email", "oidc"} {
		for _, cause := range []string{"blocked", "expired"} {
			t.Run(method+"/"+cause, func(t *testing.T) { checkGuestRADIUSRevocation(t, "guest", method, cause) })
		}
	}
}

func checkGuestRADIUSRevocation(t *testing.T, authSource, method, cause string) {
	t.Helper()
	s := database(t)
	ctx := t.Context()
	mac := "02:00:00:00:00:01"
	user := "oidc:" + strings.Repeat("a", 64)
	if method != "oidc" {
		user = "guest-" + method + ":" + strings.Repeat("a", 64)
	}
	for _, q := range []string{
		"INSERT INTO locations VALUES('office','Office')",
		"INSERT INTO network_segments VALUES('guest','Guest')",
		"INSERT INTO location_segments VALUES('office','guest',200)",
		"UPDATE nas SET location_id='office',portal_enabled=1",
		"UPDATE guest_policy SET enabled=1,vlan=100",
	} {
		if e := s.Exec(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	auth := store.AuthenticationPolicy{ID: "oidc", Name: "Guest portal", Source: authSource, Enabled: true}
	if authSource == "guest" {
		auth.GuestMethods = []string{"sms", "email", "oidc"}
	}
	if e := s.SaveAuthentication(ctx, auth); e != nil {
		t.Fatal(e)
	}
	if e := s.SaveAccess(ctx, store.AccessPolicy{ID: "guest", Name: "Guest", AuthenticationID: "oidc", Mode: "network", SegmentID: "guest", SessionSeconds: 600, Enabled: true, Subjects: []string{user}}); e != nil {
		t.Fatal(e)
	}
	if e := s.SaveNASPolicies(ctx, store.NASPolicySet{NAS: "127.0.0.1", Enabled: true, Bindings: []store.PolicyBinding{{ID: "guest", PolicyID: "guest", Protocol: "mab", Enabled: true}}}); e != nil {
		t.Fatal(e)
	}
	d := store.DefaultPortalDesign()
	d.Custom = true
	d.LoginMethod = "both"
	d.SSOEnabled = true
	d.SSOProviders = []string{"oidc"}
	if e := s.SavePortalDesign(ctx, "tenant", d); e != nil {
		t.Fatal(e)
	}
	c := store.OIDCProvider{Scope: "tenant", ID: "oidc", Name: "SSO", Issuer: "https://sso.example", ClientID: "border", Enabled: true, AccessPolicyID: "guest", Revision: "rev1"}
	raw, _ := json.Marshal(c)
	if e := s.Exec(ctx, "INSERT INTO guest_oidc_providers(scope,id,config,revision) VALUES('tenant','oidc',?,'rev1')", string(raw)); e != nil {
		t.Fatal(e)
	}
	b, e := s.GuestAccessPolicy(ctx, "127.0.0.1", mac, "", method)
	if e != nil {
		t.Fatal(e)
	}
	call := func() *radius.Packet {
		t.Helper()
		p := request(t, mac)
		rfc2865.UserName_SetString(p, mac)
		wireReply, e := ProcessWithOptions(ctx, s, wire(t, p), source(), false, Options{})
		if e != nil {
			t.Fatal(e)
		}
		reply, e := radius.Parse(wireReply, []byte(testSecret))
		if e != nil {
			t.Fatal(e)
		}
		return reply
	}
	if call().Code != radius.CodeAccessReject {
		t.Fatal("no OIDC grant accepted")
	}
	if e = s.Exec(ctx, "INSERT INTO guest_authorizations(id,nas,mac,identity,method,provider_scope,provider_id,provider_revision,policy_id,policy_hash,expires_at) VALUES('guest-id','127.0.0.1',?,?,?,'tenant','oidc','rev1','guest',?,?)", mac, user, method, store.GuestPolicyHash(b), time.Now().Unix()+90); e != nil {
		t.Fatal(e)
	}
	reply := call()
	_, vlan := rfc2868.TunnelPrivateGroupID_GetString(reply)
	if reply.Code != radius.CodeAccessAccept || vlan != "200" || rfc2865.SessionTimeout_Get(reply) > 90 {
		t.Fatalf("reply %+v vlan %s", reply, vlan)
	}
	token := string(reply.Attributes.Get(25))
	var actual, policy, guestID string
	if e = s.Row(ctx, "SELECT username,policy_id,guest_authorization_id FROM access_grants WHERE token=?", token).Scan(&actual, &policy, &guestID); e != nil || actual != user || policy != "guest" || guestID != "guest-id" {
		t.Fatal("Class not bound to OIDC identity", e)
	}
	if e = s.ApplyAccounting(ctx, store.AccountingEvent{NAS: "127.0.0.1", ID: "guest-session", MAC: mac, Username: mac, Kind: "start", At: time.Now().Unix(), Classes: []string{token}}); e != nil {
		t.Fatal(e)
	}
	var linked string
	if e = s.Row(ctx, "SELECT grant_token FROM sessions WHERE session_id='guest-session'").Scan(&linked); e != nil || linked != token {
		t.Fatal("accounting link missing", e)
	}
	// Both identity blocking and policy expiry deny new requests and retire Class.
	if cause == "blocked" {
		e = s.Exec(ctx, "INSERT INTO identity_status(username,blocked,checked_at) VALUES(?,1,0)", user)
	} else {
		e = s.Exec(ctx, "UPDATE access_policies SET valid_until=? WHERE id='guest'", time.Now().Unix()-1)
	}
	if e != nil {
		t.Fatal(e)
	}
	if call().Code != radius.CodeAccessReject {
		t.Fatal("blocked OIDC identity accepted")
	}
	if e = s.RefreshRevocations(ctx); e != nil {
		t.Fatal(e)
	}
	var reason string
	if e = s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason); e != nil || reason == "" {
		t.Fatal("no revocation", e)
	}
	conn, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if e = s.Exec(ctx, "UPDATE nas SET coa_port=? WHERE address='127.0.0.1'", conn.LocalAddr().(*net.UDPAddr).Port); e != nil {
		t.Fatal(e)
	}
	for _, code := range []radius.Code{radius.CodeDisconnectNAK, radius.CodeDisconnectACK} {
		done := make(chan error, 1)
		go func() {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			var buf [4096]byte
			n, remote, err := conn.ReadFrom(buf[:])
			if err != nil {
				done <- err
				return
			}
			p, err := radius.Parse(buf[:n], []byte(testSecret))
			if err != nil {
				done <- err
				return
			}
			if p.Code != radius.CodeDisconnectRequest || rfc2866.AcctSessionID_GetString(p) != "guest-session" || rfc2865.UserName_GetString(p) != mac {
				done <- fmt.Errorf("disconnect targets wrong guest session")
				return
			}
			wire, err := p.Response(code).Encode()
			if err == nil {
				_, err = conn.WriteTo(wire, remote)
			}
			done <- err
		}()
		if e = RevokeSessions(ctx, s); e != nil {
			t.Fatal(e)
		}
		if e = <-done; e != nil {
			t.Fatal(e)
		}
		var status string
		if e = s.Row(ctx, "SELECT status FROM sessions WHERE session_id='guest-session'").Scan(&status); e != nil {
			t.Fatal(e)
		}
		expected := "active"
		if code == radius.CodeDisconnectACK {
			expected = "disconnect-ack"
		}
		if status != expected {
			t.Fatalf("reply %v: status %s, want %s", code, status, expected)
		}
		if e = s.Exec(ctx, "UPDATE sessions SET revoke_next=0 WHERE grant_token=?", token); e != nil {
			t.Fatal(e)
		}
	}
}
