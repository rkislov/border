package aaa

import (
	"github.com/pquerna/otp/totp"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/directory"
	"github.com/rkislov/border/internal/identitysource"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2868"
	"testing"
	"time"
)

func TestBoundLocalMFAValidityLocationAndNoFallback(t *testing.T) {
	s := database(t)
	ctx := t.Context()
	codes, e := auth.New(s, make([]byte, 32), nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	identities := &identitysource.Service{Store: s, Vault: codes.Vault}
	if e = identities.SaveLocal(ctx, identitysource.LocalUser{Username: "alice", Password: "test-password-12345", Enabled: true}); e != nil {
		t.Fatal(e)
	}
	codes.Register(ctx, directory.Identity{Username: "local/alice"})
	secret, _, e := codes.Enrollment(ctx, "local/alice")
	if e != nil {
		t.Fatal(e)
	}
	otp, _ := totp.GenerateCode(secret, time.Now())
	if _, e = codes.Confirm(ctx, "local/alice", otp); e != nil {
		t.Fatal(e)
	}
	// Enrollment consumes this time step; allow a fresh network verification in the test.
	s.Exec(ctx, "UPDATE identities SET last_step=0 WHERE username='local/alice'")
	if e = s.SaveAuthentication(ctx, store.AuthenticationPolicy{ID: "password-otp", Name: "MFA", Source: "local", RequireTOTP: true, Enabled: true}); e != nil {
		t.Fatal(e)
	}
	s.Exec(ctx, "INSERT INTO locations VALUES('office','Office')")
	s.Exec(ctx, "INSERT INTO network_segments VALUES('staff','Staff')")
	s.SaveMapping(ctx, store.SegmentMapping{LocationID: "office", SegmentID: "staff", VLAN: 120})
	policy := store.AccessPolicy{ID: "staff-access", Name: "Staff", AuthenticationID: "password-otp", Mode: "network", SegmentID: "staff", SessionSeconds: 3600, IdleSeconds: 60, ValidUntil: time.Now().Unix() + 120, Enabled: true, Subjects: []string{"local/alice"}}
	if e = s.SaveAccess(ctx, policy); e != nil {
		t.Fatal(e)
	}
	if e = s.Exec(ctx, "UPDATE nas SET location_id='office',access_policy_id='staff-access'"); e != nil {
		t.Fatal(e)
	}
	call := func(password string) *radius.Packet {
		p := request(t, "aa:bb:cc:dd:ee:ff")
		rfc2865.UserName_SetString(p, "alice")
		if password != "" {
			rfc2865.UserPassword_SetString(p, password)
		}
		raw, e := ProcessWithOptions(ctx, s, wire(t, p), source(), false, Options{Network: codes, Identities: identities, TOTP: codes})
		if e != nil {
			t.Fatal(e)
		}
		out, e := radius.Parse(raw, []byte(testSecret))
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	if call("test-password-12345").Code != radius.CodeAccessReject {
		t.Fatal("password alone bypassed MFA")
	}
	if call("wrong;otp="+otp).Code != radius.CodeAccessReject {
		t.Fatal("wrong password")
	}
	out := call("test-password-12345;otp=" + otp)
	if out.Code != radius.CodeAccessAccept {
		t.Fatal("MFA rejected")
	}
	_, vlan := rfc2868.TunnelPrivateGroupID_GetString(out)
	if vlan != "120" {
		t.Fatal("location VLAN", vlan)
	}
	if ttl := rfc2865.SessionTimeout_Get(out); ttl > 120 || ttl == 0 {
		t.Fatal("policy expiry not applied", ttl)
	}
	if call("test-password-12345;otp="+otp).Code != radius.CodeAccessReject {
		t.Fatal("OTP replay")
	}
	if call("").Code != radius.CodeAccessReject {
		t.Fatal("MAB fallback")
	}
	s.Exec(ctx, "UPDATE identities SET last_step=0 WHERE username='local/alice'")
	s.SaveMapping(ctx, store.SegmentMapping{NAS: "127.0.0.1", SegmentID: "staff", VLAN: 220})
	out = call("test-password-12345;otp=" + otp)
	_, vlan = rfc2868.TunnelPrivateGroupID_GetString(out)
	if out.Code != radius.CodeAccessAccept || vlan != "220" {
		t.Fatal("NAS VLAN override", vlan)
	}
	policy.ValidUntil = time.Now().Unix() - 1
	if e = s.SaveAccess(ctx, policy); e != nil {
		t.Fatal(e)
	}
	if call("test-password-12345;otp="+otp).Code != radius.CodeAccessReject {
		t.Fatal("expired policy allowed")
	}
}
