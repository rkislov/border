package aaa

import (
	"context"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/identitysource"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"testing"
)

type chainTOTP struct {
	calls int
	valid bool
}

func (v *chainTOTP) VerifyTOTP(context.Context, string, string) (bool, error) {
	v.calls++
	return v.valid, nil
}
func TestMandatoryChainNoDowngradeAndMultipleModes(t *testing.T) {
	s := database(t)
	ctx := t.Context()
	codes, _ := auth.New(s, make([]byte, 32), nil, 0)
	identities := &identitysource.Service{Store: s, Vault: codes.Vault}
	if e := identities.SaveLocal(ctx, identitysource.LocalUser{Username: "alice", Password: "test-password-12345", Enabled: true}); e != nil {
		t.Fatal(e)
	}
	for _, a := range []store.AuthenticationPolicy{{ID: "strict", Name: "Strict", Source: "local", Steps: []string{"device", "primary", "totp"}, Enabled: true}, {ID: "weak", Name: "Weak", Source: "local", Enabled: true}} {
		if e := s.SaveAuthentication(ctx, a); e != nil {
			t.Fatal(e)
		}
	}
	for _, a := range []store.AccessPolicy{{ID: "strict", Name: "Strict", AuthenticationID: "strict", Mode: "ssh", Enabled: true, SessionSeconds: 3600, Subjects: []string{"local/alice"}}, {ID: "weak", Name: "Weak", AuthenticationID: "weak", Mode: "vpn", Enabled: true, SessionSeconds: 600, Subjects: []string{"local/alice"}}} {
		if e := s.SaveAccess(ctx, a); e != nil {
			t.Fatal(e)
		}
	}
	set := store.NASPolicySet{NAS: "127.0.0.1", Enabled: true, Bindings: []store.PolicyBinding{{ID: "strict", PolicyID: "strict", Protocol: "pap", ServiceType: 1, Priority: 10, Enabled: true}, {ID: "weak", PolicyID: "weak", Protocol: "pap", Priority: 100, Enabled: true}}}
	if e := s.SaveNASPolicies(ctx, set); e != nil {
		t.Fatal(e)
	}
	factor := &chainTOTP{valid: true}
	call := func(password string, service byte) radius.Code {
		t.Helper()
		p := request(t, "aa:bb:cc:dd:ee:ff")
		rfc2865.UserName_SetString(p, "alice")
		rfc2865.UserPassword_SetString(p, password)
		p.Attributes.Add(6, []byte{0, 0, 0, service})
		raw, e := ProcessWithOptions(ctx, s, wire(t, p), source(), false, Options{Identities: identities, TOTP: factor})
		if e != nil {
			t.Fatal(e)
		}
		out, e := radius.Parse(raw, []byte(testSecret))
		if e != nil {
			t.Fatal(e)
		}
		return out.Code
	}
	if e := s.Exec(ctx, "DELETE FROM mac_auth"); e != nil {
		t.Fatal(e)
	}
	if call("test-password-12345;otp=123456", 1) != radius.CodeAccessReject || factor.calls != 0 {
		t.Fatal("device failure bypassed or consumed OTP")
	}
	if e := s.Exec(ctx, "INSERT INTO mac_auth(mac,active) VALUES('aa:bb:cc:dd:ee:ff',1)"); e != nil {
		t.Fatal(e)
	}
	if call("wrong-password;otp=123456", 1) != radius.CodeAccessReject || factor.calls != 0 {
		t.Fatal("password failure consumed OTP")
	}
	if call("test-password-12345", 1) != radius.CodeAccessReject || factor.calls != 0 {
		t.Fatal("missing OTP accepted or consumed")
	}
	if call("test-password-12345;otp=abcdef", 1) != radius.CodeAccessReject || factor.calls != 0 {
		t.Fatal("invalid OTP format passed to verifier")
	}
	factor.valid = false
	if call("test-password-12345;otp=123456", 1) != radius.CodeAccessReject {
		t.Fatal("failed MFA fell through to weak policy")
	}
	factor.valid = true
	if call("test-password-12345;otp=123456", 1) != radius.CodeAccessAccept {
		t.Fatal("complete chain rejected")
	}
	// Same NAS, different service selector and access mode.
	if call("test-password-12345", 2) != radius.CodeAccessAccept {
		t.Fatal("second policy rejected")
	}
}
