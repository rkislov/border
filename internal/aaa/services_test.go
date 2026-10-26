package aaa

import (
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"testing"
)

func TestServiceRequiresExplicitGrantAndNeverFallsBack(t *testing.T) {
	for _, mode := range []string{"ssh", "vpn"} {
		t.Run(mode, func(t *testing.T) {
			s := database(t)
			ctx := t.Context()
			if err := s.Exec(ctx, "UPDATE nas SET access_mode=?,dictionary='cisco'", mode); err != nil {
				t.Fatal(err)
			}
			v := &testNetworkVerifier{}
			call := func(password string, pap bool) *radius.Packet {
				p := request(t, "aa:bb:cc:dd:ee:ff")
				rfc2865.UserName_SetString(p, "user")
				if pap {
					rfc2865.UserPassword_SetString(p, password)
				}
				raw, err := ProcessAuthenticated(ctx, s, wire(t, p), source(), false, v)
				if err != nil {
					t.Fatal(err)
				}
				out, err := radius.Parse(raw, []byte(testSecret))
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			if call("12345678", true).Code != radius.CodeAccessReject || v.calls != 0 {
				t.Fatal("missing grant accepted or consumed code")
			}
			if err := s.Exec(ctx, "INSERT INTO nas_grants(nas,username,mode,privilege) VALUES('127.0.0.1','user',?,3)", mode); err != nil {
				t.Fatal(err)
			}
			if call("", false).Code != radius.CodeAccessReject {
				t.Fatal("MAB service bypass")
			}
			if call("bad", true).Code != radius.CodeAccessReject {
				t.Fatal("bad password")
			}
			out := call("12345678", true)
			if out.Code != radius.CodeAccessAccept {
				t.Fatal("grant rejected")
			}
			if len(out.Attributes.Get(81)) > 0 {
				t.Fatal("network VLAN leaked to service")
			}
			if mode == "ssh" && len(out.Attributes.Get(26)) == 0 {
				t.Fatal("missing Cisco privilege")
			}
			if mode == "vpn" && rfc2865.ServiceType_Get(out) != 2 {
				t.Fatal("missing framed service")
			}
		})
	}
}
