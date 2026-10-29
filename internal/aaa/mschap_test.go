package aaa

import (
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/identitysource"
	"github.com/rkislov/border/internal/mschap"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"testing"
	"time"
)

func TestMSCHAPPolicy(t *testing.T) {
	s := database(t)
	ctx := t.Context()
	v, _ := auth.NewVault(make([]byte, 32))
	ids := &identitysource.Service{Store: s, Vault: v}
	yes := true
	u := identitysource.LocalUser{Username: "alice", Password: "test-password-123", Enabled: true, MSCHAPEnabled: &yes}
	if e := ids.SaveLocal(ctx, u); e != nil {
		t.Fatal(e)
	}
	a := store.AuthenticationPolicy{ID: "local", Name: "Local", Source: "local", Enabled: true}
	if e := s.SaveAuthentication(ctx, a); e != nil {
		t.Fatal(e)
	}
	b := store.AccessPolicy{ID: "ssh", Name: "SSH", AuthenticationID: "local", Mode: "ssh", Group: "read", Enabled: true, SessionSeconds: 600, Subjects: []string{"local/alice"}}
	if e := s.SaveAccess(ctx, b); e != nil {
		t.Fatal(e)
	}
	if e := s.Exec(ctx, "UPDATE nas SET access_policy_id='ssh',access_mode='ssh',dictionary='mikrotik'"); e != nil {
		t.Fatal(e)
	}
	call := func(password string) radius.Code {
		p := request(t, "aa:bb:cc:dd:ee:ff")
		rfc2865.UserName_SetString(p, "alice")
		p.Attributes.Del(2)
		challenge, peer := make([]byte, 16), make([]byte, 16)
		response := append([]byte{7, 0}, peer...)
		response = append(response, make([]byte, 8)...)
		response = append(response, mschap.NTResponse(mschap.PasswordHash(password), challenge, peer, "alice")...)
		for typ, val := range map[byte][]byte{11: challenge, 25: response} {
			attr, _ := radius.NewVendorSpecific(311, append([]byte{typ, byte(len(val) + 2)}, val...))
			p.Attributes.Add(26, attr)
		}
		raw, e := ProcessWithOptions(ctx, s, wire(t, p), source(), false, Options{Identities: ids})
		if e != nil {
			t.Fatal(e)
		}
		out, e := radius.Parse(raw, []byte(testSecret))
		if e != nil {
			t.Fatal(e)
		}
		return out.Code
	}
	if call(u.Password) != radius.CodeAccessAccept {
		t.Fatal("valid credentials rejected")
	}
	if call("wrong") != radius.CodeAccessReject {
		t.Fatal("wrong password accepted")
	}
	a.RequireTOTP = true
	if e := s.SaveAuthentication(ctx, a); e != nil {
		t.Fatal(e)
	}
	if call(u.Password) != radius.CodeAccessReject {
		t.Fatal("TOTP bypass")
	}
	a.RequireTOTP = false
	if e := s.SaveAuthentication(ctx, a); e != nil {
		t.Fatal(e)
	}
	b.ValidUntil = time.Now().Unix() - 1
	if e := s.SaveAccess(ctx, b); e != nil {
		t.Fatal(e)
	}
	if call(u.Password) != radius.CodeAccessReject {
		t.Fatal("expired policy accepted")
	}
	b.ValidUntil = 0
	s.SaveAccess(ctx, b)
	u.Enabled = false
	u.Password = ""
	ids.SaveLocal(ctx, u)
	if call("test-password-123") != radius.CodeAccessReject {
		t.Fatal("blocked user accepted")
	}
}
