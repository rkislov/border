package aaa

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2868"
)

func TestDynamicAuthorization(t *testing.T) {
	for _, mode := range []string{"disconnect", "vlan", "nak", "invalid-ma", "wrong-id", "stale-time", "bad-authenticator"} {
		t.Run(mode, func(t *testing.T) {
			s := database(t)
			ctx := t.Context()
			conn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err = s.Exec(ctx, "UPDATE nas SET coa_port=? WHERE address='127.0.0.1'", conn.LocalAddr().(*net.UDPAddr).Port); err != nil {
				t.Fatal(err)
			}
			if err = s.Accounting(ctx, "127.0.0.1", "session-1", "aa:bb:cc:dd:ee:ff", "user", "active"); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				var b [4096]byte
				n, remote, err := conn.ReadFrom(b[:])
				if err != nil {
					t.Error(err)
					return
				}
				raw := append([]byte(nil), b[:n]...)
				if !radius.IsAuthenticRequest(raw, []byte(testSecret)) {
					t.Error("invalid request authenticator")
					return
				}
				maInput := append([]byte(nil), raw...)
				clear(maInput[4:20])
				if !VerifyMessageAuthenticator(maInput, []byte(testSecret)) {
					t.Error("invalid request MA")
					return
				}
				p, err := radius.Parse(raw, []byte(testSecret))
				if err != nil {
					t.Error(err)
					return
				}
				if rfc2866.AcctSessionID_GetString(p) != "session-1" {
					t.Error("missing session selector")
					return
				}
				code := radius.CodeDisconnectACK
				if mode == "vlan" {
					if p.Code != radius.CodeCoARequest {
						t.Error("not CoA")
						return
					}
					_, vlan := rfc2868.TunnelPrivateGroupID_GetString(p)
					if vlan != "200" {
						t.Error("wrong VLAN")
						return
					}
					code = radius.CodeCoAACK
				} else if p.Code != radius.CodeDisconnectRequest {
					t.Error("not Disconnect")
					return
				}
				if len(p.Attributes.Get(55)) != 4 {
					t.Error("missing replay timestamp")
					return
				}
				if mode == "nak" {
					code = radius.CodeDisconnectNAK
				}
				reply := p.Response(code)
				if mode == "nak" {
					reply.Attributes.Add(101, []byte{0, 0, 1, 247})
				}
				if mode == "wrong-id" {
					reply.Identifier++
				}
				if mode == "stale-time" {
					ts := make([]byte, 4)
					binary.BigEndian.PutUint32(ts, uint32(time.Now().Add(-time.Hour).Unix()))
					reply.Attributes.Add(55, ts)
				}
				if err = SignMessageAuthenticator(reply); err != nil {
					t.Error(err)
					return
				}
				if mode == "invalid-ma" {
					reply.Attributes.Set(80, make([]byte, 16))
				}
				encoded, err := reply.Encode()
				if err != nil {
					t.Error(err)
					return
				}
				if mode == "bad-authenticator" {
					encoded[4] ^= 1
				}
				_, err = conn.WriteTo(encoded, remote)
				if err != nil {
					t.Error(err)
				}
			}()
			action := "disconnect"
			if mode == "vlan" {
				action = "vlan"
			}
			runCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer cancel()
			result, err := ChangeSession(runCtx, s, "127.0.0.1", "session-1", action, 200)
			<-done
			switch mode {
			case "disconnect", "vlan":
				if err != nil || !result.Acknowledged {
					t.Fatalf("%+v %v", result, err)
				}
			case "nak":
				if err != nil || result.Acknowledged || result.ErrorCause != 503 {
					t.Fatalf("%+v %v", result, err)
				}
			default:
				if err == nil {
					t.Fatal("accepted invalid NAS response")
				}
			}
			sessions, err := s.Sessions(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if (sessions[0].Status == "disconnect-ack") != (mode == "disconnect") {
				t.Fatal("session status changed without Disconnect-ACK")
			}
		})
	}
}
func TestDynamicAuthorizationValidation(t *testing.T) {
	s := database(t)
	for _, v := range []struct {
		nas, id, action string
		vlan            int
	}{{"127.0.0.1", "", "disconnect", 0}, {"127.0.0.1", "unknown", "disconnect", 0}, {"192.0.2.9", "unknown", "disconnect", 0}, {"127.0.0.1", "x", "invalid", 0}} {
		if _, err := ChangeSession(t.Context(), s, v.nas, v.id, v.action, v.vlan); err == nil {
			t.Fatal("invalid session action accepted")
		}
	}
	if err := s.Accounting(t.Context(), "127.0.0.1", "known", "", "user", "active"); err != nil {
		t.Fatal(err)
	}
	if _, err := ChangeSession(t.Context(), s, "127.0.0.1", "known", "disconnect", 0, store.Session{Username: "stale"}); err == nil {
		t.Fatal("stale session snapshot accepted")
	}
	for _, vlan := range []int{0, 4095, 123} {
		if _, err := ChangeSession(t.Context(), s, "127.0.0.1", "known", "vlan", vlan); err == nil {
			t.Fatal("invalid VLAN accepted")
		}
	}
}
