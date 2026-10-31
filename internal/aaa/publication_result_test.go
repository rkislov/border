package aaa

import (
	"context"
	"encoding/json"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"net"
	"testing"
	"time"
)

func TestPublicationRevocationEndToEnd(t *testing.T) {
	for _, mode := range []string{"automatic", "manual", "fallback", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			s := database(t)
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			conn, e := net.ListenPacket("udp", "127.0.0.1:0")
			must(e)
			defer conn.Close()
			must(s.Exec(ctx, "UPDATE nas SET coa_port=? WHERE address='127.0.0.1'", conn.LocalAddr().(*net.UDPAddr).Port))
			must(s.SaveAuthentication(ctx, store.AuthenticationPolicy{ID: "pub-auth", Name: "Auth", Source: "local", Enabled: true}))
			p := store.AccessPolicy{ID: "pub-vpn", Name: "VPN", AuthenticationID: "pub-auth", Mode: "vpn", Enabled: true, SessionSeconds: 3600}
			must(s.SaveAccess(ctx, p))
			token, e := s.NewAccessGrant(ctx, "127.0.0.1", "local/user", p.ID, time.Now().Unix()+3600)
			must(e)
			must(s.Accounting(ctx, "127.0.0.1", "published-session", "", "user", "active", token))
			p.Name = "Published VPN"
			raw, _ := json.Marshal(p)
			must(s.SavePolicyDraft(ctx, store.PolicyDraft{Kind: "access", PolicyID: p.ID, Payload: raw}, "admin"))
			must(s.PublishPolicyDraft(ctx, "access", p.ID, 1, "admin"))
			page, e := s.ChangeJournal(ctx, "", "", "published", 0, 1)
			must(e)
			batch := page.Items[0].BatchID
			done := make(chan error, 1)
			go func() {
				_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
				var b [4096]byte
				n, remote, e := conn.ReadFrom(b[:])
				if e != nil {
					done <- e
					return
				}
				if mode == "timeout" {
					done <- nil
					return
				}
				packet, e := radius.Parse(b[:n], []byte(testSecret))
				if e != nil {
					done <- e
					return
				}
				code := radius.CodeDisconnectACK
				if mode == "fallback" {
					code = radius.CodeDisconnectNAK
				}
				reply := packet.Response(code)
				if mode == "fallback" {
					reply.Attributes.Add(101, []byte{0, 0, 1, 150})
				}
				wire, e := reply.Encode()
				if e == nil {
					_, e = conn.WriteTo(wire, remote)
				}
				done <- e
			}()
			if mode == "automatic" {
				must(RevokeSessions(ctx, s))
			} else {
				run, cancel := context.WithTimeout(ctx, time.Second)
				defer cancel()
				result, e := ChangeSessionWithFallback(run, s, "127.0.0.1", "published-session", "disconnect", 0, func(context.Context, store.Session) (bool, error) { return true, nil })
				if mode == "timeout" {
					if e == nil {
						t.Fatal("timeout accepted")
					}
				} else {
					must(e)
					if !result.Acknowledged {
						t.Fatal(result)
					}
				}
			}
			must(<-done)
			must(s.RunPublicationResults(ctx, time.Now()))
			r, e := s.PublicationResult(ctx, batch)
			must(e)
			if len(r.Sessions) != 1 || r.Sessions[0].Attempts != 1 || len(r.Attempts) != 1 {
				t.Fatal(r)
			}
			if mode == "timeout" {
				if r.State != "attention" || r.Sessions[0].LastError == "" {
					t.Fatal(r)
				}
				return
			}
			if mode == "fallback" {
				if r.State != "completed" || r.Sessions[0].NASResponse != "Disconnect-NAK" || r.Sessions[0].NASCause != 406 || r.Sessions[0].State != "adapter_confirmed" {
					t.Fatal(r)
				}
				return
			}
			if r.State != "in_progress" || r.Sessions[0].State != "awaiting_stop" || r.Sessions[0].NASResponse != "Disconnect-ACK" {
				t.Fatal(r)
			}
			must(s.ApplyAccounting(ctx, store.AccountingEvent{NAS: "127.0.0.1", ID: "published-session", Username: "user", Kind: "stop", At: time.Now().Unix(), Classes: []string{token}}))
			must(s.RunPublicationResults(ctx, time.Now()))
			r, e = s.PublicationResult(ctx, batch)
			must(e)
			if r.State != "completed" {
				t.Fatal(r)
			}
		})
	}
}
