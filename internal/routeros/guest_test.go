package routeros

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rkislov/border/internal/store"
	"golang.org/x/crypto/ssh"
)

func TestGuestActivationSSHProofAndPin(t *testing.T) {
	for _, scenario := range []string{"accepted", "wrong-key", "command-failed", "unexpected-output", "revoked"} {
		t.Run(scenario, func(t *testing.T) {
			s := service(t)
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			for _, q := range []string{"INSERT INTO vlan_catalog VALUES(330,'Guest')", "INSERT INTO network_segments VALUES('guest','Guest')", "INSERT INTO nas(address,name,secret,dictionary,portal_enabled) VALUES('192.0.2.1','NAS','long-secret-12345','mikrotik',1)", "UPDATE guest_policy SET enabled=1"} {
				must(s.Store.Exec(ctx, q))
			}
			must(s.Store.SaveAuthentication(ctx, store.AuthenticationPolicy{ID: "guest", Name: "Guests", Source: "guest", GuestMethods: []string{"sms"}, Enabled: true}))
			must(s.Store.SaveAccess(ctx, store.AccessPolicy{ID: "guest", Name: "Guests", AuthenticationID: "guest", Mode: "network", SegmentID: "guest", SessionSeconds: 600, Enabled: true}))
			must(s.Store.SaveRules(ctx, store.RuleSet{PolicyID: "guest", Enabled: true, Rules: []store.AccessRule{{ID: "all", Name: "Guests", Effect: "allow", AllAuthenticated: true, Enabled: true}}}))
			must(s.Store.SaveMapping(ctx, store.SegmentMapping{NAS: "192.0.2.1", SegmentID: "guest", VLAN: 330}))
			must(s.Store.Exec(ctx, "UPDATE nas SET access_policy_id='guest'"))
			b, e := s.Store.GuestAccessPolicy(ctx, "192.0.2.1", "02:00:00:00:00:01", "", "sms")
			must(e)
			g := store.GuestAuthorization{ID: "test", NAS: "192.0.2.1", MAC: "02:00:00:00:00:01", Identity: "guest-sms:" + strings.Repeat("a", 64), Method: "sms", PolicyID: "guest", PolicyHash: store.GuestPolicyHash(b), Expires: time.Now().Unix() + 300}
			must(s.Store.SaveGuestAuthorization(ctx, g))
			_, key, e := ed25519.GenerateKey(rand.Reader)
			must(e)
			signer, e := ssh.NewSignerFromKey(key)
			must(e)
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			must(e)
			defer listener.Close()
			cfg := Config{Enabled: true, Address: listener.Addr().String(), Username: "service", Password: "test-only-password-123", HostKey: ssh.FingerprintSHA256(signer.PublicKey()), GuestHotspot: "guest-server"}
			if scenario == "wrong-key" {
				cfg.HostKey = "SHA256:" + strings.Repeat("A", 43)
			}
			must(s.Save(ctx, g.NAS, cfg))
			if scenario == "revoked" {
				must(s.Store.RevokeGuest(ctx, g.NAS, g.MAC))
				handled, e := s.ActivateGuest(ctx, g, 330)
				if !handled || e == nil {
					t.Fatal("revoked authorization activated")
				}
				return
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, e := listener.Accept()
				if e != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				config := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
					if string(p) != cfg.Password {
						return nil, fmt.Errorf("bad password")
					}
					return nil, nil
				}}
				config.AddHostKey(signer)
				server, chans, reqs, e := ssh.NewServerConn(conn, config)
				if e != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					channel, requests, e := ch.Accept()
					if e != nil {
						return
					}
					for req := range requests {
						if req.Type != "exec" {
							req.Reply(false, nil)
							continue
						}
						req.Reply(true, nil)
						var command struct{ Command string }
						ssh.Unmarshal(req.Payload, &command)
						if !strings.Contains(command.Command, "vlan-id=330") || !strings.Contains(command.Command, `user="02:00:00:00:00:01"`) {
							t.Error("wrong activation target")
						}
						result := "border-login-requested"
						exit := uint32(0)
						if scenario == "command-failed" {
							exit = 1
							result = "private error"
						}
						if scenario == "unexpected-output" {
							result = "failure: permission denied"
						}
						fmt.Fprintln(channel, result)
						channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{exit}))
						channel.Close()
						break
					}
				}
			}()
			handled, e := s.ActivateGuest(context.Background(), g, 330)
			<-done
			if !handled {
				t.Fatal("adapter not selected")
			}
			if (e == nil) != (scenario == "accepted") {
				t.Fatal(scenario, e)
			}
			var n int
			must(s.Store.Row(ctx, "SELECT count(*) FROM access_grants").Scan(&n))
			if n != 0 {
				t.Fatal("SSH response fabricated RADIUS proof")
			}
		})
	}
}
