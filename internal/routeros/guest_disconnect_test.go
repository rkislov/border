package routeros

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rkislov/border/internal/store"
	"golang.org/x/crypto/ssh"
)

func TestHotspotDisconnectGeneration(t *testing.T) {
	for _, scenario := range []string{"success", "replacement", "accounting-changed", "overlap", "not-confirmed"} {
		t.Run(scenario, func(t *testing.T) {
			s := service(t)
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			v := store.Session{NAS: "192.0.2.1", ID: "id", MAC: "02:00:00:00:00:01", Username: "02:00:00:00:00:01", Generation: "gen", GrantToken: "grant", StartedAt: time.Now().Unix() - 60}
			must(s.Store.Exec(ctx, "INSERT INTO nas(address,name,secret,dictionary) VALUES(?,'NAS','test-secret','mikrotik')", v.NAS))
			must(s.Store.Exec(ctx, "INSERT INTO sessions(nas,session_id,mac,username,status,updated_at,generation,started_at,grant_token) VALUES(?,?,?,?,'active',?,?,?,?)", v.NAS, v.ID, v.MAC, v.Username, v.StartedAt, v.Generation, v.StartedAt, v.GrantToken))
			if scenario == "overlap" {
				must(s.Store.Exec(ctx, "INSERT INTO sessions(nas,session_id,mac,username,status,updated_at,started_at) VALUES(?,'other',?,?,'stopped',?,?)", v.NAS, v.MAC, v.Username, v.StartedAt, v.StartedAt))
			}
			_, key, e := ed25519.GenerateKey(rand.Reader)
			must(e)
			signer, e := ssh.NewSignerFromKey(key)
			must(e)
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			must(e)
			cfg := Config{Enabled: true, Address: listener.Addr().String(), Username: "service", Password: "test-password", HostKey: ssh.FingerprintSHA256(signer.PublicKey()), GuestHotspot: "guest"}
			var removals atomic.Int32
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					conn, e := listener.Accept()
					if e != nil {
						return
					}
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					sc := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) { return nil, nil }}
					sc.AddHostKey(signer)
					server, chans, reqs, e := ssh.NewServerConn(conn, sc)
					if e != nil {
						conn.Close()
						return
					}
					go ssh.DiscardRequests(reqs)
					for ch := range chans {
						channel, requests, e := ch.Accept()
						if e != nil {
							break
						}
						for req := range requests {
							if req.Type != "exec" {
								req.Reply(false, nil)
								continue
							}
							var q struct{ Command string }
							ssh.Unmarshal(req.Payload, &q)
							req.Reply(true, nil)
							if strings.Contains(q.Command, "active remove") {
								removals.Add(1)
								for _, guard := range []string{`.id="*A"`, `server="guest"`, `radius=yes`, `session generation changed`, `session still active`} {
									if !strings.Contains(q.Command, guard) {
										t.Error("missing removal guard", guard)
									}
								}
								if scenario == "not-confirmed" {
									fmt.Fprintln(channel, "failure")
								} else {
									fmt.Fprintln(channel, "border-hotspot-removed")
								}
							} else {
								uptime := time.Now().Unix() - v.StartedAt
								if scenario == "replacement" {
									uptime = 1
								}
								if scenario == "accounting-changed" {
									if e := s.Store.Exec(ctx, "UPDATE sessions SET generation='new'"); e != nil {
										t.Error(e)
									}
								}
								fmt.Fprintf(channel, "{\"id\":\"*A\",\"uptime\":%d}\n", uptime)
							}
							channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							channel.Close()
							break
						}
					}
					server.Close()
					conn.Close()
				}
			}()
			ok, e := s.disconnectGuest(ctx, cfg, v)
			listener.Close()
			<-done
			if (ok && e == nil) != (scenario == "success") {
				t.Fatal("unsafe disconnect result", ok, e)
			}
			if scenario != "success" && scenario != "not-confirmed" && removals.Load() != 0 {
				t.Fatal("unrelated session removal")
			}
		})
	}
}
