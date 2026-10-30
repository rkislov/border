package routeros

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/store"
	"golang.org/x/crypto/ssh"
)

func service(t *testing.T) *Service {
	t.Helper()
	s, e := store.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	if e = s.Migrate(t.Context()); e != nil {
		t.Fatal(e)
	}
	v, _ := auth.NewVault(make([]byte, 32))
	return &Service{Store: s, Vault: v}
}
func TestCorrelation(t *testing.T) {
	u := active{ID: "*A", Name: "local/test", Address: "192.0.2.9", Via: "ssh", When: "2026-10-29 15:00:00", Radius: true}
	tm, _ := time.Parse("2006-01-02 15:04:05", u.When)
	v := store.Session{Username: u.Name, StartedAt: tm.Unix() - 10800 + 1}
	p := snapshot{Offset: 10800, Users: []active{u}}
	if got, e := match(v, p); e != nil || got != u {
		t.Fatal(got, e)
	}
	p.Users = append(p.Users, u)
	if _, e := match(v, p); e == nil {
		t.Fatal("ambiguous session accepted")
	}
	p.Users = p.Users[:1]
	p.Users[0].Radius = false
	if _, e := match(v, p); e == nil {
		t.Fatal("local administrator accepted")
	}
	p.Users[0] = u
	v.StartedAt -= 20
	if _, e := match(v, p); e == nil {
		t.Fatal("replacement session accepted")
	}
	q := quote(`a"; /user remove [find]; $b`)
	if !strings.Contains(q, `\"`) || !strings.Contains(q, `\$`) {
		t.Fatal("unsafe RouterOS quoting")
	}
}
func TestEncryptedConfig(t *testing.T) {
	s := service(t)
	ctx := t.Context()
	s.Store.Exec(ctx, "INSERT INTO nas(address,name,secret,dictionary,access_mode) VALUES('192.0.2.1','test','secret','mikrotik','ssh')")
	cfg := Config{Enabled: true, Address: "192.0.2.1:22", Username: "service", Password: "unique-secret-password", HostKey: "SHA256:" + strings.Repeat("A", 43)}
	if e := s.Save(ctx, "192.0.2.1", cfg); e != nil {
		t.Fatal(e)
	}
	var raw string
	s.Store.Row(ctx, "SELECT config FROM nas_routeros").Scan(&raw)
	if strings.Contains(raw, cfg.Password) {
		t.Fatal("plaintext password")
	}
	cfg.Password = ""
	if e := s.Save(ctx, "192.0.2.1", cfg); e != nil {
		t.Fatal(e)
	}
	cfg.Address = "192.0.2.2:22"
	if e := s.Save(ctx, "192.0.2.1", cfg); e == nil {
		t.Fatal("credential silently moved to another endpoint")
	}
	other := service(t)
	if v, e := other.Config(ctx, "192.0.2.1"); e != nil || v.Enabled || v.Password != "" {
		t.Fatal("tenant settings leak")
	}
}

// A real SSH handshake verifies pinning, bounded command handling and the
// requirement to observe absence after removal, without a physical router.
func TestDisconnectSSH(t *testing.T) {
	for _, scenario := range []string{"success", "wrong-key", "still-active", "generation-changed", "ambiguous", "ssh-on-vpn-nas", "canonical-domain"} {
		t.Run(scenario, func(t *testing.T) {
			s := service(t)
			ctx := t.Context()
			now := time.Now().Unix() - 60
			v := store.Session{NAS: "192.0.2.1", ID: "id", Username: "user", Generation: "generation", GrantToken: "grant", StartedAt: now}
			if e := s.Store.Exec(ctx, "INSERT INTO nas(address,name,secret,dictionary,access_mode) VALUES(?,?,?,'mikrotik','ssh')", v.NAS, "test", "test-secret-12345"); e != nil {
				t.Fatal(e)
			}
			if e := s.Store.Exec(ctx, "INSERT INTO sessions(nas,session_id,mac,username,status,updated_at,generation,started_at,grant_token) VALUES(?,?,'',?,'active',?,?,?,'grant')", v.NAS, v.ID, v.Username, now, v.Generation, now); e != nil {
				t.Fatal(e)
			}
			for _, q := range []string{
				"INSERT INTO authentication_policies(id,name,source) VALUES('auth','auth','local')",
				"INSERT INTO access_policies(id,name,authentication_id,mode,session_seconds) VALUES('ssh','ssh','auth','ssh',600)",
				"INSERT INTO access_grants(token,nas,username,policy_id,expires_at) VALUES('grant','192.0.2.1','user','ssh',0)",
			} {
				if e := s.Store.Exec(ctx, q); e != nil {
					t.Fatal(e)
				}
			}
			if scenario == "ssh-on-vpn-nas" {
				if e := s.Store.Exec(ctx, "UPDATE nas SET access_mode='vpn'"); e != nil {
					t.Fatal(e)
				}
			}
			if scenario == "canonical-domain" {
				if e := s.Store.Exec(ctx, "UPDATE access_grants SET username='samba-lab/user'"); e != nil {
					t.Fatal(e)
				}
			}
			if scenario == "generation-changed" {
				v.Generation = "old"
			}
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			signer, _ := ssh.NewSignerFromKey(key)
			pk, _ := ssh.NewPublicKey(pub)
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			cfg := Config{Enabled: true, Address: listener.Addr().String(), Username: "service", Password: "test-password-12345", HostKey: ssh.FingerprintSHA256(pk)}
			if scenario == "wrong-key" {
				cfg.HostKey = "SHA256:" + strings.Repeat("A", 43)
			}
			if e = s.Save(ctx, v.NAS, cfg); e != nil {
				t.Fatal(e)
			}
			var wg sync.WaitGroup
			wg.Add(1)
			defer wg.Wait()
			removed := false
			go func() {
				defer wg.Done()
				conn, e := listener.Accept()
				if e != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				sc := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
					if string(p) != cfg.Password {
						return nil, fmt.Errorf("bad password")
					}
					return nil, nil
				}}
				sc.AddHostKey(signer)
				server, chans, reqs, e := ssh.NewServerConn(conn, sc)
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
					for r := range requests {
						if r.Type != "exec" {
							r.Reply(false, nil)
							continue
						}
						var command struct{ Command string }
						ssh.Unmarshal(r.Payload, &command)
						r.Reply(true, nil)
						if command.Command == listCommand {
							users := []active{}
							if !removed || scenario == "still-active" {
								u := active{ID: "*1", Name: "user", Address: "192.0.2.3", Via: "ssh", Radius: true, When: time.Unix(now, 0).UTC().Format("2006-01-02 15:04:05")}
								users = append(users, u)
								if scenario == "ambiguous" {
									u.ID = "*2"
									users = append(users, u)
								}
							}
							json.NewEncoder(channel).Encode(snapshot{Users: users})
						} else {
							removed = true
							fmt.Fprintln(channel, "border-removed")
						}
						channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						channel.Close()
						break
					}
				}
			}()
			ok, e := s.Disconnect(context.Background(), v)
			if scenario == "success" || scenario == "ssh-on-vpn-nas" || scenario == "canonical-domain" {
				if !ok || e != nil {
					t.Fatal(ok, e)
				}
			} else if ok || e == nil {
				t.Fatal("unsafe confirmation", ok, e)
			}
		})
	}
}

func TestDisconnectRequiresSSHGrant(t *testing.T) {
	for _, scenario := range []string{"vpn", "missing", "other-user", "other-nas"} {
		t.Run(scenario, func(t *testing.T) {
			s := service(t)
			ctx := t.Context()
			for _, q := range []string{
				"INSERT INTO nas(address,name,secret,dictionary,access_mode) VALUES('192.0.2.1','test','secret','mikrotik','ssh')",
				"INSERT INTO authentication_policies(id,name,source) VALUES('auth','auth','local')",
				"INSERT INTO access_policies(id,name,authentication_id,mode,session_seconds) VALUES('p','p','auth','vpn',600)",
				"INSERT INTO access_grants(token,nas,username,policy_id,expires_at) VALUES('grant','192.0.2.1','user','p',0)",
			} {
				if e := s.Store.Exec(ctx, q); e != nil {
					t.Fatal(e)
				}
			}
			cfg := Config{Enabled: true, Address: "127.0.0.1:1", Username: "service", Password: "test-password-12345", HostKey: "SHA256:" + strings.Repeat("A", 43)}
			if e := s.Save(ctx, "192.0.2.1", cfg); e != nil {
				t.Fatal(e)
			}
			v := store.Session{NAS: "192.0.2.1", Username: "user", GrantToken: "grant"}
			if scenario != "vpn" {
				if e := s.Store.Exec(ctx, "UPDATE access_policies SET mode='ssh'"); e != nil {
					t.Fatal(e)
				}
			}
			switch scenario {
			case "missing":
				v.GrantToken = ""
			case "other-user":
				v.Username = "someone"
			case "other-nas":
				if e := s.Store.Exec(ctx, "UPDATE access_grants SET nas='192.0.2.2'"); e != nil {
					t.Fatal(e)
				}
			}
			ok, e := s.Disconnect(ctx, v)
			if ok || e == nil || strings.Contains(e.Error(), "management connection") {
				t.Fatalf("must refuse before SSH dial: %v %v", ok, e)
			}
		})
	}
}
