// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/rkislov/border/internal/eap"
	"github.com/rkislov/border/internal/identitysource"
	"github.com/rkislov/border/internal/pki"
	"github.com/rkislov/border/internal/store"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Domain runs are explicitly opt-in. The external hook owns fault injection and
// must implement reset, blocked and ldap-down, including its own crash rollback.
func TestDomainTunneledEAPOL(t *testing.T) {
	path := os.Getenv("BORDER_EAP_DOMAIN_CONFIG")
	if path == "" {
		t.Skip("private Samba lab configuration required")
	}
	var cfg struct {
		Domain                   identitysource.Domain
		Username, Password, Hook string
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal("invalid domain lab configuration")
	}
	clear(raw)
	if cfg.Username == "" || cfg.Password == "" || cfg.Hook == "" {
		t.Fatal("incomplete domain lab configuration")
	}
	runTunneledEAPOL(t, &cfg.Domain, cfg.Username, cfg.Password, cfg.Hook)
}

func TestTunneledEAPOL(t *testing.T) {
	runTunneledEAPOL(t, nil, "alice", "test-password-123", "")
}

func runTunneledEAPOL(t *testing.T, domain *identitysource.Domain, username, password, hook string) {
	fault := func(state string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := exec.CommandContext(ctx, hook, state).Run(); err != nil {
			t.Fatalf("lab hook %s: %v", state, err)
		}
	}
	if domain != nil {
		t.Cleanup(func() { fault("reset") })
		fault("reset")
	}
	tool := os.Getenv("BORDER_EAPOL_TEST")
	if tool == "" {
		var err error
		tool, err = exec.LookPath("eapol_test")
		if err != nil {
			t.Skip("eapol_test required")
		}
	}
	for _, method := range []string{"peap", "ttls"} {
		t.Run(method, func(t *testing.T) {
			s, o := vpnFixture(t)
			ctx := t.Context()
			for _, q := range []string{"DELETE FROM nas_policy_sets", "INSERT INTO network_segments VALUES('staff','Staff')", "UPDATE access_policies SET mode='network',segment_id='staff'", "UPDATE nas SET access_mode='network',dictionary='standard'"} {
				if err := s.Exec(ctx, q); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.SaveMapping(ctx, store.SegmentMapping{NAS: "127.0.0.1", SegmentID: "staff", VLAN: 120}); err != nil {
				t.Fatal(err)
			}
			if err := s.SaveAuthentication(ctx, store.AuthenticationPolicy{ID: "local", Name: "Local", Source: "local", Enabled: true, EAPMethod: method}); err != nil {
				t.Fatal(err)
			}
			source := "local"
			if domain != nil {
				fault("reset")
				if err := o.Identities.SaveDomain(ctx, *domain); err != nil {
					t.Fatal(err)
				}
				if err := s.SaveAuthentication(ctx, store.AuthenticationPolicy{ID: "local", Name: "Domain", Source: "directory", DomainID: domain.ID, Enabled: true, EAPMethod: method}); err != nil {
					t.Fatal(err)
				}
				if err := s.Exec(ctx, "UPDATE policy_subjects SET identity=?", domain.ID+"/"+username); err != nil {
					t.Fatal(err)
				}
				source = domain.ID
				if _, err := o.Identities.DomainGroups(ctx, source+"/"+username); err != nil {
					t.Fatalf("domain groups preflight: %v", err)
				}
				if enabled, err := o.Identities.AccountEnabled(ctx, source+"/"+username); err != nil || !enabled {
					t.Fatalf("domain status preflight: enabled=%v error=%v", enabled, err)
				}
				if _, err := o.Identities.Authenticate(ctx, source+"/"+username, password); err != nil {
					t.Fatalf("domain LDAP preflight: %v", err)
				}
			}
			var sessions *tunnelSessions
			if domain != nil {
				sessions = newTunnelSessions(t, s, o.Identities, source+"/"+username)
			}
			dir := t.TempDir()
			if err := pki.Generate(dir, "radius.example.test"); err != nil {
				t.Fatal(err)
			}
			pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"))
			if err != nil {
				t.Fatal(err)
			}
			engine, err := eap.New(eap.Config{TLSConfig: func(context.Context) (*tls.Config, error) {
				return &tls.Config{Certificates: []tls.Certificate{pair}, ClientCAs: x509.NewCertPool()}, nil
			}, Authorize: func(context.Context, tls.ConnectionState) (eap.Authorization, error) {
				return eap.Authorization{}, fmt.Errorf("certificate authentication forbidden")
			}, FragmentSize: 128})
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			o.EAP = engine
			conn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			runctx, cancel := context.WithCancel(ctx)
			done := make(chan error, 1)
			go func() { done <- ServeWithOptions(runctx, conn, s, 4, false, o) }()
			defer func() { cancel(); <-done }()
			type attempt struct {
				name, password, server string
				success                bool
			}
			cases := []attempt{
				{"success", password, "radius.example.test", true},
				{"wrong-password", "wrong-password", "radius.example.test", false},
				{"wrong-server", password, "wrong.example.test", false},
				{"blocked", password, "radius.example.test", false},
			}
			if domain != nil {
				cases = append(cases,
					attempt{"blocked-ldap-down", password, "radius.example.test", false},
					attempt{"unblocked", password, "radius.example.test", true},
					attempt{"ldap-down", password, "radius.example.test", false},
					attempt{"ldap-restored", password, "radius.example.test", true})
			}
			cases = append(cases, attempt{"expired", password, "radius.example.test", false})
			for _, tc := range cases {
				var before int
				if err := s.Row(ctx, "SELECT COUNT(*) FROM access_grants").Scan(&before); err != nil {
					t.Fatal(err)
				}
				if domain != nil {
					switch tc.name {
					case "blocked", "ldap-down":
						fault(tc.name)
					case "blocked-ldap-down":
						fault("ldap-down")
					case "unblocked", "ldap-restored":
						fault("reset")
					}
				}
				if tc.name == "blocked" && domain == nil {
					if err = s.Exec(ctx, "UPDATE local_users SET enabled=0 WHERE username='alice'"); err != nil {
						t.Fatal(err)
					}
				}
				if tc.name == "expired" {
					if err = s.Exec(ctx, "UPDATE local_users SET enabled=1"); err != nil {
						t.Fatal(err)
					}
					if err = s.Exec(ctx, "UPDATE access_policies SET valid_until=?", time.Now().Unix()-1); err != nil {
						t.Fatal(err)
					}
				}
				if sessions != nil {
					sessions.check(ctx, tc.name)
				}
				inner := "auth=MSCHAPV2"
				if method == "ttls" {
					inner = "auth=PAP"
				}
				config := fmt.Sprintf("network={\nkey_mgmt=IEEE8021X\neap=%s\nidentity=%q\nanonymous_identity=\"anonymous\"\npassword=%q\nca_cert=\"%s\"\ndomain_suffix_match=\"%s\"\nfragment_size=128\nphase1=\"tls_disable_tlsv1_3=1\"\nphase2=\"%s\"\n}\n", strings.ToUpper(method), username, tc.password, filepath.Join(dir, "ca.pem"), tc.server, inner)
				file := filepath.Join(dir, tc.name+".conf")
				if err = os.WriteFile(file, []byte(config), 0600); err != nil {
					t.Fatal(err)
				}
				cctx, stop := context.WithTimeout(ctx, 20*time.Second)
				command := exec.CommandContext(cctx, tool, "-c", file, "-a", "127.0.0.1", "-p", fmt.Sprint(conn.LocalAddr().(*net.UDPAddr).Port), "-s", testSecret, "-t", "12")
				out, err := command.CombinedOutput()
				stop()
				success := err == nil && strings.Contains(string(out), "SUCCESS")
				if success != tc.success {
					var reason string
					_ = s.Row(ctx, "SELECT reason FROM auth_log ORDER BY occurred_at DESC LIMIT 1").Scan(&reason)
					t.Logf("last audit reason: %s", reason)
					t.Fatalf("%s: success=%v, expected=%v, client error=%v (client output withheld to protect credentials)", tc.name, success, tc.success, err)
				}
				if tc.success && !strings.Contains(string(out), "MPPE keys OK: 1") {
					t.Fatal("no MPPE verification")
				}
				if !tc.success && !strings.Contains(string(out), "EAP authentication failed") && tc.name != "wrong-server" {
					t.Fatalf("%s: no explicit EAP rejection", tc.name)
				}
				var after int
				if err := s.Row(ctx, "SELECT COUNT(*) FROM access_grants").Scan(&after); err != nil {
					t.Fatal(err)
				}
				expected := before
				if tc.success {
					expected++
				}
				if after != expected {
					t.Fatalf("%s: grants before=%d after=%d expected=%d", tc.name, before, after, expected)
				}
				if sessions != nil && tc.success {
					sessions.attach(ctx, tc.name)
				}
				t.Logf("%s: success=%v; grant delta=%d", tc.name, success, after-before)
				clear(out)
			}
			var count int
			if err = s.Row(ctx, "SELECT COUNT(*) FROM access_grants WHERE username=?", source+"/"+username).Scan(&count); err != nil || (domain == nil && count != 1) || (domain != nil && count != 3) {
				t.Fatal("inner identity grants", count, err)
			}
		})
	}
}
