// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/rkislov/border/internal/eap"
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

func TestTunneledEAPOL(t *testing.T) {
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
			for _, tc := range []struct {
				name, password, server string
				success                bool
			}{{"success", "test-password-123", "radius.example.test", true}, {"wrong-password", "wrong-password", "radius.example.test", false}, {"wrong-server", "test-password-123", "wrong.example.test", false}, {"blocked", "test-password-123", "radius.example.test", false}, {"expired", "test-password-123", "radius.example.test", false}} {
				if tc.name == "blocked" {
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
				inner := "auth=MSCHAPV2"
				if method == "ttls" {
					inner = "auth=PAP"
				}
				config := fmt.Sprintf("network={\nkey_mgmt=IEEE8021X\neap=%s\nidentity=\"alice\"\nanonymous_identity=\"anonymous\"\npassword=\"%s\"\nca_cert=\"%s\"\ndomain_suffix_match=\"%s\"\nfragment_size=128\nphase1=\"tls_disable_tlsv1_3=1\"\nphase2=\"%s\"\n}\n", strings.ToUpper(method), tc.password, filepath.Join(dir, "ca.pem"), tc.server, inner)
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
					t.Fatalf("%s: %v\n%s", tc.name, err, out)
				}
				if tc.success && !strings.Contains(string(out), "MPPE keys OK: 1") {
					t.Fatalf("no MPPE verification: %s", out)
				}
			}
			var count int
			if err = s.Row(ctx, "SELECT COUNT(*) FROM access_grants WHERE username='local/alice'").Scan(&count); err != nil || count != 1 {
				t.Fatal("inner identity grants", count, err)
			}
		})
	}
}
