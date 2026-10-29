package aaa

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/eapmschap"
	"github.com/rkislov/border/internal/identitysource"
	"github.com/rkislov/border/internal/mschap"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func vpnFixture(t *testing.T) (*store.Store, Options) {
	t.Helper()
	s := database(t)
	v, _ := auth.NewVault(make([]byte, 32))
	ids := &identitysource.Service{Store: s, Vault: v}
	yes := true
	for _, e := range []error{ids.SaveLocal(t.Context(), identitysource.LocalUser{Username: "alice", Password: "test-password-123", Enabled: true, MSCHAPEnabled: &yes}), s.SaveAuthentication(t.Context(), store.AuthenticationPolicy{ID: "local", Name: "Local", Source: "local", Enabled: true}), s.SaveAccess(t.Context(), store.AccessPolicy{ID: "vpn", Name: "VPN", AuthenticationID: "local", Mode: "vpn", Enabled: true, SessionSeconds: 600, Subjects: []string{"local/alice"}}), s.Exec(t.Context(), "UPDATE nas SET access_policy_id='vpn',access_mode='vpn',dictionary='strongswan'")} {
		if e != nil {
			t.Fatal(e)
		}
	}
	if err := s.SaveNASPolicies(t.Context(), store.NASPolicySet{NAS: "127.0.0.1", Enabled: true, Bindings: []store.PolicyBinding{{ID: "vpn", PolicyID: "vpn", Protocol: "eap", Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	e := eapmschap.New()
	t.Cleanup(e.Close)
	return s, Options{Identities: ids, EAPMSCHAP: e}
}
func TestVPNEAPPolicy(t *testing.T) {
	for _, mode := range []string{"success", "disabled", "expired", "changed", "totp", "wrong-password", "mixed"} {
		t.Run(mode, func(t *testing.T) {
			s, o := vpnFixture(t)
			if mode == "totp" {
				if e := s.Exec(t.Context(), `UPDATE authentication_policies SET require_totp=1,steps='["primary","totp"]'`); e != nil {
					t.Fatal(e)
				}
			}
			call := func(message, state []byte) *radius.Packet {
				p := request(t, "aa:bb:cc:dd:ee:ff")
				p.Attributes.Del(2)
				rfc2865.UserName_SetString(p, "alice")
				p.Attributes.Add(79, message)
				if len(state) > 0 {
					p.Attributes.Add(24, state)
				}
				if mode == "mixed" {
					rfc2865.UserPassword_SetString(p, "test-password-123")
				}
				raw, e := ProcessWithOptions(t.Context(), s, wire(t, p), source(), false, o)
				if mode == "mixed" && e != nil {
					return nil
				}
				if e != nil {
					t.Fatal(e)
				}
				out, e := radius.Parse(raw, []byte(testSecret))
				if e != nil {
					t.Fatal(e)
				}
				return out
			}
			first := call([]byte{2, 1, 0, 10, 1, 'a', 'l', 'i', 'c', 'e'}, nil)
			if mode == "mixed" {
				if first != nil && first.Code != radius.CodeAccessReject {
					t.Fatal("mixed credentials accepted")
				}
				return
			}
			if mode == "totp" {
				if first.Code != radius.CodeAccessReject {
					t.Fatal("TOTP bypassed")
				}
				return
			}
			if first.Code != radius.CodeAccessChallenge {
				t.Fatal(first.Code)
			}
			challenge := first.Attributes.Get(79)
			state := first.Attributes.Get(24)
			peer := bytes.Repeat([]byte{7}, 16)
			password := "test-password-123"
			if mode == "wrong-password" {
				password = "wrong"
			}
			hash := mschap.PasswordHash(password)
			nt := mschap.NTResponse(hash, challenge[10:26], peer, "alice")
			clear(hash)
			msg := []byte{2, challenge[1], 0, 64, 26, 2, challenge[6], 0, 59, 49}
			msg = append(msg, peer...)
			msg = append(msg, make([]byte, 8)...)
			msg = append(msg, nt...)
			msg = append(msg, 0)
			msg = append(msg, "alice"...)
			binary.BigEndian.PutUint16(msg[2:], uint16(len(msg)))
			binary.BigEndian.PutUint16(msg[7:], uint16(len(msg)-5))
			second := call(msg, state)
			if mode == "wrong-password" {
				if second.Code != radius.CodeAccessReject {
					t.Fatal("bad credentials accepted")
				}
				return
			}
			if second.Code != radius.CodeAccessChallenge {
				t.Fatal(second.Code)
			}
			switch mode {
			case "disabled":
				s.Exec(t.Context(), "UPDATE local_users SET enabled=0 WHERE username='alice'")
			case "expired":
				s.Exec(t.Context(), "UPDATE access_policies SET valid_until=?", time.Now().Unix()-1)
			case "changed":
				s.Exec(t.Context(), "UPDATE access_policies SET session_seconds=120")
			}
			final := call([]byte{2, second.Attributes.Get(79)[1], 0, 6, 26, 3}, state)
			if mode != "success" {
				if final.Code != radius.CodeAccessReject {
					t.Fatal("changed policy or disabled user accepted")
				}
				return
			}
			if final.Code != radius.CodeAccessAccept || len(final.Attributes.Get(25)) == 0 {
				t.Fatal("VPN grant missing")
			}
			keys := 0
			for _, a := range final.Attributes {
				if a.Type == 26 {
					vendor, b, _ := radius.VendorSpecific(a.Attribute)
					if vendor == 311 && (b[0] == 16 || b[0] == 17) {
						keys++
					}
				}
			}
			if keys != 2 {
				t.Fatal("MPPE keys missing")
			}
		})
	}
}
func TestEAPMSCHAPInteroperability(t *testing.T) {
	tool := os.Getenv("BORDER_EAPOL_TEST")
	if tool == "" {
		var e error
		tool, e = exec.LookPath("eapol_test")
		if e != nil {
			t.Skip("install eapol_test for independent interoperability")
		}
	}
	s, o := vpnFixture(t)
	conn, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	defer conn.Close()
	go ServeWithOptions(ctx, conn, s, 4, false, o)
	for _, password := range []string{"test-password-123", "incorrect-password"} {
		p := filepath.Join(t.TempDir(), "eap.conf")
		config := fmt.Sprintf("network={\nkey_mgmt=IEEE8021X\neap=MSCHAPV2\nidentity=\"alice\"\npassword=\"%s\"\n}\n", password)
		os.WriteFile(p, []byte(config), 0600)
		run, cancel := context.WithTimeout(ctx, 20*time.Second)
		cmd := exec.CommandContext(run, tool, "-c", p, "-a", "127.0.0.1", "-p", strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port), "-s", testSecret, "-t", "10")
		out, e := cmd.CombinedOutput()
		cancel()
		ok := e == nil && bytes.Contains(out, []byte("SUCCESS"))
		if ok != (password == "test-password-123") {
			t.Fatalf("independent EAP-MSCHAPv2 exchange failed: %s", out)
		}
	}
}
