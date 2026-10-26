package aaa

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/eap"
	"github.com/rkislov/border/internal/pki"
)

// Set BORDER_EAPOL_TEST to an independently built hostap eapol_test executable.
// The tool emulates the supplicant and NAS over real UDP, and checks MPPE keys.
func TestEAPOLInteroperability(t *testing.T) {
	tool := os.Getenv("BORDER_EAPOL_TEST")
	if tool == "" {
		var err error
		tool, err = exec.LookPath("eapol_test")
		if err != nil {
			t.Skip("set BORDER_EAPOL_TEST or install eapol_test")
		}
	}
	s := database(t)
	dir := t.TempDir()
	if err := pki.Generate(dir, "radius.example.test"); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	vault, err := auth.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	manager := &pki.Manager{Store: s, Vault: vault}
	ca, err := manager.CreateCA(t.Context(), "Managed EAP test root")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := manager.Issue(t.Context(), ca.ID, "user", "user@example.test", "", "", 90)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"client.pem": bundle.Certificate + bundle.CA, "client.key": bundle.PrivateKey} {
		if err = os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	engine, err := eap.New(eap.Config{TLSConfig: func(ctx context.Context) (*tls.Config, error) { return manager.EAPTLSConfig(ctx, pair) }, Authorize: func(ctx context.Context, state tls.ConnectionState) (eap.Authorization, error) {
		identity, err := manager.AuthorizeClient(ctx, state)
		return eap.Authorization{Identity: identity, VLAN: 100}, err
	}, FragmentSize: 128})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- ServeWithOptions(ctx, conn, s, 4, false, Options{EAP: engine}) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	run := func(name string, certificate bool, wantSuccess bool) {
		t.Helper()
		config := fmt.Sprintf("network={\nkey_mgmt=IEEE8021X\neap=TLS\nidentity=\"anonymous\"\nca_cert=\"%s\"\ndomain_suffix_match=\"radius.example.test\"\nfragment_size=128\nphase1=\"tls_disable_tlsv1_3=1\"\n", filepath.Join(dir, "ca.pem"))
		if certificate {
			config += fmt.Sprintf("client_cert=\"%s\"\nprivate_key=\"%s\"\n", filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key"))
		}
		config += "}\n"
		path := filepath.Join(dir, name+".conf")
		if err := os.WriteFile(path, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		runCtx, stop := context.WithTimeout(t.Context(), 15*time.Second)
		defer stop()
		reauth := "0"
		if wantSuccess {
			reauth = "1"
		}
		command := exec.CommandContext(runCtx, tool, "-c", path, "-a", "127.0.0.1", "-p", fmt.Sprint(port), "-s", testSecret, "-t", "10", "-r", reauth)
		out, err := command.CombinedOutput()
		success := err == nil && strings.Contains(string(out), "SUCCESS")
		if success != wantSuccess {
			lines := strings.Split(string(out), "\n")
			if len(lines) > 70 {
				lines = lines[len(lines)-70:]
			}
			t.Fatalf("%s: success=%v want=%v: %v\n%s", name, success, wantSuccess, err, strings.Join(lines, "\n"))
		}
		if wantSuccess && strings.Contains(string(out), "MPPE keys OK: 0") {
			t.Fatal("supplicant did not verify MPPE keys")
		}
	}
	run("valid", true, true)
	run("missing-certificate", false, false)
	if err = manager.Revoke(t.Context(), bundle.Serial, "user"); err != nil {
		t.Fatal(err)
	}
	run("revoked", true, false)
}
