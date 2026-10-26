package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rkislov/border/internal/pki"
	"github.com/rkislov/border/internal/store"
)

func port(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}
func TestServePasswordAndMTLS(t *testing.T) {
	for _, mtls := range []bool{false, true} {
		name := "password"
		if mtls {
			name = "mtls-password"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("BORDER_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
			for _, env := range []string{"BORDER_LDAP_URL", "BORDER_SMTP_ADDRESS", "BORDER_PORTAL_VLAN"} {
				t.Setenv(env, "")
			}
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "test.db")
			db, err := store.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if err = db.Migrate(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err = db.Admin(t.Context(), "admin", "test-password-123", false); err != nil {
				t.Fatal(err)
			}
			db.DB.Close()
			if err = pki.Generate(dir, "127.0.0.1"); err != nil {
				t.Fatal(err)
			}
			addr, portal := port(t), port(t)
			args := []string{"--db", dbPath, "serve", "--certs", dir, "--web", addr, "--portal", portal, "--auth", "127.0.0.1:0", "--accounting", "127.0.0.1:0", "--acme-http", "127.0.0.1:0", "--workers", "2"}
			if mtls {
				args = append(args, "--admin-mtls")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			c := command()
			c.SetArgs(args)
			c.SetOut(io.Discard)
			c.SetErr(io.Discard)
			go func() { done <- c.ExecuteContext(ctx) }()
			ca, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(ca)
			config := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
			if mtls {
				pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "admin.pem"), filepath.Join(dir, "admin.key"))
				if err != nil {
					t.Fatal(err)
				}
				config.Certificates = []tls.Certificate{pair}
			}
			jar, _ := cookiejar.New(nil)
			transport := &http.Transport{TLSClientConfig: config}
			defer transport.CloseIdleConnections()
			// Race instrumentation and concurrent password hashing on shared CI runners
			// can exceed one second; this is a correctness test, not a latency benchmark.
			client := &http.Client{Transport: transport, Jar: jar, Timeout: 10 * time.Second}
			url := "https://" + addr
			var response *http.Response
			for i := 0; i < 50; i++ {
				response, err = client.Get(url)
				if err == nil {
					break
				}
				select {
				case e := <-done:
					t.Fatalf("startup: %v", e)
				default:
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			response, err = client.Post(url+"/api/login", "application/json", bytes.NewBufferString(`{"Username":"admin","Password":"test-password-123"}`))
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 200 {
				t.Fatal(response.StatusCode)
			}
			response.Body.Close()
			response, err = client.Get(url + "/api/state")
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 200 {
				t.Fatal(response.StatusCode)
			}
			response.Body.Close()
			// User portal must never require the administrative certificate.
			publicTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
			defer publicTransport.CloseIdleConnections()
			public := &http.Client{Transport: publicTransport, Timeout: time.Second}
			response, err = public.Get("https://" + portal)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != 200 || !strings.Contains(string(body), "Личный кабинет") {
				t.Fatal("portal unavailable")
			}
			if mtls {
				response, err = public.Get(url)
				if err == nil {
					response.Body.Close()
					t.Fatal("mTLS did not require client certificate")
				}
			}
			cancel()
			select {
			case err = <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("shutdown timed out")
			}
		})
	}
}
