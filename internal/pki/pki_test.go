package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCertificates(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1"} {
		t.Run(host, func(t *testing.T) {
			dir := t.TempDir()
			if err := Generate(dir, host); err != nil {
				t.Fatal(err)
			}
			ca, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(ca)
			for _, name := range []string{"server", "admin"} {
				pair, err := tls.LoadX509KeyPair(filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key"))
				if err != nil {
					t.Fatal(err)
				}
				cert, err := x509.ParseCertificate(pair.Certificate[0])
				if err != nil {
					t.Fatal(err)
				}
				opts := x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
				if name == "server" {
					opts.DNSName = host
					opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
				}
				if _, err = cert.Verify(opts); err != nil {
					t.Fatal(err)
				}
			}
			b, _ := pem.Decode(ca)
			if b == nil {
				t.Fatal("invalid PEM")
			}
			if err = Generate(dir, host); err == nil {
				t.Fatal("overwrote existing certificates")
			}
		})
	}
}
