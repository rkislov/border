package mail

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSMTPRefusesCleartext(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		io.WriteString(c, "220 test SMTP\r\n")
		r := bufio.NewReader(c)
		r.ReadString('\n')
		io.WriteString(c, "250 test-no-tls\r\n")
		r.ReadString('\n')
	}()
	s := &SMTP{Address: l.Addr().String(), From: "border@example.test", Username: "user", Password: "do-not-send"}
	if err = s.Send(t.Context(), "user@example.test", "Code", "secret"); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatal("cleartext delivery allowed", err)
	}
	<-done
}
func TestSMTPImplicitTLS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pair, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	message := make(chan string, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			message <- ""
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		io.WriteString(conn, "220 smtp.test\r\n")
		var body strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				message <- body.String()
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				io.WriteString(conn, "250 smtp.test\r\n")
			case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"):
				io.WriteString(conn, "250 OK\r\n")
			case line == "DATA\r\n":
				io.WriteString(conn, "354 send data\r\n")
				for {
					line, err = r.ReadString('\n')
					if err != nil || line == ".\r\n" {
						break
					}
					body.WriteString(line)
				}
				io.WriteString(conn, "250 queued\r\n")
			case line == "QUIT\r\n":
				// Simulate connection loss after DATA was acknowledged.
				// This must not turn a delivered message into a retry.
				message <- body.String()
				return
			default:
				io.WriteString(conn, "500 unsupported\r\n")
			}
		}
	}()
	s := &SMTP{Address: l.Addr().String(), From: "border@example.test", ImplicitTLS: true, TLS: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err = s.SendWithID(ctx, "user@example.test", "Network code", "12345678", "stable-delivery-id"); err != nil {
		t.Fatal(err)
	}
	if msg := <-message; !strings.Contains(msg, "Message-ID: <stable-delivery-id@border.invalid>") || !strings.Contains(msg, "12345678") || !strings.Contains(msg, "To: <user@example.test>") {
		t.Fatal("wrong message", msg)
	}
	if err = s.Send(ctx, "user@example.test\r\nBcc: attacker@example.test", "Code", "secret"); err == nil {
		t.Fatal("header injection")
	}
}
