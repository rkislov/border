// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package mail

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"time"
)

type Sender interface {
	Send(context.Context, string, string, string) error
}
type SMTP struct {
	TLS                               *tls.Config
	Address, Username, Password, From string
	CAPEM                             string
	ImplicitTLS                       bool
}

func FromEnv() (*SMTP, error) {
	addr := os.Getenv("BORDER_SMTP_ADDRESS")
	if addr == "" {
		return nil, nil
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, fmt.Errorf("SMTP address must be host:port")
	}
	from := os.Getenv("BORDER_SMTP_FROM")
	if _, err := mail.ParseAddress(from); err != nil || strings.ContainsAny(from, "\r\n") {
		return nil, fmt.Errorf("SMTP sender must be a valid address")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	var caPEM string
	if path := os.Getenv("BORDER_SMTP_CA"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("invalid SMTP CA")
		}
		config.RootCAs = roots
		caPEM = string(b)
	}
	return &SMTP{Address: addr, From: from, Username: os.Getenv("BORDER_SMTP_USERNAME"), Password: os.Getenv("BORDER_SMTP_PASSWORD"), CAPEM: caPEM, ImplicitTLS: os.Getenv("BORDER_SMTP_TLS") == "implicit", TLS: config}, nil
}

// Send never falls back to unencrypted delivery. Use port 465/implicit or
// STARTTLS (usually port 587); credentials are sent only after TLS verification.
func (s *SMTP) Send(ctx context.Context, to, subject, body string) error {
	return s.SendWithID(ctx, to, subject, body, "")
}

// SendWithID provides a stable Message-ID for retries; SMTP itself does not
// guarantee idempotent acceptance by the recipient server.
func (s *SMTP) SendWithID(ctx context.Context, to, subject, body, id string) error {
	if strings.ContainsAny(id, "\r\n<>") {
		return fmt.Errorf("invalid message id")
	}

	recipient, err := mail.ParseAddress(to)
	if err != nil || strings.ContainsAny(to+subject, "\r\n") {
		return fmt.Errorf("invalid mail header")
	}
	from, err := mail.ParseAddress(s.From)
	if err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(s.Address)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", s.Address)
	if err != nil {
		return fmt.Errorf("SMTP unavailable")
	}
	defer conn.Close()
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}
	config := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if s.TLS != nil {
		config = s.TLS.Clone()
		config.ServerName = host
	}
	if s.ImplicitTLS {
		secured := tls.Client(conn, config)
		if err = secured.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("SMTP TLS failed")
		}
		conn = secured
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTP connection failed")
	}
	defer c.Close()
	if !s.ImplicitTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("SMTP requires STARTTLS")
		}
		if err = c.StartTLS(config); err != nil {
			return fmt.Errorf("SMTP TLS failed")
		}
	}
	if s.Username != "" {
		if err = c.Auth(smtp.PlainAuth("", s.Username, s.Password, host)); err != nil {
			return fmt.Errorf("SMTP authentication failed")
		}
	}
	if err = c.Mail(from.Address); err != nil {
		return fmt.Errorf("SMTP sender rejected")
	}
	if err = c.Rcpt(recipient.Address); err != nil {
		return fmt.Errorf("SMTP recipient rejected")
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	messageID := ""
	if id != "" {
		messageID = "Message-ID: <" + id + "@border.invalid>\r\n"
	}
	message := messageID + "From: " + from.String() + "\r\nTo: " + recipient.String() + "\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + strings.ReplaceAll(body, "\n", "\r\n") + "\r\n"
	if _, err = w.Write([]byte(message)); err != nil {
		w.Close()
		return err
	}
	if err = w.Close(); err != nil {
		return fmt.Errorf("SMTP delivery failed")
	}
	// DATA acknowledgement confirms acceptance; a later QUIT failure must not resend.
	_ = c.Quit()
	return nil
}
