// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package notification

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	netmail "net/mail"
	"strings"
	"sync"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/mail"
	"github.com/rkislov/border/internal/sms"
	"github.com/rkislov/border/internal/store"
)

type SMTPConfig struct {
	Mode, Address, Username, Password, From, CAPEM string
	ImplicitTLS, HasPassword                       bool
}
type SMSConfig struct {
	Mode string
	sms.Config
	HasToken bool
}
type PushConfig struct {
	Mode, Contact, PublicKey string
	PrivateKey               string `json:"-"`
}
type Config struct {
	Scope string
	SMTP  SMTPConfig
	SMS   SMSConfig
	Push  PushConfig
}

// Private push keys are serialized only in the encrypted store, never API responses.
type storedConfig struct {
	Config
	PushPrivate string
}
type Service struct {
	Store *store.Store
	Vault *auth.Vault
	mu    sync.Mutex
}

func scope(user string) string {
	domain, _, ok := strings.Cut(user, "/")
	if !ok || domain == "local" {
		return "default"
	}
	return domain
}
func (s *Service) validScope(ctx context.Context, id string) error {
	if id == "default" {
		return nil
	}
	var n int
	if s.Store.Row(ctx, "SELECT 1 FROM domains WHERE id=?", id).Scan(&n) != nil {
		return fmt.Errorf("unknown domain")
	}
	return nil
}
func (s *Service) Config(ctx context.Context, id string) (Config, error) {
	c := Config{Scope: id}
	mode := "inherit"
	if id == "default" {
		mode = "disabled"
	}
	c.SMTP.Mode = mode
	c.SMS.Mode = mode
	c.Push.Mode = mode
	if err := s.validScope(ctx, id); err != nil {
		return c, err
	}
	var raw string
	err := s.Store.Row(ctx, "SELECT value FROM settings WHERE name=?", "notifications:"+id).Scan(&raw)
	if err == sql.ErrNoRows {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if s.Vault == nil {
		return c, fmt.Errorf("master key required")
	}
	plain, err := s.Vault.Open(raw, "notifications:"+id)
	if err != nil {
		return c, fmt.Errorf("notification configuration unavailable")
	}
	defer clear(plain)
	var stored storedConfig
	err = json.Unmarshal(plain, &stored)
	stored.Config.Push.PrivateKey = stored.PushPrivate
	return stored.Config, err
}
func Redacted(c Config) Config {
	c.SMTP.HasPassword = c.SMTP.Password != ""
	c.SMTP.Password = ""
	c.SMS.HasToken = c.SMS.Token != ""
	c.SMS.Token = ""
	c.Push.PrivateKey = ""
	return c
}
func (s *Service) Save(ctx context.Context, c Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Vault == nil {
		return fmt.Errorf("master key required")
	}
	old, err := s.Config(ctx, c.Scope)
	if err != nil {
		return err
	}
	for _, mode := range []string{c.SMTP.Mode, c.SMS.Mode, c.Push.Mode} {
		if mode != "disabled" && mode != "custom" && !(mode == "inherit" && c.Scope != "default") {
			return fmt.Errorf("channel mode must be disabled, custom, or domain inheritance")
		}
	}
	if c.SMTP.Password == "" {
		if c.SMTP.Address == old.SMTP.Address && c.SMTP.Username == old.SMTP.Username {
			c.SMTP.Password = old.SMTP.Password
		} else if old.SMTP.Password != "" && c.SMTP.Mode == "custom" {
			return fmt.Errorf("re-enter SMTP password when changing destination")
		}
	}
	if c.SMS.Token == "" && c.SMS.URL == old.SMS.URL && c.SMS.Provider == old.SMS.Provider && c.SMS.AccountSID == old.SMS.AccountSID {
		c.SMS.Token = old.SMS.Token
	}
	if c.SMTP.Mode == "custom" {
		if _, err = smtpSender(c.SMTP); err != nil {
			return err
		}
	}
	if c.SMS.Mode == "custom" {
		p, e := sms.New(c.SMS.Config)
		if e != nil {
			return e
		}
		p.Close()
	}
	c.Push.PublicKey = old.Push.PublicKey
	c.Push.PrivateKey = old.Push.PrivateKey
	if c.Push.Mode == "custom" {
		if _, err = netmail.ParseAddress(c.Push.Contact); err != nil || strings.ContainsAny(c.Push.Contact, "\r\n") {
			return fmt.Errorf("VAPID contact email required")
		}
		if c.Push.PrivateKey == "" {
			c.Push.PrivateKey, c.Push.PublicKey, err = webpush.GenerateVAPIDKeys()
			if err != nil {
				return err
			}
		}
	}
	c.SMTP.HasPassword = false
	c.SMS.HasToken = false
	raw, err := json.Marshal(storedConfig{Config: c, PushPrivate: c.Push.PrivateKey})
	if err != nil {
		return err
	}
	defer clear(raw)
	return s.Store.Exec(ctx, "INSERT INTO settings(name,value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", "notifications:"+c.Scope, s.Vault.Seal(raw, "notifications:"+c.Scope))
}
func smtpSender(c SMTPConfig) (*mail.SMTP, error) {
	host, port, err := net.SplitHostPort(c.Address)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("SMTP address must be host:port")
	}
	if _, err = netmail.ParseAddress(c.From); err != nil || strings.ContainsAny(c.From, "\r\n") {
		return nil, fmt.Errorf("valid SMTP sender required")
	}
	if c.Username != "" && c.Password == "" {
		return nil, fmt.Errorf("SMTP password required")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAPEM != "" {
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(c.CAPEM)) {
			return nil, fmt.Errorf("invalid SMTP CA")
		}
		config.RootCAs = roots
	}
	return &mail.SMTP{Address: c.Address, Username: c.Username, Password: c.Password, From: c.From, ImplicitTLS: c.ImplicitTLS, TLS: config}, nil
}
func (s *Service) effective(ctx context.Context, id string) (Config, error) {
	c, err := s.Config(ctx, id)
	if err != nil {
		return c, err
	}
	if id == "default" {
		return c, nil
	}
	root, err := s.Config(ctx, "default")
	if err != nil {
		return c, err
	}
	if c.SMTP.Mode == "inherit" {
		c.SMTP = root.SMTP
	}
	if c.SMS.Mode == "inherit" {
		c.SMS = root.SMS
	}
	if c.Push.Mode == "inherit" {
		c.Push = root.Push
	}
	return c, nil
}

// Send satisfies mail.Sender for compatibility. Identity-aware callers use SendForIdentity.
func (s *Service) Send(ctx context.Context, to, subject, body string) error {
	return s.SendForIdentity(ctx, "local/", to, subject, body)
}
func (s *Service) SendForIdentity(ctx context.Context, user, to, subject, body string) (resultErr error) {
	started := time.Now()
	defer func() { s.Store.Metrics.Finish("smtp", started, resultErr) }()
	c, err := s.effective(ctx, scope(user))
	if err != nil {
		return err
	}
	if c.SMTP.Mode != "custom" {
		return fmt.Errorf("SMTP disabled for this domain")
	}
	sender, err := smtpSender(c.SMTP)
	if err != nil {
		return err
	}
	return sender.Send(ctx, to, subject, body)
}
func (s *Service) SendSMS(ctx context.Context, user, phone, text string) (resultErr error) {
	started := time.Now()
	defer func() { s.Store.Metrics.Finish("sms", started, resultErr) }()
	c, err := s.effective(ctx, scope(user))
	if err != nil {
		return err
	}
	if c.SMS.Mode != "custom" {
		return fmt.Errorf("SMS disabled for this domain")
	}
	p, err := sms.New(c.SMS.Config)
	if err != nil {
		return err
	}
	defer p.Close()
	return p.Send(ctx, phone, text)
}

// Notify sends account events to enabled channels, without forwarding codes to push.
func (s *Service) Notify(ctx context.Context, user, email, subject, body string) error {
	c, err := s.effective(ctx, scope(user))
	if err != nil {
		return err
	}
	sent := false
	failed := false
	if c.SMTP.Mode == "custom" && email != "" {
		sent = true
		failed = s.SendForIdentity(ctx, user, email, subject, body) != nil
	}
	if c.SMS.Mode == "custom" {
		var phone string
		if s.Store.Row(ctx, "SELECT phone FROM identities WHERE username=?", user).Scan(&phone) != nil {
			return fmt.Errorf("recipient unavailable")
		}
		if phone != "" {
			sent = true
			if s.SendSMS(ctx, user, phone, "Border: account security settings changed. Open your portal to review.") != nil {
				failed = true
			}
		}
	}
	if c.Push.Mode == "custom" {
		n, e := s.Push(ctx, user, "Border", "Изменены настройки безопасности вашей учётной записи.")
		sent = sent || n > 0
		failed = failed || e != nil
	}
	if failed {
		return fmt.Errorf("one or more notification channels failed")
	}
	if !sent {
		return fmt.Errorf("no notification channel available")
	}
	return nil
}

// Bootstrap imports legacy tenant defaults once. Subsequent saves take precedence over environment variables.
func (s *Service) Bootstrap(ctx context.Context, sender *mail.SMTP, legacy sms.Config) error {
	var raw string
	err := s.Store.Row(ctx, "SELECT value FROM settings WHERE name='notifications:default'").Scan(&raw)
	if err == nil {
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	c := Config{Scope: "default", SMTP: SMTPConfig{Mode: "disabled"}, SMS: SMSConfig{Mode: "disabled"}, Push: PushConfig{Mode: "disabled"}}
	if sender != nil {
		c.SMTP = SMTPConfig{Mode: "custom", Address: sender.Address, Username: sender.Username, Password: sender.Password, From: sender.From, ImplicitTLS: sender.ImplicitTLS}
		c.SMTP.CAPEM = sender.CAPEM
	}
	if legacy.Provider != "" {
		c.SMS = SMSConfig{Mode: "custom", Config: legacy}
	}
	return s.Save(ctx, c)
}

type smsSender struct {
	s    *Service
	user string
}

func (v smsSender) Send(ctx context.Context, phone, text string) error {
	return v.s.SendSMS(ctx, v.user, phone, text)
}
func (s *Service) GuestSender(ctx context.Context, nas string) (sms.SMSProvider, error) {
	user := "local/guest"
	if nas != "" {
		b, e := s.Store.BoundPolicy(ctx, nas)
		if e != nil {
			return nil, e
		}
		if b != nil && b.Authentication.DomainID != "" {
			user = b.Authentication.DomainID + "/guest"
		}
	}
	c, e := s.effective(ctx, scope(user))
	if e != nil {
		return nil, e
	}
	if c.SMS.Mode != "custom" {
		return nil, fmt.Errorf("SMS disabled")
	}
	return smsSender{s, user}, nil
}
