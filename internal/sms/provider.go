// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package sms

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type SMSProvider interface {
	Send(context.Context, string, string) error
}
type Config struct{ Provider, URL, AccountSID, Token, From, CAPEM string }

var phonePattern = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)

func Phone(raw string) (string, error) {
	v := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "").Replace(strings.TrimSpace(raw))
	if !phonePattern.MatchString(v) {
		return "", fmt.Errorf("номер должен быть в формате +79991234567")
	}
	return v, nil
}
func Mask(phone string) string {
	if len(phone) < 6 {
		return "***"
	}
	return phone[:2] + strings.Repeat("*", len(phone)-6) + phone[len(phone)-4:]
}

type HTTPProvider struct {
	config Config
	client *http.Client
}

func New(c Config) (*HTTPProvider, error) {
	if c.Provider != "webhook" && c.Provider != "twilio" {
		return nil, fmt.Errorf("SMS provider must be webhook or twilio")
	}
	if len(c.Token) < 16 || len(c.Token) > 512 || strings.ContainsAny(c.Token, "\r\n") {
		return nil, fmt.Errorf("SMS token must contain 16–512 bytes")
	}
	if c.Provider == "twilio" {
		if !regexp.MustCompile(`^AC[0-9a-fA-F]{32}$`).MatchString(c.AccountSID) || c.From == "" || len(c.From) > 32 || strings.ContainsAny(c.From, "\r\n") {
			return nil, fmt.Errorf("Twilio Account SID and sender required")
		}
		c.URL = "https://api.twilio.com/2010-04-01/Accounts/" + c.AccountSID + "/Messages.json"
	}
	endpoint, err := url.Parse(c.URL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return nil, fmt.Errorf("SMS endpoint requires HTTPS without embedded credentials")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.MaxIdleConnsPerHost = 4
	transport.ResponseHeaderTimeout = 5 * time.Second
	if c.CAPEM != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(c.CAPEM)) {
			return nil, fmt.Errorf("invalid SMS CA PEM")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return &HTTPProvider{config: c, client: &http.Client{Transport: transport, Timeout: 7 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (p *HTTPProvider) Close() { p.client.CloseIdleConnections() }
func (p *HTTPProvider) Send(ctx context.Context, phone, text string) error {
	if _, err := Phone(phone); err != nil {
		return err
	}
	if text == "" || len(text) > 500 {
		return fmt.Errorf("invalid SMS text")
	}
	var body []byte
	contentType := "application/json"
	if p.config.Provider == "twilio" {
		body = []byte(url.Values{"To": {phone}, "From": {p.config.From}, "Body": {text}}.Encode())
		contentType = "application/x-www-form-urlencoded"
	} else {
		var err error
		body, err = json.Marshal(map[string]string{"to": phone, "text": text})
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, "POST", p.config.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("SMS request failed")
	}
	req.Header.Set("Content-Type", contentType)
	if p.config.Provider == "twilio" {
		req.SetBasicAuth(p.config.AccountSID, p.config.Token)
	} else {
		req.Header.Set("Authorization", "Bearer "+p.config.Token)
	}
	response, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("SMS transport failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("SMS provider rejected delivery (HTTP %d)", response.StatusCode)
	}
	return nil
}
