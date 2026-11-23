// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package netcraze

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

type client struct {
	cfg       Config
	http      *http.Client
	transport *http.Transport
}

func connect(ctx context.Context, c Config) (*client, error) {
	if e := c.validate(); e != nil {
		return nil, e
	}
	u, _ := url.Parse(c.Address)
	name := u.Hostname()
	if c.HTTPHost != "" {
		v, _ := url.Parse("http://" + c.HTTPHost)
		name = v.Hostname()
	}
	pin, _ := hex.DecodeString(c.CertificateSHA256)
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name, InsecureSkipVerify: true, // Verified explicitly against an administrator-pinned certificate.
		VerifyConnection: func(v tls.ConnectionState) error {
			if len(v.PeerCertificates) == 0 {
				return fmt.Errorf("NAS certificate missing")
			}
			sum := sha256.Sum256(v.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
				return fmt.Errorf("NAS certificate mismatch")
			}
			now := time.Now()
			if now.Before(v.PeerCertificates[0].NotBefore) || now.After(v.PeerCertificates[0].NotAfter) {
				return fmt.Errorf("NAS certificate expired or not yet valid")
			}
			return nil
		}}, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16384}
	jar, _ := cookiejar.New(nil)
	x := &client{c, &http.Client{Transport: tr, Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, tr}
	good := false
	defer func() {
		if !good {
			x.close()
		}
	}()
	status, h, _, e := x.request(ctx, "/auth", nil)
	if e != nil {
		return nil, e
	}
	challenge, realm := h.Get("X-NDM-Challenge"), h.Get("X-NDM-Realm")
	if status != 401 || challenge == "" || realm == "" || len(challenge) > 256 || len(realm) > 256 {
		return nil, fmt.Errorf("NAS authentication challenge unavailable")
	}
	inner := md5.Sum([]byte(c.Username + ":" + realm + ":" + c.Password))
	outer := sha256.Sum256([]byte(challenge + hex.EncodeToString(inner[:])))
	status, _, _, e = x.request(ctx, "/auth", map[string]string{"login": c.Username, "password": hex.EncodeToString(outer[:])})
	if e != nil || status != 200 {
		return nil, fmt.Errorf("NAS authentication failed")
	}
	good = true
	return x, nil
}
func (c *client) close() { c.transport.CloseIdleConnections() }
func (c *client) request(ctx context.Context, path string, body any) (int, http.Header, []byte, error) {
	var data []byte
	var e error
	method := "GET"
	if body != nil {
		data, e = json.Marshal(body)
		if e != nil {
			return 0, nil, nil, fmt.Errorf("invalid NAS request")
		}
		defer clear(data)
		method = "POST"
	}
	r, e := http.NewRequestWithContext(ctx, method, c.cfg.Address+path, bytes.NewReader(data))
	if e != nil {
		return 0, nil, nil, fmt.Errorf("invalid NAS request")
	}
	if c.cfg.HTTPHost != "" {
		r.Host = c.cfg.HTTPHost
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	resp, e := c.http.Do(r)
	if e != nil {
		return 0, nil, nil, fmt.Errorf("NAS connection or certificate verification failed")
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 1048577))
	if e != nil || len(b) > 1048576 {
		return 0, nil, nil, fmt.Errorf("invalid NAS response size")
	}
	return resp.StatusCode, resp.Header, b, nil
}
func (c *client) command(ctx context.Context, command string, out any) error {
	status, _, b, e := c.request(ctx, "/rci/", map[string]string{"parse": command})
	if e != nil {
		return e
	}
	defer clear(b)
	if status != 200 {
		return fmt.Errorf("NAS command unavailable")
	}
	var v struct{ Parse json.RawMessage }
	if json.Unmarshal(b, &v) != nil || len(v.Parse) == 0 {
		return fmt.Errorf("invalid NAS command response")
	}
	var state struct{ Status []struct{ Status string } }
	if json.Unmarshal(v.Parse, &state) != nil {
		return fmt.Errorf("invalid NAS command response")
	}
	for _, s := range state.Status {
		if s.Status == "error" || s.Status == "fatal" {
			return fmt.Errorf("NAS rejected command")
		}
	}
	if out != nil && json.Unmarshal(v.Parse, out) != nil {
		return fmt.Errorf("invalid NAS command response")
	}
	return nil
}
