// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package notification

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	webpush "github.com/SherClockHolmes/webpush-go"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func hash(v string) string { b := sha256.Sum256([]byte(v)); return hex.EncodeToString(b[:]) }
func validateSubscription(sub webpush.Subscription) error {
	u, err := url.Parse(sub.Endpoint)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") || len(sub.Endpoint) > 4096 {
		return fmt.Errorf("invalid push endpoint")
	}
	host := strings.ToLower(u.Hostname())
	allowed := host == "fcm.googleapis.com" || host == "updates.push.services.mozilla.com" || strings.HasSuffix(host, ".push.services.mozilla.com") || host == "web.push.apple.com" || strings.HasSuffix(host, ".notify.windows.com")
	if !allowed {
		return fmt.Errorf("push provider unsupported")
	}
	key, e := base64.RawURLEncoding.DecodeString(sub.Keys.P256dh)
	if e != nil {
		return fmt.Errorf("invalid push key")
	}
	if _, e = ecdh.P256().NewPublicKey(key); e != nil {
		return fmt.Errorf("invalid push key")
	}
	auth, e := base64.RawURLEncoding.DecodeString(sub.Keys.Auth)
	if e != nil || len(auth) != 16 {
		return fmt.Errorf("invalid push auth")
	}
	return nil
}
func (s *Service) PushKey(ctx context.Context, user string) (string, error) {
	c, e := s.effective(ctx, scope(user))
	if e != nil {
		return "", e
	}
	if c.Push.Mode != "custom" {
		return "", fmt.Errorf("push disabled")
	}
	return c.Push.PublicKey, nil
}
func (s *Service) Subscribe(ctx context.Context, user, key string, sub webpush.Subscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, e := s.PushKey(ctx, user)
	if e != nil {
		return e
	}
	if key != current {
		return fmt.Errorf("push key changed; subscribe again")
	}
	if e = validateSubscription(sub); e != nil {
		return e
	}
	id := hash(sub.Endpoint)
	var owner string
	e = s.Store.Row(ctx, "SELECT username FROM push_subscriptions WHERE endpoint_hash=?", id).Scan(&owner)
	if e == nil && owner != user {
		return fmt.Errorf("browser subscription belongs to another account; disconnect it first")
	}
	var n int
	if e = s.Store.Row(ctx, "SELECT COUNT(*) FROM push_subscriptions WHERE username=?", user).Scan(&n); e != nil {
		return e
	}
	if n >= 10 && owner != user {
		return fmt.Errorf("maximum 10 browser subscriptions per user")
	}
	raw, e := json.Marshal(sub)
	if e != nil {
		return e
	}
	defer clear(raw)
	return s.Store.Exec(ctx, "INSERT INTO push_subscriptions(endpoint_hash,username,subscription,key_id,created_at) VALUES(?,?,?,?,?) ON CONFLICT(endpoint_hash) DO UPDATE SET subscription=excluded.subscription,key_id=excluded.key_id,created_at=excluded.created_at", id, user, s.Vault.Seal(raw, "push:"+user+":"+id), hash(current), time.Now().Unix())
}
func (s *Service) Unsubscribe(ctx context.Context, user, endpoint string) error {
	return s.Store.Exec(ctx, "DELETE FROM push_subscriptions WHERE username=? AND endpoint_hash=?", user, hash(endpoint))
}

// Pin each connection to a freshly resolved public IP; never follow redirects or proxy environment variables.
func publicDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
	if e != nil {
		return nil, fmt.Errorf("push DNS failed")
	}
	for _, addr := range ips {
		ip := addr.IP
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return nil, fmt.Errorf("non-public push destination")
		}
	}
	for _, addr := range ips {
		conn, e := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, network, net.JoinHostPort(addr.IP.String(), port))
		if e == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("push endpoint unavailable")
}
func (s *Service) Push(ctx context.Context, user, title, body string) (sentResult int, resultErr error) {
	started := time.Now()
	defer func() {
		outcome := "success"
		if sentResult == 0 {
			outcome = "empty"
		}
		if resultErr != nil {
			outcome = "error"
		}
		s.Store.Metrics.Observe("push", outcome, resultErr != nil, time.Since(started))
	}()
	c, e := s.effective(ctx, scope(user))
	if e != nil {
		return 0, e
	}
	if c.Push.Mode != "custom" {
		return 0, fmt.Errorf("push disabled")
	}
	rows, e := s.Store.DB.QueryContext(ctx, s.Store.SQL("SELECT endpoint_hash,subscription FROM push_subscriptions WHERE username=? AND key_id=?"), user, hash(c.Push.PublicKey))
	if e != nil {
		return 0, e
	}
	type entry struct{ id, raw string }
	items := []entry{}
	for rows.Next() {
		var v entry
		if e = rows.Scan(&v.id, &v.raw); e != nil {
			rows.Close()
			return 0, e
		}
		items = append(items, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, e
	}
	payload, e := json.Marshal(map[string]string{"title": title, "body": body})
	if e != nil {
		return 0, e
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = publicDial
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 7 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	sent := 0
	failed := false
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for _, v := range items {
		raw, err := s.Vault.Open(v.raw, "push:"+user+":"+v.id)
		if err != nil {
			failed = true
			continue
		}
		var sub webpush.Subscription
		err = json.Unmarshal(raw, &sub)
		clear(raw)
		if err != nil || validateSubscription(sub) != nil {
			failed = true
			continue
		}
		response, err := webpush.SendNotificationWithContext(ctx, payload, &sub, &webpush.Options{HTTPClient: client, Subscriber: c.Push.Contact, VAPIDPublicKey: c.Push.PublicKey, VAPIDPrivateKey: c.Push.PrivateKey, TTL: 300})
		if err != nil {
			failed = true
			continue
		}
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if response.StatusCode == 404 || response.StatusCode == 410 {
			_ = s.Unsubscribe(ctx, user, sub.Endpoint)
		} else if response.StatusCode < 200 || response.StatusCode >= 300 {
			failed = true
		} else {
			sent++
		}
	}
	if failed {
		return sent, fmt.Errorf("push delivery failed")
	}
	return sent, nil
}
