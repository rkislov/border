// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package notification

import (
	"context"
	"encoding/json"
	"fmt"
	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/rkislov/border/internal/store"
	"io"
	"log/slog"
	"net/http"
	netmail "net/mail"
	"regexp"
	"strings"
	"time"
)

type PolicyRecipient struct {
	Channel, Scope, Destination string
	Enabled                     bool
}

func (s *Service) SavePolicyRecipient(ctx context.Context, user string, v PolicyRecipient) error {
	if v.Channel != "email" && v.Channel != "sms" {
		return fmt.Errorf("use browser subscription for push")
	}
	if v.Scope == "" {
		v.Scope = "default"
	}
	if e := s.validScope(ctx, v.Scope); e != nil {
		return e
	}
	v.Destination = strings.TrimSpace(v.Destination)
	if v.Enabled && v.Channel == "email" {
		a, e := netmail.ParseAddress(v.Destination)
		if e != nil || strings.ContainsAny(v.Destination, "\r\n") {
			return fmt.Errorf("invalid email")
		}
		v.Destination = a.Address
	}
	if v.Enabled && v.Channel == "sms" && !regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`).MatchString(v.Destination) {
		return fmt.Errorf("phone must use international format")
	}
	if len(v.Destination) > 320 {
		return fmt.Errorf("destination too long")
	}
	return s.Store.SavePolicyNotificationTarget(ctx, store.PolicyNotificationTarget{Username: user, Channel: v.Channel, Scope: v.Scope, Destination: v.Destination, Enabled: v.Enabled})
}
func (s *Service) SubscribePolicy(ctx context.Context, user, id, key string, sub webpush.Subscription) error {
	if s.Vault == nil {
		return fmt.Errorf("master key required")
	}
	if id == "" {
		id = "default"
	}
	c, e := s.effective(ctx, id)
	if e != nil {
		return e
	}
	if c.Push.Mode != "custom" || c.Push.PublicKey != key {
		return fmt.Errorf("push key changed or push disabled")
	}
	if e = validateSubscription(sub); e != nil {
		return e
	}
	raw, e := json.Marshal(struct {
		Subscription webpush.Subscription
		Key          string
	}{sub, hash(key)})
	if e != nil {
		return e
	}
	defer clear(raw)
	return s.Store.SavePolicyNotificationTarget(ctx, store.PolicyNotificationTarget{Username: user, Channel: "push", Scope: id, EndpointHash: hash(sub.Endpoint), Destination: s.Vault.Seal(raw, "policy-push:"+user), Enabled: true})
}
func (s *Service) SendPolicyDelivery(ctx context.Context, j store.PolicyDeliveryJob) error {
	tenant := s.Tenant
	if tenant == "" {
		tenant = "default"
	}
	title := "Border [" + tenant + "]: согласование и публикация"
	body := j.Message + "\nID уведомления: " + j.ID
	switch j.Target.Channel {
	case "email":
		c, e := s.effective(ctx, j.Target.Scope)
		if e != nil {
			return e
		}
		if c.SMTP.Mode != "custom" {
			return fmt.Errorf("SMTP disabled")
		}
		sender, e := smtpSender(c.SMTP)
		if e != nil {
			return e
		}
		return sender.SendWithID(ctx, j.Target.Destination, title, body, j.ID)
	case "sms":
		return s.SendSMS(ctx, j.Target.Scope+"/administrator", j.Target.Destination, body)
	case "push":
		if s.Vault == nil {
			return fmt.Errorf("push unavailable")
		}
		c, e := s.effective(ctx, j.Target.Scope)
		if e != nil {
			return e
		}
		if c.Push.Mode != "custom" {
			return fmt.Errorf("push disabled")
		}
		raw, e := s.Vault.Open(j.Target.Destination, "policy-push:"+j.Target.Username)
		if e != nil {
			return fmt.Errorf("push subscription unavailable")
		}
		defer clear(raw)
		var saved struct {
			Subscription webpush.Subscription
			Key          string
		}
		if json.Unmarshal(raw, &saved) != nil || validateSubscription(saved.Subscription) != nil || saved.Key != hash(c.Push.PublicKey) {
			return fmt.Errorf("push subscription changed; subscribe again")
		}
		payload, _ := json.Marshal(map[string]string{"title": title, "body": j.Message, "tag": j.ID})
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.DialContext = publicDial
		defer transport.CloseIdleConnections()
		client := &http.Client{Timeout: 7 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		response, e := webpush.SendNotificationWithContext(ctx, payload, &saved.Subscription, &webpush.Options{HTTPClient: client, Subscriber: c.Push.Contact, VAPIDPublicKey: c.Push.PublicKey, VAPIDPrivateKey: c.Push.PrivateKey, TTL: 3600, Topic: hash(j.ID)[:32]})
		if e != nil {
			return fmt.Errorf("push delivery failed")
		}
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return fmt.Errorf("push provider rejected delivery")
		}
		return nil
	}
	return fmt.Errorf("unsupported notification channel")
}

// Delivery occurs outside database transactions. The lease is longer than the
// bounded network attempt and a fencing token protects completion after recovery.
func (s *Service) DeliverPolicies(ctx context.Context, send func(context.Context, store.PolicyDeliveryJob) error) error {
	for range 20 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		j, e := s.Store.ClaimPolicyDelivery(ctx, time.Now().Unix())
		if e != nil {
			return e
		}
		if j == nil {
			return nil
		}
		run, cancel := context.WithTimeout(ctx, 25*time.Second)
		started := time.Now()
		err := send(run, *j)
		s.Store.Metrics.Finish("policy_notification_delivery", started, err)
		cancel()
		reason := ""
		if err != nil {
			reason = "delivery failed; check channel configuration and provider availability"
		}
		if e = s.Store.FinishPolicyDelivery(ctx, *j, err == nil, reason, time.Now().Unix()); e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) StartPolicyDeliveries(parent context.Context) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			started := time.Now()
			e := s.DeliverPolicies(ctx, s.SendPolicyDelivery)
			s.Store.Metrics.Finish("policy_notifications", started, e)
			if e != nil && ctx.Err() == nil {
				slog.Error("policy notification queue failed", "error", e)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}
