// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package guest

import (
	"context"
	"errors"
	"github.com/rkislov/border/internal/store"
	"strings"
	"testing"
)

func TestEmailChallengeLifecycle(t *testing.T) {
	s, smsSender, token := fixture(t)
	ctx := t.Context()
	d := store.DefaultPortalDesign()
	d.Custom = true
	d.LoginMethod = "email"
	if err := s.Store.SavePortalDesign(ctx, "tenant", d); err != nil {
		t.Fatal(err)
	}
	var code string
	calls := 0
	s.SendEmail = func(ctx context.Context, nas, domain, to, text string) error {
		calls++
		if nas != "192.0.2.1" || to != "alice@example.org" {
			t.Fatalf("wrong recipient/scope %s %s", nas, to)
		}
		code = strings.TrimSuffix(strings.Fields(text)[3], ".")
		return nil
	}
	if _, err := s.Request(ctx, token, "+79991234567"); err == nil {
		t.Fatal("disabled SMS accepted")
	}
	for _, bad := range []string{"bad", "Name <alice@example.org>", "alice@example.org\r\nBcc: x@y.test"} {
		if _, err := s.RequestContact(ctx, token, "email", bad); err == nil {
			t.Fatal("bad email accepted")
		}
	}
	c, err := s.RequestContact(ctx, token, "email", "alice@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if c.Channel != "email" || c.MaskedContact != "a***@example.org" || calls != 1 || smsSender.calls != 0 {
		t.Fatal("channel mismatch", c, calls)
	}
	var cipher string
	if err = s.Store.Row(ctx, "SELECT phone_cipher FROM guest_challenges WHERE id=?", c.ID).Scan(&cipher); err != nil || strings.Contains(cipher, "alice@example.org") {
		t.Fatal("plaintext contact", err)
	}
	if _, err = s.RequestContact(ctx, token, "email", "alice@example.org"); err == nil {
		t.Fatal("resend limit missing")
	}
	if _, err = s.Confirm(ctx, c.ID, "nototp"); err == nil {
		t.Fatal("invalid code accepted")
	}
	if _, err = s.Confirm(ctx, c.ID, code); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Confirm(ctx, c.ID, code); err == nil {
		t.Fatal("replayed code")
	}
	var masked string
	if err = s.Store.Row(ctx, "SELECT masked_phone FROM guest_sessions WHERE nas='192.0.2.1'").Scan(&masked); err != nil || masked != "a***@example.org" {
		t.Fatal(masked, err)
	}
}
func TestEmailDeliveryFailureInvalidatesCode(t *testing.T) {
	s, _, token := fixture(t)
	ctx := t.Context()
	d := store.DefaultPortalDesign()
	d.Custom = true
	d.LoginMethod = "both"
	if err := s.Store.SavePortalDesign(ctx, "tenant", d); err != nil {
		t.Fatal(err)
	}
	var code string
	s.SendEmail = func(_ context.Context, _, _, _, text string) error {
		code = strings.TrimSuffix(strings.Fields(text)[3], ".")
		return errors.New("delivery failed")
	}
	if _, err := s.RequestContact(ctx, token, "email", "alice@example.org"); err == nil {
		t.Fatal("failed SMTP accepted")
	}
	var id string
	if err := s.Store.Row(ctx, "SELECT id FROM guest_challenges LIMIT 1").Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Confirm(ctx, id, code); err == nil {
		t.Fatal("failed delivery code valid")
	}
}
