// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package guest

import (
	"context"
	"encoding/base64"
	"github.com/rkislov/border/internal/store"
	"strings"
	"testing"
)

func TestDesignRequiresSignedDomainAndNAS(t *testing.T) {
	s, _, token := fixture(t)
	ctx := t.Context()
	if err := s.Store.Exec(ctx, "INSERT INTO domains(id,name,config,enabled) VALUES('corp','Corp','',1)"); err != nil {
		t.Fatal(err)
	}
	d := store.DefaultPortalDesign()
	d.Custom = true
	d.Title = "Corp"
	if err := s.Store.SavePortalDesign(ctx, "domain:corp", d); err != nil {
		t.Fatal(err)
	}
	signed, err := SignRedirect(Redirect{NAS: "192.0.2.1", MAC: "00:11:22:33:44:55", Domain: "corp"}, "long-test-secret-123")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Design(ctx, signed)
	if err != nil || got.Title != "Corp" {
		t.Fatal(got, err)
	}
	got, err = s.Design(ctx, token)
	if err != nil || got.Title == "Corp" {
		t.Fatal("domain selected without signed context")
	}
	parts := strings.Split(signed, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	parts[0] = base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(raw), "corp", "other", 1)))
	if _, err = s.Design(ctx, strings.Join(parts, ".")); err == nil {
		t.Fatal("tampered domain accepted")
	}
}

func TestPublicMethodsRequireEnabledAndConfiguredChannel(t *testing.T) {
	s, sender, token := fixture(t)
	ctx := t.Context()
	d := store.DefaultPortalDesign()
	d.Custom = true
	d.LoginMethod = "both"
	d.SSOEnabled = true
	d.SSOProviders = []string{"google", "yandex"}
	if err := s.Store.SavePortalDesign(ctx, "tenant", d); err != nil {
		t.Fatal(err)
	}
	configured := []string{"email", "google"}
	s.AvailableChannels = func(_ context.Context, nas, domain string) ([]string, error) {
		if nas != "192.0.2.1" || domain != "" {
			t.Fatal("wrong scope")
		}
		return configured, nil
	}
	got, err := s.Design(ctx, token)
	if err != nil || len(got.Methods) != 1 || got.Methods[0] != "email" {
		t.Fatal(got.Methods, err)
	}
	d.LoginMethod = "sms"
	if err = s.Store.SavePortalDesign(ctx, "tenant", d); err != nil {
		t.Fatal(err)
	}
	got, err = s.Design(ctx, token)
	if err != nil || len(got.Methods) != 0 {
		t.Fatal("unconfigured channel exposed", err)
	}
	configured = []string{"sms", "email"}
	got, err = s.Design(ctx, token)
	if err != nil || len(got.Methods) != 1 || got.Methods[0] != "sms" {
		t.Fatal(got.Methods, err)
	}
	if err = s.Store.Exec(ctx, "UPDATE guest_policy SET enabled=0"); err != nil {
		t.Fatal(err)
	}
	got, err = s.Design(ctx, token)
	if err != nil || len(got.Methods) != 0 || sender.calls != 0 {
		t.Fatal("disabled portal exposed methods or sent messages", err)
	}
}
