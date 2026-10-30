// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import "testing"

func TestPortalDesignInheritanceAndIsolation(t *testing.T) {
	s := ruleStore(t)
	other := ruleStore(t)
	ctx := t.Context()
	for _, q := range []string{"INSERT INTO domains(id,name,config,enabled) VALUES('corp','Corp','',1)", "INSERT INTO nas(address,name,secret) VALUES('192.0.2.1','NAS','secret')"} {
		if err := s.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	for _, scope := range []string{"tenant", "domain:corp", "nas:192.0.2.1"} {
		d := DefaultPortalDesign()
		d.Custom = true
		d.Title = scope
		if err := s.SavePortalDesign(ctx, scope, d); err != nil {
			t.Fatal(err)
		}
		got, err := s.EffectivePortalDesign(ctx, "192.0.2.1", "corp")
		if err != nil || got.Title != scope {
			t.Fatal(got, err)
		}
	}
	d, _ := s.PortalDesign(ctx, "nas:192.0.2.1")
	d.Custom = false
	if err := s.SavePortalDesign(ctx, "nas:192.0.2.1", d); err != nil {
		t.Fatal(err)
	}
	got, err := s.EffectivePortalDesign(ctx, "192.0.2.1", "corp")
	if err != nil || got.Title != "domain:corp" {
		t.Fatal(got, err)
	}
	got, err = other.EffectivePortalDesign(ctx, "192.0.2.1", "corp")
	if err != nil || got.Title != DefaultPortalDesign().Title {
		t.Fatal("tenant leak", got, err)
	}
	if s.SavePortalDesign(ctx, "domain:missing", d) == nil {
		t.Fatal("unknown domain accepted")
	}
	d.Position = "url(javascript:bad)"
	if s.SavePortalDesign(ctx, "tenant", d) == nil {
		t.Fatal("invalid layout accepted")
	}
}

func TestPortalChannelsAndSSOPlaceholders(t *testing.T) {
	s := ruleStore(t)
	d := DefaultPortalDesign()
	d.Custom = true
	d.LoginMethod = "both"
	d.SSOEnabled = true
	d.SSOPosition = "top"
	d.SSOProviders = []string{"yandex", "gosuslugi", "google", "apple", "vk", "oidc"}
	if err := s.SavePortalDesign(t.Context(), "tenant", d); err != nil {
		t.Fatal(err)
	}
	got, err := s.PortalDesign(t.Context(), "tenant")
	if err != nil || got.LoginMethod != "both" || !got.SSOEnabled || len(got.SSOProviders) != 6 {
		t.Fatal(got, err)
	}
	for _, ids := range [][]string{{"google", "google"}, {"javascript:alert(1)"}} {
		d.SSOProviders = ids
		if s.SavePortalDesign(t.Context(), "tenant", d) == nil {
			t.Fatal("invalid SSO accepted")
		}
	}
	d.SSOProviders = nil
	d.LoginMethod = "password"
	if s.SavePortalDesign(t.Context(), "tenant", d) == nil {
		t.Fatal("unknown login accepted")
	}
}
