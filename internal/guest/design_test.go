// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package guest

import (
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
