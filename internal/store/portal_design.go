// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type PortalDesign struct {
	SSOEnabled                                     bool
	SSOPosition                                    string
	SSOProviders                                   []string
	LoginMethod                                    string
	Custom                                         bool
	Title, Description, RequestLabel, ConfirmLabel string
	Position, ButtonAlign, ButtonPosition          string
	Background                                     string
}

func DefaultPortalDesign() PortalDesign {
	return PortalDesign{LoginMethod: "sms", SSOPosition: "bottom", Title: "Подключение к сети", Description: "Получите код для доступа к сети", RequestLabel: "Получить код", ConfirmLabel: "Подключиться", Position: "center", ButtonAlign: "stretch", ButtonPosition: "bottom"}
}
func (s *Store) ValidatePortalScope(ctx context.Context, scope string) error {
	if scope == "tenant" {
		return nil
	}
	kind, id, ok := strings.Cut(scope, ":")
	if !ok || id == "" {
		return fmt.Errorf("invalid portal scope")
	}
	var n int
	var err error
	switch kind {
	case "domain":
		err = s.Row(ctx, "SELECT 1 FROM domains WHERE id=?", id).Scan(&n)
	case "nas":
		err = s.Row(ctx, "SELECT 1 FROM nas WHERE address=?", id).Scan(&n)
	default:
		return fmt.Errorf("invalid portal scope")
	}
	if err != nil {
		return fmt.Errorf("portal scope not found")
	}
	return nil
}
func (s *Store) PortalDesign(ctx context.Context, scope string) (PortalDesign, error) {
	d := DefaultPortalDesign()
	var raw string
	err := s.Row(ctx, "SELECT value FROM settings WHERE name=?", "portal_design:"+scope).Scan(&raw)
	if err == sql.ErrNoRows {
		return d, nil
	}
	if err != nil {
		return d, err
	}
	err = json.Unmarshal([]byte(raw), &d)
	return d, err
}
func (s *Store) SavePortalDesign(ctx context.Context, scope string, d PortalDesign) error {
	if d.SSOPosition == "" {
		d.SSOPosition = "bottom"
	}
	if d.SSOPosition != "top" && d.SSOPosition != "bottom" {
		return fmt.Errorf("invalid SSO position")
	}
	providers := map[string]bool{"yandex": true, "gosuslugi": true, "google": true, "apple": true, "vk": true, "oidc": true}
	if len(d.SSOProviders) > 6 {
		return fmt.Errorf("too many SSO placeholders")
	}
	for _, id := range d.SSOProviders {
		if !providers[id] {
			return fmt.Errorf("invalid or duplicate SSO provider")
		}
		providers[id] = false
	}
	if d.LoginMethod == "" {
		d.LoginMethod = "sms"
	}
	if d.LoginMethod != "sms" && d.LoginMethod != "email" && d.LoginMethod != "both" {
		return fmt.Errorf("invalid portal login method")
	}
	if err := s.ValidatePortalScope(ctx, scope); err != nil {
		return err
	}
	if len(d.Title) > 150 || len(d.Description) > 1000 || len(d.RequestLabel) > 80 || len(d.ConfirmLabel) > 80 || strings.TrimSpace(d.Title) == "" || strings.TrimSpace(d.RequestLabel) == "" || strings.TrimSpace(d.ConfirmLabel) == "" {
		return fmt.Errorf("invalid portal text")
	}
	if !regexp.MustCompile(`^(top-left|top|top-right|left|center|right|bottom-left|bottom|bottom-right)$`).MatchString(d.Position) || !regexp.MustCompile(`^(left|center|right|stretch)$`).MatchString(d.ButtonAlign) || (d.ButtonPosition != "top" && d.ButtonPosition != "bottom") {
		return fmt.Errorf("invalid portal layout")
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return s.Exec(ctx, "INSERT INTO settings(name,value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", "portal_design:"+scope, string(raw))
}
func (s *Store) EffectivePortalDesign(ctx context.Context, nas, domain string) (PortalDesign, error) {
	scopes := []string{"nas:" + nas}
	if domain != "" {
		scopes = append(scopes, "domain:"+domain)
	}
	scopes = append(scopes, "tenant")
	for _, scope := range scopes {
		d, err := s.PortalDesign(ctx, scope)
		if err != nil {
			return d, err
		}
		if d.Custom {
			return d, nil
		}
	}
	return DefaultPortalDesign(), nil
}
