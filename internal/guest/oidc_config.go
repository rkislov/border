// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package guest

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/rkislov/border/internal/store"
)

type OIDCConfiguration struct {
	store.OIDCProvider
	ClientSecret string
}

func (s *Service) SaveOIDCProvider(ctx context.Context, c OIDCConfiguration) error {
	if err := s.Store.ValidatePortalScope(ctx, c.Scope); err != nil {
		return err
	}
	if !slices.Contains([]string{"oidc", "google", "yandex", "gosuslugi", "apple", "vk"}, c.ID) || strings.TrimSpace(c.Name) == "" || len(c.Name) > 80 {
		return fmt.Errorf("select a provider slot and name")
	}
	if err := oidcURL(c.Issuer); err != nil {
		return fmt.Errorf("Issuer must be an HTTPS URL without credentials or fragment")
	}
	issuer, _ := url.Parse(c.Issuer)
	if issuer.RawQuery != "" {
		return fmt.Errorf("Issuer must not contain a query")
	}
	if c.ClientID == "" || len(c.ClientID) > 512 || len(c.ClientSecret) > 4096 {
		return fmt.Errorf("Client ID required; credential too long")
	}
	if c.AuthStyle != "basic" && c.AuthStyle != "post" && c.AuthStyle != "none" {
		return fmt.Errorf("select basic, post or none client authentication")
	}
	if len(c.EmailDomains) > 20 {
		return fmt.Errorf("maximum 20 email domains")
	}
	for i, d := range c.EmailDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if len(d) > 253 || !strings.Contains(d, ".") || strings.ContainsAny(d, " /@:\r\n\t") || d == "" {
			return fmt.Errorf("invalid email domain")
		}
		c.EmailDomains[i] = d
	}
	var source, mode string
	if err := s.Store.Row(ctx, "SELECT a.source,p.mode FROM access_policies p JOIN authentication_policies a ON a.id=p.authentication_id WHERE p.id=?", c.AccessPolicyID).Scan(&source, &mode); err != nil || source != "oidc" || mode != "network" {
		return fmt.Errorf("select a published network access policy with OIDC authentication")
	}
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Serialize first inserts and updates across processes before checking revision.
	if _, err = tx.ExecContext(ctx, "UPDATE guest_policy SET enabled=enabled WHERE id=1"); err != nil {
		return err
	}
	var raw, secret, revision string
	err = tx.QueryRowContext(ctx, s.Store.SQL("SELECT config,secret,revision FROM guest_oidc_providers WHERE scope=? AND id=?"), c.Scope, c.ID).Scan(&raw, &secret, &revision)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if revision != c.Revision {
		return fmt.Errorf("provider changed; reload settings")
	}
	var old store.OIDCProvider
	if raw != "" && json.Unmarshal([]byte(raw), &old) != nil {
		return fmt.Errorf("invalid stored provider")
	}
	if old.Issuer != c.Issuer || old.ClientID != c.ClientID || old.AuthStyle != c.AuthStyle {
		secret = ""
	}
	if c.ClientSecret != "" {
		secret = s.Vault.Seal([]byte(c.ClientSecret), "guest-oidc:"+c.Scope+":"+c.ID)
	}
	if c.AuthStyle == "none" {
		secret = ""
	}
	if c.Enabled && c.AuthStyle != "none" && secret == "" {
		return fmt.Errorf("Client Secret required")
	}
	c.ClientSecret = ""
	c.Revision = randomID()
	c.HasSecret = false
	data, _ := json.Marshal(c.OIDCProvider)
	if _, err = tx.ExecContext(ctx, s.Store.SQL("INSERT INTO guest_oidc_providers(scope,id,config,secret,revision) VALUES(?,?,?,?,?) ON CONFLICT(scope,id) DO UPDATE SET config=excluded.config,secret=excluded.secret,revision=excluded.revision"), c.Scope, c.ID, string(data), secret, c.Revision); err != nil {
		return err
	}
	// Scope overrides and credential changes retire previous grants immediately.
	predicate := "provider_id=?"
	args := []any{c.ID}
	if strings.HasPrefix(c.Scope, "nas:") {
		predicate += " AND nas=?"
		args = append(args, strings.TrimPrefix(c.Scope, "nas:"))
	}
	if strings.HasPrefix(c.Scope, "domain:") {
		predicate += " AND domain_id=?"
		args = append(args, strings.TrimPrefix(c.Scope, "domain:"))
	}
	if _, err = tx.ExecContext(ctx, s.Store.SQL("UPDATE access_grants SET reason='OIDC provider changed',next_attempt=0 WHERE reason='' AND guest_oidc_id IN (SELECT id FROM guest_oidc_sessions WHERE "+predicate+")"), args...); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, s.Store.SQL("DELETE FROM guest_oidc_sessions WHERE "+predicate), args...); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) oidcSecret(ctx context.Context, c store.OIDCProvider) (string, error) {
	var encrypted string
	if err := s.Store.Row(ctx, "SELECT secret FROM guest_oidc_providers WHERE scope=? AND id=? AND revision=?", c.Scope, c.ID, c.Revision).Scan(&encrypted); err != nil {
		return "", err
	}
	if encrypted == "" {
		return "", nil
	}
	raw, err := s.Vault.Open(encrypted, "guest-oidc:"+c.Scope+":"+c.ID)
	defer clear(raw)
	return string(raw), err
}

func (s *Service) OIDCCallbackURL() (string, error) {
	if err := oidcURL(s.PublicURL); err != nil {
		return "", fmt.Errorf("public portal HTTPS URL required")
	}
	u, _ := url.Parse(s.PublicURL)
	if u.RawQuery != "" {
		return "", fmt.Errorf("public URL query not allowed")
	}
	return strings.TrimSuffix(s.PublicURL, "/") + "/api/guest/oidc/callback", nil
}
