// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
)

// Credentials are kept in a separate encrypted column, never in this public configuration.
type OIDCProvider struct {
	Scope, ID, Name, Issuer, ClientID, AccessPolicyID, AuthStyle string
	Enabled, AllowPrivateNetwork, HasSecret                      bool
	EmailDomains                                                 []string
	Revision                                                     string
}

func (s *Store) OIDCProviders(ctx context.Context, scope string) ([]OIDCProvider, error) {
	rows, err := s.DB.QueryContext(ctx, s.SQL("SELECT config,revision,secret<>'' FROM guest_oidc_providers WHERE scope=? ORDER BY id"), scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OIDCProvider{}
	for rows.Next() {
		var raw string
		var c OIDCProvider
		if err = rows.Scan(&raw, &c.Revision, &c.HasSecret); err != nil {
			return nil, err
		}
		revision, secret := c.Revision, c.HasSecret
		if err = json.Unmarshal([]byte(raw), &c); err != nil {
			return nil, err
		}
		c.Revision, c.HasSecret = revision, secret
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) EffectiveOIDCProvider(ctx context.Context, nas, domain, id string) (OIDCProvider, error) {
	scopes := []string{"nas:" + nas}
	if domain != "" {
		scopes = append(scopes, "domain:"+domain)
	}
	scopes = append(scopes, "tenant")
	for _, scope := range scopes {
		list, err := s.OIDCProviders(ctx, scope)
		if err != nil {
			return OIDCProvider{}, err
		}
		for _, c := range list {
			if c.ID == id {
				return c, nil
			}
		}
	}
	return OIDCProvider{}, sql.ErrNoRows
}

// Provider binding adds OIDC-specific requirements to the shared guest policy.
func (s *Store) GuestOIDCPolicy(ctx context.Context, nas, mac, domain, id string) (*BoundPolicy, OIDCProvider, error) {
	b, err := s.GuestAccessPolicy(ctx, nas, mac, domain, "oidc")
	if err != nil {
		return nil, OIDCProvider{}, err
	}
	d, err := s.EffectivePortalDesign(ctx, nas, domain)
	if err != nil || !slices.Contains(d.SSOProviders, id) {
		return nil, OIDCProvider{}, fmt.Errorf("OIDC button unavailable")
	}
	c, err := s.EffectiveOIDCProvider(ctx, nas, domain, id)
	if err != nil || !c.Enabled || c.AccessPolicyID != b.Access.ID {
		return nil, c, fmt.Errorf("OIDC provider or access policy unavailable")
	}
	return b, c, nil
}
