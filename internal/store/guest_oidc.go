// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"slices"
	"time"
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

func OIDCPolicyHash(b *BoundPolicy) string {
	raw, _ := json.Marshal(b)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// OIDC authorizes only a dedicated network policy selected for this NAS's MAC flow.
// A password/TOTP policy can never be satisfied by an external identity token.
func (s *Store) GuestOIDCPolicy(ctx context.Context, nas, mac, domain, id string) (*BoundPolicy, OIDCProvider, error) {
	denied := fmt.Errorf("OIDC provider or access policy unavailable")
	var active int
	if err := s.Row(ctx, "SELECT 1 FROM nas n JOIN guest_policy g ON g.id=1 WHERE n.address=? AND n.portal_enabled=1 AND n.access_mode='network' AND g.enabled=1", nas).Scan(&active); err != nil {
		return nil, OIDCProvider{}, denied
	}
	if domain != "" {
		if err := s.Row(ctx, "SELECT 1 FROM domains WHERE id=? AND enabled=1", domain).Scan(&active); err != nil {
			return nil, OIDCProvider{}, denied
		}
	}
	if err := s.Row(ctx, "SELECT 1 FROM mac_auth WHERE mac=?", mac).Scan(&active); err != sql.ErrNoRows {
		return nil, OIDCProvider{}, denied
	}
	d, err := s.EffectivePortalDesign(ctx, nas, domain)
	if err != nil || !d.SSOEnabled || !slices.Contains(d.SSOProviders, id) {
		return nil, OIDCProvider{}, denied
	}
	c, err := s.EffectiveOIDCProvider(ctx, nas, domain, id)
	if err != nil || !c.Enabled {
		return nil, c, denied
	}
	b, _, err := s.SelectPolicy(ctx, nas, PolicyRequest{Protocol: "mab", Username: mac})
	if err != nil || b == nil || b.Authentication.Source != "oidc" || b.Access.Mode != "network" || b.Access.ID != c.AccessPolicyID {
		return nil, c, denied
	}
	if _, err = b.Timeout(time.Now()); err != nil {
		return nil, c, denied
	}
	return b, c, nil
}

func (s *Store) EvaluateGuestOIDC(ctx context.Context, b *BoundPolicy, nas, mac, user string) error {
	c := AccessContext{NAS: nas, MAC: mac, Username: user}
	if err := s.Row(ctx, "SELECT COALESCE(location_id,'') FROM nas WHERE address=?", nas).Scan(&c.Location); err != nil {
		return err
	}
	err := s.Row(ctx, "SELECT os,device_type,manufacturer FROM device_fingerprints WHERE mac=?", mac).Scan(&c.OS, &c.DeviceType, &c.Manufacturer)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	enabled, err := s.IdentityEnabled(ctx, user)
	if err != nil || !enabled {
		return fmt.Errorf("identity disabled")
	}
	ok, _, err := s.EvaluateAccess(ctx, b, c)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("access policy denied")
	}
	return nil
}

type GuestOIDCSession struct {
	ID, NAS, MAC, Identity, ProviderScope, ProviderID, ProviderRevision, DomainID, PolicyID, PolicyHash string
	Expires                                                                                             int64
}

func (s *Store) GuestOIDCSession(ctx context.Context, nas, mac string) (GuestOIDCSession, error) {
	var g GuestOIDCSession
	err := s.Row(ctx, "SELECT id,nas,mac,identity,provider_scope,provider_id,provider_revision,domain_id,policy_id,policy_hash,expires_at FROM guest_oidc_sessions WHERE nas=? AND mac=?", nas, mac).Scan(&g.ID, &g.NAS, &g.MAC, &g.Identity, &g.ProviderScope, &g.ProviderID, &g.ProviderRevision, &g.DomainID, &g.PolicyID, &g.PolicyHash, &g.Expires)
	if err != nil {
		return g, err
	}
	b, c, err := s.GuestOIDCPolicy(ctx, nas, mac, g.DomainID, g.ProviderID)
	if err != nil {
		return g, err
	}
	if g.Expires <= time.Now().Unix() || g.ProviderScope != c.Scope || g.ProviderRevision != c.Revision || g.PolicyHash != OIDCPolicyHash(b) {
		return g, fmt.Errorf("guest authorization changed or expired")
	}
	return g, s.EvaluateGuestOIDC(ctx, b, nas, mac, g.Identity)
}

// This runs in the normal revocation worker, including after restart. Invalid
// grants are latched; re-enabling a provider never restores an old session.
func (s *Store) RefreshOIDCRevocations(ctx context.Context) error {
	rows, err := s.DB.QueryContext(ctx, "SELECT DISTINCT g.token,g.guest_oidc_id,COALESCE(o.nas,''),COALESCE(o.mac,'') FROM access_grants g LEFT JOIN guest_oidc_sessions o ON o.id=g.guest_oidc_id WHERE g.guest_oidc_id<>'' AND g.reason=''")
	if err != nil {
		return err
	}
	type item struct{ token, id, nas, mac string }
	var items []item
	for rows.Next() {
		var i item
		if err = rows.Scan(&i.token, &i.id, &i.nas, &i.mac); err != nil {
			rows.Close()
			return err
		}
		items = append(items, i)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, i := range items {
		g, e := s.GuestOIDCSession(ctx, i.nas, i.mac)
		if e != nil || g.ID != i.id {
			if err = s.Exec(ctx, "UPDATE access_grants SET reason='OIDC access unavailable',next_attempt=0 WHERE token=? AND reason=''", i.token); err != nil {
				return err
			}
			if err = s.Exec(ctx, "DELETE FROM guest_oidc_sessions WHERE id=?", i.id); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) NewGuestOIDCGrant(ctx context.Context, g GuestOIDCSession, b *BoundPolicy, expires int64) (string, error) {
	token := "border:" + uuid.NewString()
	result, err := s.DB.ExecContext(ctx, s.SQL("INSERT INTO access_grants(token,nas,username,policy_id,expires_at,binding_version,guest_oidc_id) SELECT ?,nas,identity,policy_id,?,?,id FROM guest_oidc_sessions WHERE id=? AND expires_at>=?"), token, expires, b.BindingVersion, g.ID, expires)
	if err != nil {
		return "", err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if n != 1 {
		return "", sql.ErrNoRows
	}
	return token, nil
}
