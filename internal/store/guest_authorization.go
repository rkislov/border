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

func (a AuthenticationPolicy) ValidateGuestMethods() error {
	if a.Source != "guest" {
		if len(a.GuestMethods) > 0 {
			return fmt.Errorf("guest methods require guest authentication source")
		}
		return nil
	}
	if len(a.GuestMethods) == 0 || len(a.GuestMethods) > 3 {
		return fmt.Errorf("select SMS, email or OIDC for guest authentication")
	}
	seen := map[string]bool{}
	for _, m := range a.GuestMethods {
		if !slices.Contains([]string{"sms", "email", "oidc"}, m) || seen[m] {
			return fmt.Errorf("invalid or duplicate guest method")
		}
		seen[m] = true
	}
	return nil
}
func (a AuthenticationPolicy) AllowsGuestMethod(method string) bool {
	return a.Source == "guest" && slices.Contains(a.GuestMethods, method) || a.Source == "oidc" && method == "oidc"
}
func GuestPolicyHash(b *BoundPolicy) string {
	raw, _ := json.Marshal(b)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// No fallback to a password policy, legacy VLAN, or a weaker method is allowed.
func (s *Store) GuestAccessPolicy(ctx context.Context, nas, mac, domain, method string) (*BoundPolicy, error) {
	denied := fmt.Errorf("guest method or access policy unavailable")
	var active int
	if err := s.Row(ctx, "SELECT 1 FROM nas n JOIN guest_policy g ON g.id=1 WHERE n.address=? AND n.portal_enabled=1 AND n.access_mode='network' AND g.enabled=1", nas).Scan(&active); err != nil {
		return nil, denied
	}
	if domain != "" {
		if err := s.Row(ctx, "SELECT 1 FROM domains WHERE id=? AND enabled=1", domain).Scan(&active); err != nil {
			return nil, denied
		}
	}
	if err := s.Row(ctx, "SELECT 1 FROM mac_auth WHERE mac=?", mac).Scan(&active); err != sql.ErrNoRows {
		return nil, denied
	}
	d, err := s.EffectivePortalDesign(ctx, nas, domain)
	if err != nil {
		return nil, err
	}
	if method == "oidc" {
		if !d.SSOEnabled {
			return nil, denied
		}
	} else if method != "sms" && method != "email" || d.LoginMethod != "both" && d.LoginMethod != method {
		return nil, denied
	}
	b, _, err := s.SelectPolicy(ctx, nas, PolicyRequest{Protocol: "mab", Username: mac})
	if err != nil || b == nil || b.Access.Mode != "network" || !b.Authentication.AllowsGuestMethod(method) {
		return nil, denied
	}
	if _, err = b.Timeout(time.Now()); err != nil {
		return nil, denied
	}
	return b, nil
}

func (s *Store) EvaluateGuestAccess(ctx context.Context, b *BoundPolicy, nas, mac, user string) error {
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
		return fmt.Errorf("guest access policy denied")
	}
	return nil
}

type GuestAuthorization struct {
	ID, NAS, MAC, Identity, Method, MaskedContact, ProviderScope, ProviderID, ProviderRevision, DomainID, PolicyID, PolicyHash string
	Expires                                                                                                                    int64
}

func (s *Store) GuestAuthorization(ctx context.Context, nas, mac string) (GuestAuthorization, error) {
	var g GuestAuthorization
	err := s.Row(ctx, "SELECT id,nas,mac,identity,method,masked_contact,provider_scope,provider_id,provider_revision,domain_id,policy_id,policy_hash,expires_at FROM guest_authorizations WHERE nas=? AND mac=?", nas, mac).Scan(&g.ID, &g.NAS, &g.MAC, &g.Identity, &g.Method, &g.MaskedContact, &g.ProviderScope, &g.ProviderID, &g.ProviderRevision, &g.DomainID, &g.PolicyID, &g.PolicyHash, &g.Expires)
	if err != nil {
		return g, err
	}
	b, err := s.GuestAccessPolicy(ctx, nas, mac, g.DomainID, g.Method)
	if err != nil {
		return g, err
	}
	if g.Expires <= time.Now().Unix() || g.PolicyID != b.Access.ID || g.PolicyHash != GuestPolicyHash(b) {
		return g, fmt.Errorf("guest authorization changed or expired")
	}
	if g.Method == "oidc" {
		_, c, e := s.GuestOIDCPolicy(ctx, nas, mac, g.DomainID, g.ProviderID)
		if e != nil || g.ProviderScope != c.Scope || g.ProviderRevision != c.Revision {
			return g, fmt.Errorf("OIDC provider changed")
		}
	}
	return g, s.EvaluateGuestAccess(ctx, b, nas, mac, g.Identity)
}

// One authorization per NAS/MAC, independent of how the identity was verified.
// Re-authenticating via another method retires only that device's old grants.
func (s *Store) SaveGuestAuthorization(ctx context.Context, g GuestAuthorization) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE guest_policy SET enabled=enabled WHERE id=1"); err != nil {
		return err
	}
	if g.Method == "oidc" {
		var revision string
		if err = tx.QueryRowContext(ctx, s.SQL("SELECT revision FROM guest_oidc_providers WHERE scope=? AND id=?"), g.ProviderScope, g.ProviderID).Scan(&revision); err != nil || revision != g.ProviderRevision {
			return fmt.Errorf("OIDC provider changed")
		}
	}
	if _, err = tx.ExecContext(ctx, s.SQL("UPDATE access_grants SET reason='guest reauthenticated',next_attempt=0 WHERE reason='' AND guest_authorization_id IN (SELECT id FROM guest_authorizations WHERE nas=? AND mac=?)"), g.NAS, g.MAC); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, s.SQL("INSERT INTO guest_authorizations(id,nas,mac,identity,method,masked_contact,provider_scope,provider_id,provider_revision,domain_id,policy_id,policy_hash,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(nas,mac) DO UPDATE SET id=excluded.id,identity=excluded.identity,method=excluded.method,masked_contact=excluded.masked_contact,provider_scope=excluded.provider_scope,provider_id=excluded.provider_id,provider_revision=excluded.provider_revision,domain_id=excluded.domain_id,policy_id=excluded.policy_id,policy_hash=excluded.policy_hash,expires_at=excluded.expires_at"), g.ID, g.NAS, g.MAC, g.Identity, g.Method, g.MaskedContact, g.ProviderScope, g.ProviderID, g.ProviderRevision, g.DomainID, g.PolicyID, g.PolicyHash, g.Expires); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, s.SQL("INSERT INTO auth_log(id,occurred_at,source,identity,result,reason) VALUES(?,?,?,?,?,?)"), uuid.NewString(), time.Now().Unix(), "guest-"+g.Method, g.Identity, "verified", "policy "+g.PolicyID+" NAS "+g.NAS+" MAC "+g.MAC); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RefreshGuestRevocations(ctx context.Context) error {
	rows, err := s.DB.QueryContext(ctx, "SELECT id,nas,mac FROM guest_authorizations")
	if err != nil {
		return err
	}
	type item struct{ id, nas, mac string }
	var items []item
	for rows.Next() {
		var i item
		if err = rows.Scan(&i.id, &i.nas, &i.mac); err != nil {
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
		g, e := s.GuestAuthorization(ctx, i.nas, i.mac)
		if e == nil && g.ID == i.id {
			continue
		}
		// Delete by generation ID so a concurrent new login is never removed.
		if err = s.Exec(ctx, "DELETE FROM guest_authorizations WHERE id=?", i.id); err != nil {
			return err
		}
	}
	return s.Exec(ctx, "UPDATE access_grants SET reason='guest authorization unavailable',next_attempt=0 WHERE reason='' AND guest_authorization_id<>'' AND NOT EXISTS(SELECT 1 FROM guest_authorizations g WHERE g.id=access_grants.guest_authorization_id)")
}

func (s *Store) NewGuestGrant(ctx context.Context, g GuestAuthorization, b *BoundPolicy, expires int64) (string, error) {
	token := "border:" + uuid.NewString()
	result, err := s.DB.ExecContext(ctx, s.SQL("INSERT INTO access_grants(token,nas,username,policy_id,expires_at,binding_version,guest_authorization_id) SELECT ?,nas,identity,policy_id,?,?,id FROM guest_authorizations WHERE id=? AND expires_at>=?"), token, expires, b.BindingVersion, g.ID, expires)
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

// Publication must also retire grants which have not yet reached Accounting.
// Otherwise rolling back a policy could resurrect a previously verified login.
func (s *Store) retirePublishedGuests(ctx context.Context, tx *sql.Tx, targets impactTargets) error {
	for _, table := range []string{"guest_authorizations", "guest_challenges"} {
		rows, err := tx.QueryContext(ctx, "SELECT id,nas,policy_id FROM "+table)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id, nas, policy string
			if err = rows.Scan(&id, &nas, &policy); err != nil {
				rows.Close()
				return err
			}
			if targets.matches(nas, policy) {
				ids = append(ids, id)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, id := range ids {
			q := "DELETE FROM guest_authorizations WHERE id=?"
			if table == "guest_challenges" {
				q = "UPDATE guest_challenges SET code_digest='',expires_at=0 WHERE id=? AND verified_at=0"
			}
			if _, err = tx.ExecContext(ctx, s.SQL(q), id); err != nil {
				return err
			}
		}
	}
	return nil
}
