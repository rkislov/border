// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package guest

import (
	"context"
	"fmt"
	"github.com/rkislov/border/internal/store"
	"time"
)

// All verified methods enter the same policy and persistence path. A successful
// contact verification alone never grants the legacy global guest VLAN.
func (s *Service) authorizeGuest(ctx context.Context, g store.GuestAuthorization) (Grant, error) {
	denied := fmt.Errorf("политика гостевого доступа изменилась или не разрешает вход; откройте портал заново")
	b, err := s.Store.GuestAccessPolicy(ctx, g.NAS, g.MAC, g.DomainID, g.Method)
	if err != nil || g.PolicyID != b.Access.ID || g.PolicyHash != store.GuestPolicyHash(b) {
		return Grant{}, denied
	}
	if g.Method == "oidc" {
		_, c, e := s.Store.GuestOIDCPolicy(ctx, g.NAS, g.MAC, g.DomainID, g.ProviderID)
		if e != nil || c.Scope != g.ProviderScope || c.Revision != g.ProviderRevision {
			return Grant{}, denied
		}
	}
	if err = s.Store.EvaluateGuestAccess(ctx, b, g.NAS, g.MAC, g.Identity); err != nil {
		return Grant{}, denied
	}
	ttl, err := b.Timeout(time.Now())
	if err != nil {
		return Grant{}, denied
	}
	expires := time.Now().Unix() + int64(ttl)
	if g.Expires > 0 {
		expires = min(expires, g.Expires)
	}
	if expires <= time.Now().Unix() {
		return Grant{}, denied
	}
	g.ID = randomID()
	g.Expires = expires
	if s.Activate != nil {
		g.ActivationState = "pending"
	}
	if err = s.Store.SaveGuestAuthorization(ctx, g); err != nil {
		return Grant{}, err
	}
	current, err := s.Store.GuestAuthorization(ctx, g.NAS, g.MAC)
	if err != nil || current.ID != g.ID {
		_ = s.Store.Exec(ctx, "DELETE FROM guest_authorizations WHERE id=?", g.ID)
		return Grant{}, denied
	}
	state := "manual"
	if s.Activate != nil {
		state = "pending"
	}
	return Grant{Expires: g.Expires, VLAN: b.VLAN, ReconnectRequired: state == "manual", ActivationState: state, StatusToken: g.ID + "." + s.digest("guest-status", g.ID)}, nil
}
