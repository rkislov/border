// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package nascontrol

import (
	"context"
	"github.com/rkislov/border/internal/guest"
	"github.com/rkislov/border/internal/netcraze"
	"github.com/rkislov/border/internal/routeros"
	"github.com/rkislov/border/internal/store"
)

// Each tenant owns its store, vault and public URL. No client/session state is
// shared across tenants or management endpoints.
func ConfigureGuest(g *guest.Service) {
	g.Activate = func(ctx context.Context, a store.GuestAuthorization, vlan int) (bool, error) {
		var dictionary string
		if e := g.Store.Row(ctx, "SELECT dictionary FROM nas WHERE address=?", a.NAS).Scan(&dictionary); e != nil {
			return true, e
		}
		switch dictionary {
		case "keenetic":
			return (&netcraze.Service{Store: g.Store, Vault: g.Vault, PublicURL: g.PublicURL}).ActivateGuest(ctx, a, vlan)
		case "mikrotik":
			return (&routeros.Service{Store: g.Store, Vault: g.Vault}).ActivateGuest(ctx, a, vlan)
		default:
			return false, nil
		}
	}
	g.CaptiveRedirect = func(ctx context.Context, nas, query, publicURL string) (string, error) {
		return (&netcraze.Service{Store: g.Store, Vault: g.Vault, PublicURL: publicURL}).Redirect(ctx, nas, query, publicURL)
	}
}
