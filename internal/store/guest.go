// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"fmt"
)

type GuestPolicy struct {
	Enabled    bool
	MaxPerHour int
}
type GuestSession struct {
	ID, NAS, MAC, Identity, Method, MaskedContact, PolicyID, DomainID string
	VLAN                                                              int
	Expires                                                           int64
}

func (s *Store) GuestPolicy(ctx context.Context) (GuestPolicy, error) {
	var p GuestPolicy
	err := s.Row(ctx, "SELECT enabled,max_per_hour FROM guest_policy WHERE id=1").Scan(&p.Enabled, &p.MaxPerHour)
	return p, err
}
func (s *Store) SetGuestPolicy(ctx context.Context, p GuestPolicy) error {
	if p.MaxPerHour < 1 || p.MaxPerHour > 100000 {
		return fmt.Errorf("hourly code limit must be 1–100000")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, s.SQL("UPDATE guest_policy SET generation=generation+CASE WHEN enabled<>? THEN 1 ELSE 0 END,enabled=?,max_per_hour=? WHERE id=1"), integer(p.Enabled), integer(p.Enabled), p.MaxPerHour); err != nil {
		return err
	}
	if !p.Enabled {
		if _, err = tx.ExecContext(ctx, "UPDATE access_grants SET reason='guest portal disabled',next_attempt=0 WHERE reason='' AND guest_authorization_id<>''"); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM guest_authorizations"); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE guest_challenges SET code_digest='',expires_at=0 WHERE verified_at=0"); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) GuestSessions(ctx context.Context) ([]GuestSession, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT g.id,g.nas,g.mac,g.identity,g.method,g.masked_contact,g.policy_id,g.domain_id,COALESCE(n.vlan,l.vlan,0),g.expires_at FROM guest_authorizations g LEFT JOIN access_policies p ON p.id=g.policy_id JOIN nas a ON a.address=g.nas LEFT JOIN nas_segments n ON n.nas=g.nas AND n.segment_id=p.segment_id LEFT JOIN location_segments l ON l.location_id=a.location_id AND l.segment_id=p.segment_id ORDER BY g.expires_at DESC LIMIT 200")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GuestSession{}
	for rows.Next() {
		var g GuestSession
		if err = rows.Scan(&g.ID, &g.NAS, &g.MAC, &g.Identity, &g.Method, &g.MaskedContact, &g.PolicyID, &g.DomainID, &g.VLAN, &g.Expires); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) RevokeGuest(ctx context.Context, nas, mac string, expectedID ...string) error {
	predicate := "nas=? AND mac=?"
	args := []any{nas, mac}
	if len(expectedID) > 0 && expectedID[0] != "" {
		predicate += " AND id=?"
		args = append(args, expectedID[0])
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, s.SQL("UPDATE access_grants SET reason='guest access revoked',next_attempt=0 WHERE reason='' AND guest_authorization_id IN (SELECT id FROM guest_authorizations WHERE "+predicate+")"), args...); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, s.SQL("DELETE FROM guest_authorizations WHERE "+predicate), args...); e != nil {
		return e
	}

	return tx.Commit()
}
