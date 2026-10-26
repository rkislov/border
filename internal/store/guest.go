// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type GuestPolicy struct {
	Enabled                          bool
	VLAN, SessionSeconds, MaxPerHour int
}
type GuestSession struct {
	NAS, MAC, MaskedPhone string
	VLAN                  int
	Expires               int64
}

func (s *Store) GuestPolicy(ctx context.Context) (GuestPolicy, error) {
	var p GuestPolicy
	var enabled int
	var vlan sql.NullInt64
	err := s.Row(ctx, "SELECT enabled,vlan,session_seconds,max_per_hour FROM guest_policy WHERE id=1").Scan(&enabled, &vlan, &p.SessionSeconds, &p.MaxPerHour)
	p.Enabled = enabled == 1
	p.VLAN = int(vlan.Int64)
	return p, err
}
func (s *Store) SetGuestPolicy(ctx context.Context, p GuestPolicy) error {
	if p.VLAN < 0 || p.VLAN > 4094 || (p.Enabled && p.VLAN == 0) || p.SessionSeconds < 300 || p.SessionSeconds > 86400 || p.MaxPerHour < 1 || p.MaxPerHour > 100000 {
		return fmt.Errorf("guest VLAN required; TTL 300–86400; hourly limit 1–100000")
	}
	var vlan any
	if p.VLAN > 0 {
		vlan = p.VLAN
	}
	enabled := 0
	if p.Enabled {
		enabled = 1
	}
	return s.Exec(ctx, "UPDATE guest_policy SET enabled=?,vlan=?,session_seconds=?,max_per_hour=? WHERE id=1", enabled, vlan, p.SessionSeconds, p.MaxPerHour)
}
func (s *Store) GuestAccess(ctx context.Context, nas, mac string) (int, int64, error) {
	var vlan int
	var expires int64
	err := s.Row(ctx, "SELECT g.vlan,g.expires_at FROM guest_sessions g JOIN nas n ON n.address=g.nas JOIN guest_policy p ON p.id=1 WHERE g.nas=? AND g.mac=? AND g.expires_at>? AND n.portal_enabled=1 AND p.enabled=1", nas, mac, time.Now().Unix()).Scan(&vlan, &expires)
	return vlan, expires, err
}
func (s *Store) GuestSessions(ctx context.Context) ([]GuestSession, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT nas,mac,masked_phone,vlan,expires_at FROM guest_sessions ORDER BY expires_at DESC LIMIT 200")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GuestSession{}
	for rows.Next() {
		var g GuestSession
		if err = rows.Scan(&g.NAS, &g.MAC, &g.MaskedPhone, &g.VLAN, &g.Expires); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
