// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"context"
	"database/sql"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// Called-Station-Id is interpreted only in the RFC3580 BSSID:SSID form.
func policyContext(ctx context.Context, s *store.Store, p *radius.Packet, host, user string, groups []string) (store.AccessContext, error) {
	c := store.AccessContext{NAS: host, Username: user, DirectoryGroups: groups}
	if e := s.Row(ctx, "SELECT COALESCE(location_id,'') FROM nas WHERE address=?", host).Scan(&c.Location); e != nil {
		return c, e
	}
	called := rfc2865.CalledStationID_GetString(p)
	if len(called) > 18 && called[17] == ':' {
		if _, e := NormalizeMAC(called[:17]); e == nil && len(called[18:]) <= 32 {
			c.SSID = called[18:]
		}
	}
	mac, e := NormalizeMAC(rfc2865.CallingStationID_GetString(p))
	if e != nil {
		return c, nil
	}
	c.MAC = mac
	e = s.Row(ctx, "SELECT os,device_type,manufacturer FROM device_fingerprints WHERE mac=?", mac).Scan(&c.OS, &c.DeviceType, &c.Manufacturer)
	if e == sql.ErrNoRows {
		return c, nil
	}
	return c, e
}
func evaluatePolicy(ctx context.Context, s *store.Store, p *radius.Packet, host, user string, groups []string, b *store.BoundPolicy) (bool, string, error) {
	c, e := policyContext(ctx, s, p, host, user, groups)
	if e != nil {
		return false, "context unavailable", e
	}
	return s.EvaluateAccess(ctx, b, c)
}
