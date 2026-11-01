// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package routeros

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rkislov/border/internal/identity"
	"github.com/rkislov/border/internal/store"
)

func (s *Service) disconnectGuest(ctx context.Context, cfg Config, v store.Session) (bool, error) {
	mac, e := identity.MAC(v.Username)
	if e != nil || mac != v.MAC || v.StartedAt <= 0 || cfg.GuestHotspot == "" {
		return false, fmt.Errorf("HotSpot session identity unavailable")
	}
	var overlaps int
	if e = s.Store.Row(ctx, "SELECT count(*) FROM sessions WHERE nas=? AND username=? AND started_at BETWEEN ? AND ?", v.NAS, v.Username, v.StartedAt-4, v.StartedAt+4).Scan(&overlaps); e != nil || overlaps != 1 {
		return false, fmt.Errorf("ambiguous HotSpot accounting generation")
	}
	selector := `user=` + quote(v.Username) + ` and mac-address=` + quote(strings.ToUpper(mac)) + ` and server=` + quote(cfg.GuestHotspot) + ` and radius=yes`
	query := `:local ids [/ip hotspot active find where ` + selector + `]; :if ([:len $ids] != 1) do={:error "session ambiguous"}; :local id [:pick $ids 0]; :put [:serialize to=json value={"id"=[:tostr $id];"uptime"=([:tonsec [/ip hotspot active get $id uptime]] / 1000000000)}]`
	raw, e := guestCommand(ctx, cfg, query)
	if e != nil {
		return false, e
	}
	var snapshot struct {
		ID     string `json:"id"`
		Uptime int64  `json:"uptime"`
	}
	if e = json.Unmarshal(raw, &snapshot); e != nil || snapshot.ID == "" || snapshot.Uptime < 0 {
		return false, fmt.Errorf("HotSpot session snapshot unavailable")
	}
	delta := time.Now().Unix() - snapshot.Uptime - v.StartedAt
	if delta < -3 || delta > 3 {
		return false, fmt.Errorf("HotSpot session start does not match accounting")
	}
	var generation, token, status string
	if e = s.Store.Row(ctx, "SELECT generation,grant_token,status FROM sessions WHERE nas=? AND session_id=?", v.NAS, v.ID).Scan(&generation, &token, &status); e != nil || generation != v.Generation || token != v.GrantToken || (status != "active" && status != "stale") {
		return false, fmt.Errorf("HotSpot accounting changed")
	}
	// Guard the router's generation and elapsed lifetime again within removal.
	q := `:local ids [/ip hotspot active find where .id=` + quote(snapshot.ID) + ` and ` + selector + `]; :if ([:len $ids] != 1) do={:error "session changed"}; :local id [:pick $ids 0]; :local age ([:tonsec [/ip hotspot active get $id uptime]] / 1000000000); :if (($age < ` + strconv.FormatInt(snapshot.Uptime, 10) + `) or ($age > ` + strconv.FormatInt(snapshot.Uptime+12, 10) + `)) do={:error "session generation changed"}; /ip hotspot active remove $id; :if ([:len [/ip hotspot active find where .id=` + quote(snapshot.ID) + `]] != 0) do={:error "session still active"}; :put "border-hotspot-removed"`
	raw, e = guestCommand(ctx, cfg, q)
	if e != nil {
		return false, e
	}
	if strings.TrimSpace(string(raw)) != "border-hotspot-removed" {
		return false, fmt.Errorf("HotSpot removal not confirmed")
	}
	return true, nil
}
