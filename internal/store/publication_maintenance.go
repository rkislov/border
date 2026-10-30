// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"
)

// Days use ISO weekday numbers: Monday=1, Sunday=7. End is exclusive.
type PublicationWindow struct {
	Days       []int
	Start, End string
}
type PublicationWindowSettings struct {
	Revision        int64
	Enabled         bool
	Timezone        string
	MaxDelaySeconds int64
	Windows         []PublicationWindow
}

func scanPublicationWindows(scan func(...any) error) (PublicationWindowSettings, error) {
	var v PublicationWindowSettings
	var raw string
	e := scan(&v.Revision, &v.Enabled, &v.Timezone, &v.MaxDelaySeconds, &raw)
	if e != nil {
		return v, e
	}
	e = json.Unmarshal([]byte(raw), &v.Windows)
	return v, e
}

const publicationWindowColumns = "revision,enabled,timezone,max_delay_seconds,windows"

func (s *Store) PublicationWindows(ctx context.Context) (PublicationWindowSettings, error) {
	return scanPublicationWindows(s.Row(ctx, "SELECT "+publicationWindowColumns+" FROM publication_window_settings WHERE id=1").Scan)
}
func (s *Store) publicationWindowsTx(ctx context.Context, tx *sql.Tx) (PublicationWindowSettings, error) {
	return scanPublicationWindows(tx.QueryRowContext(ctx, "SELECT "+publicationWindowColumns+" FROM publication_window_settings WHERE id=1").Scan)
}
func windowMinute(value string, end bool) (int, error) {
	if end && value == "24:00" {
		return 1440, nil
	}
	if len(value) != 5 || value[2] != ':' {
		return 0, fmt.Errorf("maintenance: invalid time")
	}
	p := strings.Split(value, ":")
	h, e := strconv.Atoi(p[0])
	if e != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("maintenance: invalid time")
	}
	m, e := strconv.Atoi(p[1])
	if e != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("maintenance: invalid time")
	}
	if fmt.Sprintf("%02d:%02d", h, m) != value {
		return 0, fmt.Errorf("maintenance: invalid time")
	}
	return h*60 + m, nil
}
func (v PublicationWindowSettings) Validate() error {
	if len(v.Timezone) > 100 {
		return fmt.Errorf("maintenance: invalid timezone")
	}
	if _, e := time.LoadLocation(v.Timezone); e != nil || v.Timezone == "" || v.Timezone == "Local" {
		return fmt.Errorf("maintenance: invalid timezone")
	}
	if v.MaxDelaySeconds < 60 || v.MaxDelaySeconds > 7*86400 {
		return fmt.Errorf("maintenance: delay must be between 60 and 604800 seconds")
	}
	if len(v.Windows) > 32 || (v.Enabled && len(v.Windows) == 0) {
		return fmt.Errorf("maintenance: configure between 1 and 32 windows")
	}
	for _, w := range v.Windows {
		start, e := windowMinute(w.Start, false)
		if e != nil {
			return e
		}
		end, e := windowMinute(w.End, true)
		if e != nil {
			return e
		}
		if start == end || len(w.Days) == 0 || len(w.Days) > 7 {
			return fmt.Errorf("maintenance: invalid interval or days")
		}
		seen := map[int]bool{}
		for _, d := range w.Days {
			if d < 1 || d > 7 || seen[d] {
				return fmt.Errorf("maintenance: invalid interval or days")
			}
			seen[d] = true
		}
	}
	return nil
}
func (v PublicationWindowSettings) Allows(now time.Time) (bool, error) {
	if e := v.Validate(); e != nil {
		return false, e
	}
	if !v.Enabled {
		return true, nil
	}
	loc, _ := time.LoadLocation(v.Timezone)
	local := now.In(loc)
	day := int(local.Weekday())
	if day == 0 {
		day = 7
	}
	previous := (day+5)%7 + 1
	minute := local.Hour()*60 + local.Minute()
	for _, w := range v.Windows {
		start, _ := windowMinute(w.Start, false)
		end, _ := windowMinute(w.End, true)
		for _, d := range w.Days {
			if start < end {
				if d == day && minute >= start && minute < end {
					return true, nil
				}
			} else if (d == day && minute >= start) || (d == previous && minute < end) {
				return true, nil
			}
		}
	}
	return false, nil
}
func (s *Store) SavePublicationWindows(ctx context.Context, v PublicationWindowSettings, actor string) error {
	if e := v.Validate(); e != nil {
		return e
	}
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = s.reviewAdmin(ctx, tx, actor); e != nil {
		return e
	}
	old, e := s.publicationWindowsTx(ctx, tx)
	if e != nil {
		return e
	}
	if v.Revision != old.Revision {
		return fmt.Errorf("maintenance: settings changed; reload")
	}
	raw, e := json.Marshal(v.Windows)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, s.SQL("UPDATE publication_window_settings SET revision=revision+1,enabled=?,timezone=?,max_delay_seconds=?,windows=? WHERE id=1"), integer(v.Enabled), v.Timezone, v.MaxDelaySeconds, string(raw))
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, s.SQL("UPDATE policy_schedules SET expires_at=due_at+? WHERE state='pending' AND expires_at>due_at+?"), v.MaxDelaySeconds, v.MaxDelaySeconds); e != nil {
		return e
	}
	if e = s.reviewAudit(ctx, tx, actor, "maintenance settings changed revision "+strconv.FormatInt(old.Revision+1, 10)); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) checkPublicationWindow(ctx context.Context, tx *sql.Tx, now time.Time) error {
	v, e := s.publicationWindowsTx(ctx, tx)
	if e != nil {
		return e
	}
	allowed, e := v.Allows(now)
	if e != nil {
		return e
	}
	if !allowed {
		return fmt.Errorf("maintenance: outside allowed publication window")
	}
	return nil
}
