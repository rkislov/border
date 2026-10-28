// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type RetentionPolicy struct {
	AuditDays, SessionDays                int
	LastRun                               int64
	LastAuditDeleted, LastSessionsDeleted int64
}

func (p RetentionPolicy) Validate() error {
	for _, days := range []int{p.AuditDays, p.SessionDays} {
		if days != 0 && (days < 7 || days > 3650) {
			return fmt.Errorf("retention: 0 (disabled) or 7–3650 days")
		}
	}
	return nil
}
func (s *Store) Retention(ctx context.Context) (RetentionPolicy, error) {
	var p RetentionPolicy
	var raw string
	err := s.Row(ctx, "SELECT value FROM settings WHERE name='history_retention'").Scan(&raw)
	if err == sql.ErrNoRows {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	err = json.Unmarshal([]byte(raw), &p)
	if err == nil {
		err = p.Validate()
	}
	return p, err
}
func (s *Store) SaveRetention(ctx context.Context, p RetentionPolicy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	// Only configuration is writable via API; a saved policy starts fresh run statistics.
	raw, err := json.Marshal(RetentionPolicy{AuditDays: p.AuditDays, SessionDays: p.SessionDays})
	if err != nil {
		return err
	}
	return s.Exec(ctx, "INSERT INTO settings(name,value) VALUES('history_retention',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", string(raw))
}

type RetentionPreview struct{ AuditEvents, ClosedSessions int64 }

func (s *Store) PreviewRetention(ctx context.Context, p RetentionPolicy, now time.Time) (RetentionPreview, error) {
	var out RetentionPreview
	if err := p.Validate(); err != nil {
		return out, err
	}
	if p.AuditDays > 0 {
		if err := s.Row(ctx, "SELECT COUNT(*) FROM auth_log WHERE occurred_at<?", now.Unix()-int64(p.AuditDays)*86400).Scan(&out.AuditEvents); err != nil {
			return out, err
		}
	}
	if p.SessionDays > 0 {
		if err := s.Row(ctx, "SELECT COUNT(*) FROM sessions WHERE status IN ('stopped','disconnect-ack') AND updated_at<?", now.Unix()-int64(p.SessionDays)*86400).Scan(&out.ClosedSessions); err != nil {
			return out, err
		}
	}
	return out, nil
}

// PruneHistory is bounded and serialized with policy updates and NAS accounting.
// Replay metadata is retained even after removing the user-facing session row.
func (s *Store) PruneHistory(ctx context.Context, now time.Time) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	exec := func(q string, args ...any) (sql.Result, error) { return tx.ExecContext(ctx, s.SQL(q), args...) }
	result, err := exec("UPDATE settings SET value=value WHERE name='history_retention'")
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return tx.Commit()
	}
	var raw string
	if err = tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE name='history_retention'").Scan(&raw); err != nil {
		return err
	}
	var p RetentionPolicy
	if err = json.Unmarshal([]byte(raw), &p); err != nil {
		return err
	}
	if err = p.Validate(); err != nil {
		return err
	}
	if p.AuditDays == 0 && p.SessionDays == 0 || p.LastRun > now.Unix()-60 {
		return tx.Commit()
	}
	p.LastAuditDeleted = 0
	p.LastSessionsDeleted = 0
	if p.AuditDays > 0 {
		result, err = exec("DELETE FROM auth_log WHERE id IN (SELECT id FROM auth_log WHERE occurred_at<? ORDER BY occurred_at,id LIMIT 500)", now.Unix()-int64(p.AuditDays)*86400)
		if err != nil {
			return err
		}
		p.LastAuditDeleted, err = result.RowsAffected()
		if err != nil {
			return err
		}
	}
	if p.SessionDays > 0 {
		cutoff := now.Unix() - int64(p.SessionDays)*86400
		rows, e := tx.QueryContext(ctx, s.SQL("SELECT nas,session_id FROM sessions WHERE status IN ('stopped','disconnect-ack') AND updated_at<? ORDER BY nas,session_id LIMIT 200"), cutoff)
		if e != nil {
			return e
		}
		var keys [][2]string
		for rows.Next() {
			var k [2]string
			if err = rows.Scan(&k[0], &k[1]); err != nil {
				rows.Close()
				return err
			}
			keys = append(keys, k)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, k := range keys {
			if _, err = exec("INSERT INTO accounting_nas(nas) VALUES(?) ON CONFLICT(nas) DO UPDATE SET nas=excluded.nas", k[0]); err != nil {
				return err
			}
			var token, generation string
			var at int64
			err = tx.QueryRowContext(ctx, s.SQL("SELECT grant_token,generation,event_at FROM sessions WHERE nas=? AND session_id=? AND status IN ('stopped','disconnect-ack') AND updated_at<?"), k[0], k[1], cutoff).Scan(&token, &generation, &at)
			if err == sql.ErrNoRows {
				continue
			}
			if err != nil {
				return err
			}
			if _, err = exec("INSERT INTO session_tombstones(nas,session_id,event_at,grant_token,generation) VALUES(?,?,?,?,?) ON CONFLICT(nas,session_id) DO UPDATE SET event_at=excluded.event_at,grant_token=excluded.grant_token,generation=excluded.generation", k[0], k[1], at, token, generation); err != nil {
				return err
			}
			if _, err = exec("DELETE FROM sessions WHERE nas=? AND session_id=?", k[0], k[1]); err != nil {
				return err
			}
			p.LastSessionsDeleted++
		}
	}
	p.LastRun = now.Unix()
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if _, err = exec("UPDATE settings SET value=? WHERE name='history_retention'", string(data)); err != nil {
		return err
	}
	return tx.Commit()
}
