// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"time"
)

// EnableVPNAccounting records the authenticated connection tuple, never a username-only match.
func (s *Store) EnableVPNAccounting(ctx context.Context, token, key string) error {
	if key == "" {
		return nil
	}
	return s.Exec(ctx, "UPDATE access_grants SET accounting_key=?,issued_at=? WHERE token=?", key, time.Now().Unix(), token)
}

// vpnAccountingToken resolves only timestamped events with the same authenticated
// tuple. First binding requires a fresh Start and a unique recent grant. Claims
// are permanent, so a permission cannot migrate to another accounting session.
func (s *Store) vpnAccountingToken(ctx context.Context, tx *sql.Tx, e AccountingEvent, now int64) (string, error) {
	if len(e.Classes) > 0 || e.AccountingKey == "" || !e.Timed || !e.HasSeconds || e.Seconds < 0 || e.At > now+5 || e.At < now-60 {
		return "", nil
	}
	start := e.At - e.Seconds
	rows, err := tx.QueryContext(ctx, s.SQL("SELECT token,accounting_session,accounting_started FROM access_grants WHERE nas=? AND username=? AND accounting_key=? AND issued_at BETWEEN ? AND ?"), e.NAS, e.Username, e.AccountingKey, start-30, start+2)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	type candidate struct {
		token, id string
		start     int64
	}
	var all []candidate
	for rows.Next() {
		var c candidate
		if err = rows.Scan(&c.token, &c.id, &c.start); err != nil {
			return "", err
		}
		all = append(all, c)
	}
	if err = rows.Err(); err != nil {
		return "", err
	}
	// An established claim is identified by the accounting session and its start
	// time, even if another authorization for the same tuple has since appeared.
	for _, c := range all {
		if c.id == e.ID && c.id != "" && start >= c.start-2 && start <= c.start+2 {
			return c.token, nil
		}
	}
	if e.Kind != "start" || e.Seconds > 5 || len(all) != 1 || all[0].id != "" {
		return "", nil
	}
	return all[0].token, nil
}
