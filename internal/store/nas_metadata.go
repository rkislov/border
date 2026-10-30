// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"fmt"
)

// SaveNASMetadata serializes metadata edits with publication. A stale card may
// never overwrite a single-policy assignment published by another administrator.
// The web handler validates the NAS address, secret, profile and timing fields.
func (s *Store) SaveNASMetadata(ctx context.Context, n NAS, secret string) error {
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var current string
	if e = tx.QueryRowContext(ctx, s.SQL("SELECT COALESCE(access_policy_id,'') FROM nas WHERE address=?"), n.Address).Scan(&current); e != nil && e != sql.ErrNoRows {
		return e
	}
	if n.AccessPolicyID != "" && n.AccessPolicyID != current {
		return fmt.Errorf("assignment changed; use an assignment draft")
	}
	if current != "" {
		var mode string
		if e = tx.QueryRowContext(ctx, s.SQL("SELECT mode FROM access_policies WHERE id=?"), current).Scan(&mode); e != nil {
			return e
		}
		if mode != n.Mode {
			return fmt.Errorf("policy mode must match NAS")
		}
	}
	var location any
	if n.LocationID != "" {
		location = n.LocationID
	}
	_, e = tx.ExecContext(ctx, s.SQL("INSERT INTO nas(address,name,secret,coa_port,portal_enabled,dictionary,access_mode,credential,location_id,interim_seconds,stale_seconds) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(address) DO UPDATE SET name=excluded.name,secret=excluded.secret,coa_port=excluded.coa_port,portal_enabled=excluded.portal_enabled,dictionary=excluded.dictionary,access_mode=excluded.access_mode,credential=excluded.credential,location_id=excluded.location_id,interim_seconds=excluded.interim_seconds,stale_seconds=excluded.stale_seconds"), n.Address, n.Name, secret, n.CoAPort, integer(n.PortalEnabled), n.Dictionary, n.Mode, n.Credential, location, n.InterimSeconds, n.StaleSeconds)
	if e != nil {
		return e
	}
	return tx.Commit()
}
