// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"fmt"
)

// Transfer copies application data into an empty initialized PostgreSQL database.
// UUID/text primary keys do not require resetting PostgreSQL sequences.
// Stop radiusd before copying to obtain a consistent SQLite snapshot.
func Transfer(ctx context.Context, source, target *Store) error {
	if source.Driver != "sqlite" || target.Driver != "pgx" {
		return fmt.Errorf("migration requires SQLite source and PostgreSQL target")
	}
	tx, err := target.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var tenantCount int
	if err = source.Row(ctx, "SELECT COUNT(*) FROM tenant_instances").Scan(&tenantCount); err != nil {
		return err
	}
	if tenantCount > 0 {
		return fmt.Errorf("migrate each tenant database separately before transferring the platform catalog")
	}
	tables := []string{"admins", "vlan_catalog", "domains", "local_users", "local_mschap_credentials", "locations", "network_segments", "authentication_policies", "access_policies", "policy_subjects", "user_groups", "user_group_members", "access_rule_sets", "nas", "nas_routeros", "nas_policy_sets", "location_segments", "nas_segments", "mac_auth", "settings", "auth_log", "sessions", "session_tombstones", "access_grants", "identity_status", "accounting_nas", "accounting_events", "accounting_grants", "identities", "push_subscriptions", "user_codes", "certificate_authorities", "certificates", "guest_policy", "guest_challenges", "guest_sessions", "nas_grants", "device_fingerprints", "fingerprint_history", "oui_prefixes", "fingerprint_cache", "tenant_instances"}
	for _, table := range tables {
		var n int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			return fmt.Errorf("inspect target table %s: %w", table, err)
		}
		if table == "settings" {
			if n != 3 {
				return fmt.Errorf("target settings are not pristine")
			}
			rows, err := tx.QueryContext(ctx, "SELECT name,value FROM settings")
			if err != nil {
				return err
			}
			for rows.Next() {
				var name, value string
				if err = rows.Scan(&name, &value); err != nil {
					rows.Close()
					return err
				}
				if (name != "isolation_vlan" && name != "eap_enabled" && name != "eap_vlan") || value != "0" {
					rows.Close()
					return fmt.Errorf("target settings are not pristine")
				}
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
		}
		if table == "guest_policy" {
			var enabled, ttl, limit int
			var vlan sql.NullInt64
			if n != 1 {
				return fmt.Errorf("target guest policy is not pristine")
			}
			if err = tx.QueryRowContext(ctx, "SELECT enabled,vlan,session_seconds,max_per_hour FROM guest_policy WHERE id=1").Scan(&enabled, &vlan, &ttl, &limit); err != nil {
				return err
			}
			if enabled != 0 || vlan.Valid || ttl != 3600 || limit != 1000 {
				return fmt.Errorf("target guest policy is not pristine")
			}
		}
		if n > 0 && table != "settings" && table != "guest_policy" {
			return fmt.Errorf("target table %s is not empty", table)
		}
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM settings"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM guest_policy"); err != nil {
		return err
	}
	snapshot, err := source.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer snapshot.Rollback()
	for _, table := range tables {
		rows, err := snapshot.QueryContext(ctx, "SELECT * FROM "+table)
		if err != nil {
			return err
		}
		cols, err := rows.Columns()
		if err != nil {
			rows.Close()
			return err
		}
		for rows.Next() {
			values := make([]any, len(cols))
			dest := make([]any, len(cols))
			for i := range values {
				dest[i] = &values[i]
			}
			if err = rows.Scan(dest...); err != nil {
				rows.Close()
				return err
			}
			q := "INSERT INTO " + table + " VALUES ("
			for i := range cols {
				if i > 0 {
					q += ","
				}
				q += fmt.Sprintf("$%d", i+1)
			}
			q += ")"
			if _, err = tx.ExecContext(ctx, q, values...); err != nil {
				rows.Close()
				return fmt.Errorf("copy table %s failed", table)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	if err = snapshot.Commit(); err != nil {
		return err
	}
	return tx.Commit()
}
