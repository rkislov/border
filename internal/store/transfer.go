// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
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
	tables := []string{"admins", "nas", "vlan_catalog", "mac_auth", "settings", "auth_log", "sessions", "identities", "user_codes", "certificate_authorities", "certificates"}
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
		if n > 0 && table != "settings" {
			return fmt.Errorf("target table %s is not empty", table)
		}
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM settings"); err != nil {
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
