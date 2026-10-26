// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
)

// Lock the singleton policy row before validating or deleting a referenced VLAN.
// This serializes policy updates with VLAN deletion in PostgreSQL. SQLite uses
// the Store's single connection to serialize these transactions.
func (s *Store) policyTransaction(ctx context.Context, fn func(*sql.Tx, int) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := "SELECT value FROM settings WHERE name='isolation_vlan'"
	if s.Driver == "pgx" {
		q += " FOR UPDATE"
	}
	var raw string
	if err = tx.QueryRowContext(ctx, q).Scan(&raw); err != nil {
		return err
	}
	current, err := strconv.Atoi(raw)
	if err != nil {
		return err
	}
	if err = fn(tx, current); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) SetIsolation(ctx context.Context, vlan int) error {
	if vlan < 0 || vlan > 4094 {
		return fmt.Errorf("invalid VLAN")
	}
	return s.policyTransaction(ctx, func(tx *sql.Tx, _ int) error {
		if vlan > 0 {
			var id int
			if err := tx.QueryRowContext(ctx, s.query("SELECT id FROM vlan_catalog WHERE id=?"), vlan).Scan(&id); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, s.query("UPDATE settings SET value=? WHERE name='isolation_vlan'"), strconv.Itoa(vlan))
		return err
	})
}
func (s *Store) DeleteVLAN(ctx context.Context, vlan int) error {
	return s.policyTransaction(ctx, func(tx *sql.Tx, current int) error {
		if current == vlan {
			return fmt.Errorf("VLAN is used for isolation")
		}
		var eapVLAN string
		if err := tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE name='eap_vlan'").Scan(&eapVLAN); err != nil {
			return err
		}
		if eapVLAN == strconv.Itoa(vlan) {
			return fmt.Errorf("VLAN is used for EAP")
		}
		_, err := tx.ExecContext(ctx, s.query("DELETE FROM vlan_catalog WHERE id=?"), vlan)
		return err
	})
}

func (s *Store) EAPPolicy(ctx context.Context) (bool, int, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT name,value FROM settings WHERE name IN ('eap_enabled','eap_vlan')")
	if err != nil {
		return false, 0, err
	}
	defer rows.Close()
	values := map[string]string{}
	for rows.Next() {
		var name, value string
		if err = rows.Scan(&name, &value); err != nil {
			return false, 0, err
		}
		values[name] = value
	}
	if err = rows.Err(); err != nil {
		return false, 0, err
	}
	if len(values) != 2 {
		return false, 0, fmt.Errorf("run init-db to update EAP settings")
	}
	vlan, err := strconv.Atoi(values["eap_vlan"])
	if err != nil || vlan < 0 || vlan > 4094 || (values["eap_enabled"] != "0" && values["eap_enabled"] != "1") {
		return false, 0, fmt.Errorf("invalid EAP policy")
	}
	return values["eap_enabled"] == "1", vlan, nil
}
func (s *Store) SetEAPPolicy(ctx context.Context, enabled bool, vlan int) error {
	if vlan < 0 || vlan > 4094 {
		return fmt.Errorf("invalid VLAN")
	}
	return s.policyTransaction(ctx, func(tx *sql.Tx, _ int) error {
		if vlan > 0 {
			var id int
			if err := tx.QueryRowContext(ctx, s.query("SELECT id FROM vlan_catalog WHERE id=?"), vlan).Scan(&id); err != nil {
				return err
			}
		}
		flag := "0"
		if enabled {
			flag = "1"
		}
		if _, err := tx.ExecContext(ctx, s.query("UPDATE settings SET value=? WHERE name='eap_enabled'"), flag); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, s.query("UPDATE settings SET value=? WHERE name='eap_vlan'"), strconv.Itoa(vlan))
		return err
	})
}
