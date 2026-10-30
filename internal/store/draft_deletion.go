// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
)

func isDeletion(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }
func draftOperation(raw json.RawMessage) string {
	if isDeletion(raw) {
		return "delete"
	}
	return "upsert"
}

// Older releases represented absent versioned sets with an empty version-zero
// object. Normalize that representation when comparing or undoing old history.
func normalizeSnapshot(kind string, raw json.RawMessage) json.RawMessage {
	if isDeletion(raw) {
		return json.RawMessage("null")
	}
	switch kind {
	case "rules":
		var v RuleSet
		if json.Unmarshal(raw, &v) == nil && v.Version == 0 && !v.Enabled && len(v.Rules) == 0 {
			return json.RawMessage("null")
		}
	case "nas-policies":
		var v NASPolicySet
		if json.Unmarshal(raw, &v) == nil && v.Version == 0 && !v.Enabled && len(v.Bindings) == 0 {
			return json.RawMessage("null")
		}
	case "nas-assignment":
		var v NASAssignment
		if json.Unmarshal(raw, &v) == nil && v.AccessPolicyID == "" {
			return json.RawMessage("null")
		}
	}
	return raw
}
func validateDraftKey(kind, id string) error {
	if _, ok := draftOrder[kind]; !ok {
		return fmt.Errorf("unknown draft kind")
	}
	switch kind {
	case "mapping":
		_, e := parseMappingID(id)
		return e
	case "nas-policies", "nas-assignment":
		ip := net.ParseIP(id)
		if ip == nil || ip.String() != id {
			return fmt.Errorf("canonical NAS IP required")
		}
	default:
		if !ruleID.MatchString(id) {
			return fmt.Errorf("invalid draft ID")
		}
	}
	return nil
}
func (s *Store) nextConfigurationVersion(ctx context.Context, tx *sql.Tx, kind, id string, current int64) (int64, error) {
	var saved int64
	e := tx.QueryRowContext(ctx, s.SQL("SELECT version FROM configuration_versions WHERE kind=? AND object_id=?"), kind, id).Scan(&saved)
	if e != nil && e != sql.ErrNoRows {
		return 0, e
	}
	if saved < current {
		saved = current
	}
	saved++
	_, e = tx.ExecContext(ctx, s.SQL("INSERT INTO configuration_versions(kind,object_id,version) VALUES(?,?,?) ON CONFLICT(kind,object_id) DO UPDATE SET version=excluded.version"), kind, id, saved)
	return saved, e
}
func (s *Store) deleteDraftObject(ctx context.Context, tx *sql.Tx, kind, id string) error {
	if e := validateDraftKey(kind, id); e != nil {
		return e
	}
	// JSON references are not foreign keys. Never silently cascade away rules or
	// bindings: their removal must have its own reviewed and reversible draft.
	if kind == "group" || kind == "access" {
		table, col := "access_rule_sets", "policy_id"
		if kind == "access" {
			table, col = "nas_policy_sets", "nas"
		}
		rows, e := tx.QueryContext(ctx, "SELECT "+col+",config FROM "+table)
		if e != nil {
			return e
		}
		for rows.Next() {
			var owner, raw string
			if e = rows.Scan(&owner, &raw); e != nil {
				rows.Close()
				return e
			}
			used := false
			if kind == "group" {
				var c RuleSet
				if e = json.Unmarshal([]byte(raw), &c); e != nil {
					rows.Close()
					return e
				}
				for _, r := range c.Rules {
					for _, g := range r.Groups {
						used = used || g == id
					}
				}
			} else {
				var c NASPolicySet
				if e = json.Unmarshal([]byte(raw), &c); e != nil {
					rows.Close()
					return e
				}
				for _, b := range c.Bindings {
					used = used || b.PolicyID == id
				}
			}
			if used {
				rows.Close()
				return fmt.Errorf("cannot delete %s/%s: referenced by %s/%s", kind, id, table, owner)
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
	}
	if kind == "access" {
		var count int
		if e := tx.QueryRowContext(ctx, s.SQL("SELECT COUNT(*) FROM access_rule_sets WHERE policy_id=?"), id).Scan(&count); e != nil {
			return e
		}
		if count > 0 {
			return fmt.Errorf("cannot delete access/%s: include its rules deletion in the package", id)
		}
	}
	var q string
	args := []any{id}
	switch kind {
	case "authentication":
		q = "DELETE FROM authentication_policies WHERE id=?"
	case "access":
		q = "DELETE FROM access_policies WHERE id=?"
	case "rules":
		q = "DELETE FROM access_rule_sets WHERE policy_id=?"
	case "group":
		q = "DELETE FROM user_groups WHERE id=?"
	case "segment":
		q = "DELETE FROM network_segments WHERE id=?"
	case "nas-policies":
		q = "DELETE FROM nas_policy_sets WHERE nas=?"
	case "nas-assignment":
		q = "UPDATE nas SET access_policy_id=NULL WHERE address=?"
	case "mapping":
		m, e := parseMappingID(id)
		if e != nil {
			return e
		}
		if m.NAS != "" {
			q = "DELETE FROM nas_segments WHERE nas=? AND segment_id=?"
			args = []any{m.NAS, m.SegmentID}
		} else {
			q = "DELETE FROM location_segments WHERE location_id=? AND segment_id=?"
			args = []any{m.LocationID, m.SegmentID}
		}
	}
	_, e := tx.ExecContext(ctx, s.SQL(q), args...)
	if e != nil {
		return fmt.Errorf("cannot delete %s/%s: remove dependent references in the same package", kind, id)
	}
	return nil
}
