// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

type NASAssignment struct{ NAS, AccessPolicyID string }

func MappingDraftID(m SegmentMapping) string {
	if m.NAS != "" {
		return "nas/" + m.NAS + "/" + m.SegmentID
	}
	return "location/" + m.LocationID + "/" + m.SegmentID
}
func parseMappingID(id string) (SegmentMapping, error) {
	p := strings.Split(id, "/")
	if len(p) != 3 || !ruleID.MatchString(p[2]) {
		return SegmentMapping{}, fmt.Errorf("invalid mapping ID")
	}
	m := SegmentMapping{SegmentID: p[2]}
	switch p[0] {
	case "nas":
		if net.ParseIP(p[1]) == nil {
			return m, fmt.Errorf("invalid NAS")
		}
		m.NAS = p[1]
	case "location":
		if !ruleID.MatchString(p[1]) {
			return m, fmt.Errorf("invalid location")
		}
		m.LocationID = p[1]
	default:
		return m, fmt.Errorf("invalid mapping scope")
	}
	return m, nil
}
func draftPayload(kind, id string, raw json.RawMessage) (json.RawMessage, error) {
	var v any
	switch kind {
	case "authentication":
		v = &AuthenticationPolicy{}
	case "access":
		v = &AccessPolicy{}
	case "rules":
		v = &RuleSet{}
	case "group":
		v = &UserGroup{}
	case "segment":
		v = &Named{}
	case "mapping":
		v = &SegmentMapping{}
	case "nas-policies":
		v = &NASPolicySet{}
	case "nas-assignment":
		v = &NASAssignment{}
	default:
		return nil, fmt.Errorf("unknown draft kind")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if e := dec.Decode(v); e != nil {
		return nil, e
	}
	key := ""
	switch p := v.(type) {
	case *AuthenticationPolicy:
		key = p.ID
	case *AccessPolicy:
		key = p.ID
		for i := range p.Subjects {
			p.Subjects[i] = strings.ToLower(strings.TrimSpace(p.Subjects[i]))
		}
		seen := map[string]bool{}
		for _, u := range p.Subjects {
			if seen[u] {
				return nil, fmt.Errorf("duplicate identity")
			}
			seen[u] = true
		}
	case *RuleSet:
		key = p.PolicyID
	case *UserGroup:
		key = p.ID
	case *Named:
		key = p.ID
	case *SegmentMapping:
		key = MappingDraftID(*p)
	case *NASPolicySet:
		key = p.NAS
	case *NASAssignment:
		key = p.NAS
	}
	if key != id || len(id) > 200 {
		return nil, fmt.Errorf("draft ID mismatch")
	}
	switch kind {
	case "mapping":
		if _, e := parseMappingID(id); e != nil {
			return nil, e
		}
	case "nas-policies", "nas-assignment":
		ip := net.ParseIP(id)
		if ip == nil || ip.String() != id {
			return nil, fmt.Errorf("canonical NAS IP required")
		}
	default:
		if !ruleID.MatchString(id) {
			return nil, fmt.Errorf("invalid draft ID")
		}
	}
	return policyJSON(v), nil
}
func (s *Store) objectSnapshot(ctx context.Context, tx *sql.Tx, kind, id string) (json.RawMessage, error) {
	var e error
	var out any
	switch kind {
	case "segment":
		v := Named{ID: id}
		e = tx.QueryRowContext(ctx, s.SQL("SELECT name FROM network_segments WHERE id=?"), id).Scan(&v.Name)
		out = v
	case "group":
		v := UserGroup{ID: id, Members: []string{}}
		e = tx.QueryRowContext(ctx, s.SQL("SELECT name,enabled FROM user_groups WHERE id=?"), id).Scan(&v.Name, &v.Enabled)
		if e == nil {
			rows, err := tx.QueryContext(ctx, s.SQL("SELECT username FROM user_group_members WHERE group_id=? ORDER BY username"), id)
			if err != nil {
				return nil, err
			}
			for rows.Next() {
				var u string
				if err = rows.Scan(&u); err != nil {
					rows.Close()
					return nil, err
				}
				v.Members = append(v.Members, u)
			}
			e = rows.Err()
			rows.Close()
		}
		out = v
	case "mapping":
		v, err := parseMappingID(id)
		if err != nil {
			return nil, err
		}
		if v.NAS != "" {
			e = tx.QueryRowContext(ctx, s.SQL("SELECT vlan FROM nas_segments WHERE nas=? AND segment_id=?"), v.NAS, v.SegmentID).Scan(&v.VLAN)
		} else {
			e = tx.QueryRowContext(ctx, s.SQL("SELECT vlan FROM location_segments WHERE location_id=? AND segment_id=?"), v.LocationID, v.SegmentID).Scan(&v.VLAN)
		}
		out = v
	case "nas-policies":
		v := NASPolicySet{NAS: id, Bindings: []PolicyBinding{}}
		var raw string
		var version int64
		e = tx.QueryRowContext(ctx, s.SQL("SELECT config,version FROM nas_policy_sets WHERE nas=?"), id).Scan(&raw, &version)
		if e == sql.ErrNoRows {
			return json.RawMessage("null"), nil
		}
		if e == nil {
			e = json.Unmarshal([]byte(raw), &v)
			v.Version = version
		}
		out = v
	case "nas-assignment":
		v := NASAssignment{NAS: id}
		e = tx.QueryRowContext(ctx, s.SQL("SELECT COALESCE(access_policy_id,'') FROM nas WHERE address=?"), id).Scan(&v.AccessPolicyID)
		if e == nil && v.AccessPolicyID == "" {
			return json.RawMessage("null"), nil
		}
		out = v
	default:
		return nil, fmt.Errorf("unknown draft kind")
	}
	if e == sql.ErrNoRows {
		return json.RawMessage("null"), nil
	}
	if e != nil {
		return nil, e
	}
	return policyJSON(out), nil
}
func (s *Store) applyObject(ctx context.Context, tx *sql.Tx, kind, id string, raw json.RawMessage) error {
	canonical, e := draftPayload(kind, id, raw)
	if e != nil {
		return e
	}
	switch kind {
	case "group":
		var v UserGroup
		json.Unmarshal(canonical, &v)
		return s.saveGroupTx(ctx, tx, v)
	case "mapping":
		var v SegmentMapping
		json.Unmarshal(canonical, &v)
		return s.saveMappingTx(ctx, tx, v)
	case "segment":
		var v Named
		json.Unmarshal(canonical, &v)
		if v.Name == "" || len(v.Name) > 100 {
			return fmt.Errorf("segment name required")
		}
		_, e = tx.ExecContext(ctx, s.SQL("INSERT INTO network_segments(id,name) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name"), id, v.Name)
		return e
	case "nas-policies":
		var v NASPolicySet
		json.Unmarshal(canonical, &v)
		return s.saveNASPoliciesTx(ctx, tx, v)
	case "nas-assignment":
		var v NASAssignment
		json.Unmarshal(canonical, &v)
		var mode string
		if e = tx.QueryRowContext(ctx, s.SQL("SELECT access_mode FROM nas WHERE address=?"), id).Scan(&mode); e != nil {
			return e
		}
		var policy any
		if v.AccessPolicyID != "" {
			var wanted string
			if e = tx.QueryRowContext(ctx, s.SQL("SELECT mode FROM access_policies WHERE id=?"), v.AccessPolicyID).Scan(&wanted); e != nil {
				return e
			}
			if wanted != mode {
				return fmt.Errorf("policy mode must match NAS")
			}
			policy = v.AccessPolicyID
		}
		_, e = tx.ExecContext(ctx, s.SQL("UPDATE nas SET access_policy_id=? WHERE address=?"), policy, id)
		return e
	}
	return fmt.Errorf("unknown draft kind")
}
