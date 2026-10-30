// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"sort"
	"time"
)

type DraftRef struct {
	Kind, PolicyID string
	Revision       int64
}
type BatchImpact struct {
	Drafts                     []PolicyDraft
	Devices                    []string
	Sessions, UnlinkedSessions []ImpactSession
	Errors                     []string
}
type impactTargets struct{ policies, nas, pairs map[string]bool }

func newTargets() impactTargets {
	return impactTargets{map[string]bool{}, map[string]bool{}, map[string]bool{}}
}
func (t impactTargets) matches(nas, p string) bool {
	return t.policies[p] || t.nas[nas] || t.pairs[nas+"\x00"+p]
}
func (s *Store) targetChanges(ctx context.Context, tx *sql.Tx, ds []PolicyDraft, t impactTargets) error {
	for _, d := range ds {
		switch d.Kind {
		case "access", "rules":
			t.policies[d.PolicyID] = true
		case "authentication", "segment":
			col := "authentication_id"
			if d.Kind == "segment" {
				col = "segment_id"
			}
			rows, e := tx.QueryContext(ctx, s.SQL("SELECT id FROM access_policies WHERE "+col+"=?"), d.PolicyID)
			if e != nil {
				return e
			}
			for rows.Next() {
				var id string
				if e = rows.Scan(&id); e != nil {
					rows.Close()
					return e
				}
				t.policies[id] = true
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
		case "nas-policies", "nas-assignment":
			t.nas[d.PolicyID] = true
		case "group":
			rows, e := tx.QueryContext(ctx, "SELECT policy_id,config FROM access_rule_sets")
			if e != nil {
				return e
			}
			for rows.Next() {
				var id, raw string
				if e = rows.Scan(&id, &raw); e != nil {
					rows.Close()
					return e
				}
				var c RuleSet
				if e = json.Unmarshal([]byte(raw), &c); e != nil {
					rows.Close()
					return e
				}
				for _, r := range c.Rules {
					for _, g := range r.Groups {
						if g == d.PolicyID {
							t.policies[id] = true
						}
					}
				}
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
		case "mapping":
			m, e := parseMappingID(d.PolicyID)
			if e != nil {
				return e
			}
			q := "SELECT n.address,p.id FROM nas n CROSS JOIN access_policies p WHERE p.segment_id=? AND n.address=?"
			scope := m.NAS
			if scope == "" {
				scope = m.LocationID
				q = "SELECT n.address,p.id FROM nas n CROSS JOIN access_policies p WHERE p.segment_id=? AND n.location_id=? AND NOT EXISTS(SELECT 1 FROM nas_segments ns WHERE ns.nas=n.address AND ns.segment_id=p.segment_id)"
			}
			rows, e := tx.QueryContext(ctx, s.SQL(q), m.SegmentID, scope)
			if e != nil {
				return e
			}
			for rows.Next() {
				var nas, p string
				if e = rows.Scan(&nas, &p); e != nil {
					rows.Close()
					return e
				}
				t.pairs[nas+"\x00"+p] = true
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
		}
	}
	return nil
}
func (s *Store) batchImpactTargets(ctx context.Context, tx *sql.Tx, t impactTargets, out *BatchImpact) error {
	devices := map[string]bool{}
	for n := range t.nas {
		devices[n] = true
	}
	rows, e := tx.QueryContext(ctx, "SELECT n.address,COALESCE(n.access_policy_id,''),COALESCE(ns.config,'') FROM nas n LEFT JOIN nas_policy_sets ns ON ns.nas=n.address")
	if e != nil {
		return e
	}
	for rows.Next() {
		var nas, p, raw string
		if e = rows.Scan(&nas, &p, &raw); e != nil {
			rows.Close()
			return e
		}
		match := t.matches(nas, p)
		if raw != "" {
			var set NASPolicySet
			if e = json.Unmarshal([]byte(raw), &set); e != nil {
				rows.Close()
				return e
			}
			for _, b := range set.Bindings {
				match = match || t.matches(nas, b.PolicyID)
			}
		}
		if match {
			devices[nas] = true
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	rows, e = tx.QueryContext(ctx, "SELECT s.nas,s.session_id,s.username,s.status,COALESCE(g.policy_id,''),COALESCE(g.token,'') FROM sessions s LEFT JOIN access_grants g ON g.token=s.grant_token WHERE s.status IN ('active','stale') ORDER BY s.nas,s.session_id")
	if e != nil {
		return e
	}
	out.Sessions = []ImpactSession{}
	out.UnlinkedSessions = []ImpactSession{}
	for rows.Next() {
		var v ImpactSession
		var p, token string
		if e = rows.Scan(&v.NAS, &v.ID, &v.Username, &v.Status, &p, &token); e != nil {
			rows.Close()
			return e
		}
		if token != "" && t.matches(v.NAS, p) {
			out.Sessions = append(out.Sessions, v)
			devices[v.NAS] = true
		} else if p == "" && devices[v.NAS] {
			out.UnlinkedSessions = append(out.UnlinkedSessions, v)
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	out.Devices = []string{}
	for n := range devices {
		out.Devices = append(out.Devices, n)
	}
	sort.Strings(out.Devices)
	return nil
}

var draftOrder = map[string]int{"segment": 0, "group": 1, "authentication": 2, "access": 3, "rules": 4, "mapping": 5, "nas-assignment": 6, "nas-policies": 7}

func (s *Store) batchDrafts(ctx context.Context, tx *sql.Tx, refs []DraftRef) ([]PolicyDraft, error) {
	if len(refs) < 1 || len(refs) > 100 {
		return nil, fmt.Errorf("select 1–100 drafts")
	}
	out := []PolicyDraft{}
	seen := map[string]bool{}
	for _, r := range refs {
		key := r.Kind + "/" + r.PolicyID
		if seen[key] {
			return nil, fmt.Errorf("duplicate draft")
		}
		seen[key] = true
		d, e := draftTx(ctx, s, tx, r.Kind, r.PolicyID)
		if e != nil {
			return nil, fmt.Errorf("draft changed: %s", key)
		}
		if d.Revision != r.Revision {
			return nil, fmt.Errorf("draft changed: %s", key)
		}
		live, e := s.policySnapshot(ctx, tx, r.Kind, r.PolicyID)
		if e != nil {
			return nil, e
		}
		if string(live) != string(d.Base) {
			return nil, fmt.Errorf("live configuration changed: %s", key)
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		di, dj := isDeletion(out[i].Payload), isDeletion(out[j].Payload)
		if di != dj {
			return !di
		}
		a, b := draftOrder[out[i].Kind], draftOrder[out[j].Kind]
		if a != b {
			if di {
				return a > b
			}
			return a < b
		}
		return out[i].PolicyID < out[j].PolicyID
	})
	return out, nil
}
func (s *Store) validateBatchDependencies(ctx context.Context, tx *sql.Tx, t impactTargets) error {
	if _, e := tx.ExecContext(ctx, "SAVEPOINT validate_dependencies"); e != nil {
		return e
	}
	for id := range t.policies {
		for _, kind := range []string{"access", "rules"} {
			raw, e := s.policySnapshot(ctx, tx, kind, id)
			if e != nil {
				return e
			}
			if string(raw) == "null" {
				continue
			}
			if e = s.applyPolicy(ctx, tx, kind, id, raw); e != nil {
				return fmt.Errorf("dependent policy %s: %w", id, e)
			}
		}
	}
	rows, e := tx.QueryContext(ctx, "SELECT nas,config FROM nas_policy_sets")
	if e != nil {
		return e
	}
	sets := []NASPolicySet{}
	for rows.Next() {
		var nas, raw string
		if e = rows.Scan(&nas, &raw); e != nil {
			rows.Close()
			return e
		}
		var set NASPolicySet
		if e = json.Unmarshal([]byte(raw), &set); e != nil {
			rows.Close()
			return e
		}
		match := t.nas[nas]
		for _, b := range set.Bindings {
			match = match || t.policies[b.PolicyID]
		}
		if match {
			sets = append(sets, set)
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, set := range sets {
		if e = s.saveNASPoliciesTx(ctx, tx, set); e != nil {
			return fmt.Errorf("dependent NAS %s: %w", set.NAS, e)
		}
	}
	if e = s.validateNetworkMappings(ctx, tx, t); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT validate_dependencies"); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, "RELEASE SAVEPOINT validate_dependencies")
	return e
}
func (s *Store) applyBatch(ctx context.Context, tx *sql.Tx, ds []PolicyDraft, t impactTargets) ([]json.RawMessage, error) {
	if e := s.targetChanges(ctx, tx, ds, t); e != nil {
		return nil, e
	}
	previousTargets := make([]impactTargets, len(ds))
	for i, d := range ds {
		previousTargets[i] = newTargets()
		if e := s.targetChanges(ctx, tx, []PolicyDraft{d}, previousTargets[i]); e != nil {
			return nil, e
		}
	}
	after := []json.RawMessage{}
	for _, d := range ds {
		if e := s.applyPolicy(ctx, tx, d.Kind, d.PolicyID, d.Payload); e != nil {
			return nil, fmt.Errorf("%s/%s: %w", d.Kind, d.PolicyID, e)
		}
		raw, e := s.policySnapshot(ctx, tx, d.Kind, d.PolicyID)
		if e != nil {
			return nil, e
		}
		after = append(after, raw)
	}
	if e := s.targetChanges(ctx, tx, ds, t); e != nil {
		return nil, e
	}
	if e := s.validateBatchDependencies(ctx, tx, t); e != nil {
		return nil, e
	}
	clear(t.policies)
	clear(t.nas)
	clear(t.pairs)
	for i, d := range ds {
		if string(d.Base) == string(after[i]) {
			continue
		}
		for p := range previousTargets[i].policies {
			t.policies[p] = true
		}
		for n := range previousTargets[i].nas {
			t.nas[n] = true
		}
		for pair := range previousTargets[i].pairs {
			t.pairs[pair] = true
		}
		if e := s.targetChanges(ctx, tx, []PolicyDraft{d}, t); e != nil {
			return nil, e
		}
	}
	return after, nil
}
func (s *Store) PolicyBatchImpact(ctx context.Context, refs []DraftRef) (BatchImpact, error) {
	out := BatchImpact{Drafts: []PolicyDraft{}, Devices: []string{}, Sessions: []ImpactSession{}, UnlinkedSessions: []ImpactSession{}, Errors: []string{}}
	tx, e := s.policyTx(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	ds, e := s.batchDrafts(ctx, tx, refs)
	if e != nil {
		out.Errors = append(out.Errors, e.Error())
		return out, nil
	}
	out.Drafts = ds
	t := newTargets()
	if e = s.targetChanges(ctx, tx, ds, t); e != nil {
		return out, e
	}
	if e = s.batchImpactTargets(ctx, tx, t, &out); e != nil {
		return out, e
	}
	beforeDevices := out.Devices
	if _, e = s.applyBatch(ctx, tx, ds, t); e != nil {
		out.Errors = append(out.Errors, e.Error())
		return out, nil
	}
	if e = s.batchImpactTargets(ctx, tx, t, &out); e != nil {
		return out, e
	}
	seen := map[string]bool{}
	for _, n := range out.Devices {
		seen[n] = true
	}
	for _, n := range beforeDevices {
		if !seen[n] {
			out.Devices = append(out.Devices, n)
		}
	}
	sort.Strings(out.Devices)
	return out, nil
}
func (s *Store) PublishPolicyBatch(ctx context.Context, refs []DraftRef, actor string) error {
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	ds, e := s.batchDrafts(ctx, tx, refs)
	if e != nil {
		return e
	}
	reviewID, e := s.requireBatchApproval(ctx, tx, ds, actor)
	if e != nil {
		return e
	}
	t := newTargets()
	after, e := s.applyBatch(ctx, tx, ds, t)
	if e != nil {
		return e
	}
	// Collect tokens before updates so SQLite never has a live row cursor while writing.
	rows, e := tx.QueryContext(ctx, "SELECT token,nas,policy_id FROM access_grants WHERE reason=''")
	if e != nil {
		return e
	}
	tokens := []string{}
	for rows.Next() {
		var token, nas, p string
		if e = rows.Scan(&token, &nas, &p); e != nil {
			rows.Close()
			return e
		}
		if t.matches(nas, p) {
			tokens = append(tokens, token)
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, token := range tokens {
		if _, e = tx.ExecContext(ctx, s.SQL("UPDATE access_grants SET reason='configuration published: reauthentication required',next_attempt=0 WHERE token=? AND reason=''"), token); e != nil {
			return e
		}
	}
	batch := uuid.NewString()
	if reviewID != "" {
		if _, e = tx.ExecContext(ctx, s.SQL("UPDATE policy_reviews SET state='published',batch_id=?,updated_at=? WHERE id=?"), batch, time.Now().Unix(), reviewID); e != nil {
			return e
		}
	}
	for i, d := range ds {
		if _, e = tx.ExecContext(ctx, s.SQL("INSERT INTO policy_releases(id,kind,policy_id,before_payload,after_payload,actor,created_at,batch_id) VALUES(?,?,?,?,?,?,?,?)"), uuid.NewString(), d.Kind, d.PolicyID, string(d.Base), string(after[i]), actor, time.Now().Unix(), batch); e != nil {
			return e
		}
		if e = s.invalidateDraftReviews(ctx, tx, d.Kind, d.PolicyID, "draft published in another package"); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, s.SQL("DELETE FROM policy_draft_authors WHERE kind=? AND policy_id=?"), d.Kind, d.PolicyID); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, s.SQL("DELETE FROM policy_drafts WHERE kind=? AND policy_id=?"), d.Kind, d.PolicyID); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Store) RollbackPolicyBatch(ctx context.Context, batch, actor string) error {
	if batch == "" {
		return fmt.Errorf("batch required")
	}
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	rows, e := tx.QueryContext(ctx, s.SQL("SELECT kind,policy_id,before_payload FROM policy_releases WHERE batch_id=? ORDER BY kind,policy_id"), batch)
	if e != nil {
		return e
	}
	ds := []PolicyDraft{}
	for rows.Next() {
		var d PolicyDraft
		var raw string
		if e = rows.Scan(&d.Kind, &d.PolicyID, &raw); e != nil {
			rows.Close()
			return e
		}
		d.Payload = json.RawMessage(raw)
		ds = append(ds, d)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if len(ds) == 0 || len(ds) > 100 {
		return fmt.Errorf("batch not found or too large")
	}
	for _, d := range ds {
		d.Payload, e = s.rollbackPayload(ctx, tx, d.Kind, d.PolicyID, d.Payload)
		if e != nil {
			return e
		}
		if e = s.savePolicyDraftTx(ctx, tx, d, actor); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Store) rollbackPayload(ctx context.Context, tx *sql.Tx, kind, id string, raw json.RawMessage) (json.RawMessage, error) {
	raw = normalizeSnapshot(kind, raw)
	if isDeletion(raw) {
		return raw, nil
	}
	if kind != "rules" && kind != "nas-policies" {
		return raw, nil
	}
	live, e := s.policySnapshot(ctx, tx, kind, id)
	if e != nil {
		return nil, e
	}
	if kind == "rules" {
		var old, current RuleSet
		json.Unmarshal(raw, &old)
		json.Unmarshal(live, &current)
		old.Version = current.Version
		return policyJSON(old), nil
	}
	var old, current NASPolicySet
	json.Unmarshal(raw, &old)
	json.Unmarshal(live, &current)
	old.Version = current.Version
	return policyJSON(old), nil
}

func (s *Store) validateNetworkMappings(ctx context.Context, tx *sql.Tx, t impactTargets) error {
	rows, e := tx.QueryContext(ctx, "SELECT n.address,COALESCE(n.access_policy_id,''),COALESCE(ns.config,'') FROM nas n LEFT JOIN nas_policy_sets ns ON ns.nas=n.address")
	if e != nil {
		return e
	}
	type pair struct{ nas, policy string }
	pairs := []pair{}
	for rows.Next() {
		var nas, p, raw string
		if e = rows.Scan(&nas, &p, &raw); e != nil {
			rows.Close()
			return e
		}
		set := NASPolicySet{}
		if raw != "" {
			if e = json.Unmarshal([]byte(raw), &set); e != nil {
				rows.Close()
				return e
			}
		}
		if set.Enabled {
			for _, b := range set.Bindings {
				if b.Enabled && t.matches(nas, b.PolicyID) {
					pairs = append(pairs, pair{nas, b.PolicyID})
				}
			}
		} else if p != "" && t.matches(nas, p) {
			pairs = append(pairs, pair{nas, p})
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, p := range pairs {
		var mode, segment string
		if e = tx.QueryRowContext(ctx, s.SQL("SELECT mode,COALESCE(segment_id,'') FROM access_policies WHERE id=?"), p.policy).Scan(&mode, &segment); e != nil {
			return e
		}
		if mode != "network" {
			continue
		}
		var n int
		e = tx.QueryRowContext(ctx, s.SQL("SELECT COUNT(*) FROM nas n WHERE n.address=? AND (EXISTS(SELECT 1 FROM nas_segments m WHERE m.nas=n.address AND m.segment_id=?) OR EXISTS(SELECT 1 FROM location_segments m WHERE m.location_id=n.location_id AND m.segment_id=?))"), p.nas, segment, segment).Scan(&n)
		if e != nil {
			return e
		}
		if n == 0 {
			return fmt.Errorf("NAS %s: missing VLAN mapping for segment %s", p.nas, segment)
		}
	}
	return nil
}
