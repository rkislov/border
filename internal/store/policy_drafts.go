// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"strings"
	"time"
)

type PolicyDraft struct {
	Kind, PolicyID string
	Revision       int64
	Base, Payload  json.RawMessage
	Actor          string
	UpdatedAt      int64
}
type PolicyRelease struct {
	ID, Kind, PolicyID, Actor string
	CreatedAt                 int64
	Before, After             json.RawMessage
}
type PolicyImpact struct {
	Draft            PolicyDraft
	Devices          []string
	Sessions         []ImpactSession
	UnlinkedSessions []ImpactSession
	Conflict         bool
}
type ImpactSession struct{ NAS, ID, Username, Status string }

// Every policy writer takes the same database lock, including legacy store APIs.
func (s *Store) policyTx(ctx context.Context) (*sql.Tx, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE policy_write_lock SET revision=revision+1 WHERE id=1"); e != nil {
		tx.Rollback()
		return nil, e
	}
	return tx, nil
}
func policyJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
func (s *Store) policySnapshot(ctx context.Context, tx *sql.Tx, kind, id string) (json.RawMessage, error) {
	switch kind {
	case "authentication":
		var a AuthenticationPolicy
		var steps string
		e := tx.QueryRowContext(ctx, s.SQL("SELECT id,name,source,COALESCE(domain_id,''),require_totp,enabled,steps,eap_method FROM authentication_policies WHERE id=?"), id).Scan(&a.ID, &a.Name, &a.Source, &a.DomainID, &a.RequireTOTP, &a.Enabled, &steps, &a.EAPMethod)
		if e == sql.ErrNoRows {
			return json.RawMessage("null"), nil
		}
		if e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(steps), &a.Steps); e != nil {
			return nil, e
		}
		return policyJSON(a), nil
	case "access":
		var a AccessPolicy
		e := tx.QueryRowContext(ctx, s.SQL("SELECT id,name,authentication_id,mode,COALESCE(segment_id,''),valid_from,valid_until,session_seconds,idle_seconds,privilege,group_name,role,filter_id,enabled FROM access_policies WHERE id=?"), id).Scan(&a.ID, &a.Name, &a.AuthenticationID, &a.Mode, &a.SegmentID, &a.ValidFrom, &a.ValidUntil, &a.SessionSeconds, &a.IdleSeconds, &a.Privilege, &a.Group, &a.Role, &a.Filter, &a.Enabled)
		if e == sql.ErrNoRows {
			return json.RawMessage("null"), nil
		}
		if e != nil {
			return nil, e
		}
		rows, e := tx.QueryContext(ctx, s.SQL("SELECT identity FROM policy_subjects WHERE policy_id=? ORDER BY identity"), id)
		if e != nil {
			return nil, e
		}
		defer rows.Close()
		a.Subjects = []string{}
		for rows.Next() {
			var u string
			if e = rows.Scan(&u); e != nil {
				return nil, e
			}
			a.Subjects = append(a.Subjects, u)
		}
		return policyJSON(a), rows.Err()
	case "rules":
		var raw string
		var version int64
		e := tx.QueryRowContext(ctx, s.SQL("SELECT config,version FROM access_rule_sets WHERE policy_id=?"), id).Scan(&raw, &version)
		if e == sql.ErrNoRows {
			return policyJSON(RuleSet{PolicyID: id, Rules: []AccessRule{}}), nil
		}
		if e != nil {
			return nil, e
		}
		var c RuleSet
		if e = json.Unmarshal([]byte(raw), &c); e != nil {
			return nil, e
		}
		c.Version = version
		return policyJSON(c), nil
	default:
		return nil, fmt.Errorf("unknown policy kind")
	}
}
func (s *Store) applyPolicy(ctx context.Context, tx *sql.Tx, kind, id string, raw json.RawMessage) error {
	switch kind {
	case "authentication":
		var v AuthenticationPolicy
		if e := json.Unmarshal(raw, &v); e != nil {
			return e
		}
		if v.ID != id {
			return fmt.Errorf("policy ID mismatch")
		}
		return s.saveAuthenticationTx(ctx, tx, v)
	case "access":
		var v AccessPolicy
		if e := json.Unmarshal(raw, &v); e != nil {
			return e
		}
		if v.ID != id {
			return fmt.Errorf("policy ID mismatch")
		}
		for i := range v.Subjects {
			v.Subjects[i] = strings.ToLower(strings.TrimSpace(v.Subjects[i]))
		}
		return s.saveAccessTx(ctx, tx, v)
	case "rules":
		var v RuleSet
		if e := json.Unmarshal(raw, &v); e != nil {
			return e
		}
		if v.PolicyID != id {
			return fmt.Errorf("policy ID mismatch")
		}
		return s.saveRulesTx(ctx, tx, v)
	}
	return fmt.Errorf("unknown policy kind")
}
func draftTx(ctx context.Context, s *Store, tx *sql.Tx, kind, id string) (PolicyDraft, error) {
	d := PolicyDraft{Kind: kind, PolicyID: id}
	var base, raw string
	e := tx.QueryRowContext(ctx, s.SQL("SELECT revision,base,payload,actor,updated_at FROM policy_drafts WHERE kind=? AND policy_id=?"), kind, id).Scan(&d.Revision, &base, &raw, &d.Actor, &d.UpdatedAt)
	d.Base = json.RawMessage(base)
	d.Payload = json.RawMessage(raw)
	return d, e
}
func (s *Store) SavePolicyDraft(ctx context.Context, d PolicyDraft, actor string) error {
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	return s.savePolicyDraftTx(ctx, tx, d, actor)
}
func (s *Store) savePolicyDraftTx(ctx context.Context, tx *sql.Tx, d PolicyDraft, actor string) error {
	if !ruleID.MatchString(d.PolicyID) || len(d.Payload) > 256*1024 {
		return fmt.Errorf("invalid policy draft")
	}
	current, e := draftTx(ctx, s, tx, d.Kind, d.PolicyID)
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	if current.Revision != d.Revision {
		return fmt.Errorf("draft changed; reload before saving")
	}
	base, e := s.policySnapshot(ctx, tx, d.Kind, d.PolicyID)
	if e != nil {
		return e
	}
	if current.Revision > 0 {
		base = current.Base
	}
	// Reuse production validation inside a savepoint; no live change can escape.
	if _, e = tx.ExecContext(ctx, "SAVEPOINT validate_policy"); e != nil {
		return e
	}
	if e = s.applyPolicy(ctx, tx, d.Kind, d.PolicyID, d.Payload); e != nil {
		return e
	}
	canonical, e := s.policySnapshot(ctx, tx, d.Kind, d.PolicyID)
	if e != nil {
		return e
	}
	if d.Kind == "rules" {
		var c RuleSet
		json.Unmarshal(canonical, &c)
		c.Version--
		canonical = policyJSON(c)
	}
	if _, e = tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT validate_policy"); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "RELEASE SAVEPOINT validate_policy"); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, s.SQL("INSERT INTO policy_draft_versions(kind,policy_id,revision) VALUES(?,?,1) ON CONFLICT(kind,policy_id) DO UPDATE SET revision=policy_draft_versions.revision+1"), d.Kind, d.PolicyID); e != nil {
		return e
	}
	var next int64
	if e = tx.QueryRowContext(ctx, s.SQL("SELECT revision FROM policy_draft_versions WHERE kind=? AND policy_id=?"), d.Kind, d.PolicyID).Scan(&next); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, s.SQL("INSERT INTO policy_drafts(kind,policy_id,revision,base,payload,actor,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(kind,policy_id) DO UPDATE SET revision=excluded.revision,payload=excluded.payload,actor=excluded.actor,updated_at=excluded.updated_at"), d.Kind, d.PolicyID, next, string(base), string(canonical), actor, time.Now().Unix())
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) PolicyDrafts(ctx context.Context) ([]PolicyDraft, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT kind,policy_id,revision,base,payload,actor,updated_at FROM policy_drafts ORDER BY updated_at DESC,kind,policy_id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []PolicyDraft{}
	for rows.Next() {
		var d PolicyDraft
		var b, p string
		if e = rows.Scan(&d.Kind, &d.PolicyID, &d.Revision, &b, &p, &d.Actor, &d.UpdatedAt); e != nil {
			return nil, e
		}
		d.Base = json.RawMessage(b)
		d.Payload = json.RawMessage(p)
		out = append(out, d)
	}
	return out, rows.Err()
}
func (s *Store) PolicyReleases(ctx context.Context) ([]PolicyRelease, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT id,kind,policy_id,actor,created_at,before_payload,after_payload FROM policy_releases ORDER BY created_at DESC,id DESC LIMIT 100")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []PolicyRelease{}
	for rows.Next() {
		var r PolicyRelease
		var b, p string
		if e = rows.Scan(&r.ID, &r.Kind, &r.PolicyID, &r.Actor, &r.CreatedAt, &b, &p); e != nil {
			return nil, e
		}
		r.Before = json.RawMessage(b)
		r.After = json.RawMessage(p)
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) PolicyDraftImpact(ctx context.Context, kind, id string) (PolicyImpact, error) {
	tx, e := s.policyTx(ctx)
	if e != nil {
		return PolicyImpact{}, e
	}
	defer tx.Rollback()
	d, e := draftTx(ctx, s, tx, kind, id)
	if e != nil {
		return PolicyImpact{}, e
	}
	live, e := s.policySnapshot(ctx, tx, kind, id)
	if e != nil {
		return PolicyImpact{}, e
	}
	out := PolicyImpact{Draft: d, Conflict: string(live) != string(d.Base), Devices: []string{}, Sessions: []ImpactSession{}, UnlinkedSessions: []ImpactSession{}}
	policies, e := s.affectedPolicyIDs(ctx, tx, kind, id)
	if e != nil {
		return out, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT n.address,COALESCE(n.access_policy_id,''),COALESCE(ns.config,'') FROM nas n LEFT JOIN nas_policy_sets ns ON ns.nas=n.address ORDER BY n.address")
	if e != nil {
		return out, e
	}
	devices := map[string]bool{}
	for rows.Next() {
		var nas, p, raw string
		if e = rows.Scan(&nas, &p, &raw); e != nil {
			rows.Close()
			return out, e
		}
		matched := policies[p]
		if raw != "" {
			var set NASPolicySet
			if e = json.Unmarshal([]byte(raw), &set); e != nil {
				rows.Close()
				return out, e
			}
			for _, b := range set.Bindings {
				matched = matched || policies[b.PolicyID]
			}
		}
		if matched {
			devices[nas] = true
			out.Devices = append(out.Devices, nas)
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	rows, e = tx.QueryContext(ctx, "SELECT s.nas,s.session_id,s.username,s.status,COALESCE(g.policy_id,'') FROM sessions s LEFT JOIN access_grants g ON g.token=s.grant_token WHERE s.status IN ('active','stale') ORDER BY s.nas,s.session_id")
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var v ImpactSession
		var p string
		if e = rows.Scan(&v.NAS, &v.ID, &v.Username, &v.Status, &p); e != nil {
			return out, e
		}
		if policies[p] {
			out.Sessions = append(out.Sessions, v)
		} else if p == "" && devices[v.NAS] {
			out.UnlinkedSessions = append(out.UnlinkedSessions, v)
		}
	}
	return out, rows.Err()
}
func (s *Store) affectedPolicyIDs(ctx context.Context, tx *sql.Tx, kind, id string) (map[string]bool, error) {
	out := map[string]bool{}
	if kind != "authentication" {
		out[id] = true
		return out, nil
	}
	rows, e := tx.QueryContext(ctx, s.SQL("SELECT id FROM access_policies WHERE authentication_id=?"), id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var p string
		if e = rows.Scan(&p); e != nil {
			return nil, e
		}
		out[p] = true
	}
	return out, rows.Err()
}
func (s *Store) PublishPolicyDraft(ctx context.Context, kind, id string, revision int64, actor string) error {
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	d, e := draftTx(ctx, s, tx, kind, id)
	if e != nil {
		return e
	}
	if d.Revision != revision {
		return fmt.Errorf("draft changed; review impact again")
	}
	live, e := s.policySnapshot(ctx, tx, kind, id)
	if e != nil {
		return e
	}
	if string(live) != string(d.Base) {
		return fmt.Errorf("live policy changed; discard draft and create it again")
	}
	if e = s.applyPolicy(ctx, tx, kind, id, d.Payload); e != nil {
		return e
	}
	if kind == "authentication" {
		ids, err := s.affectedPolicyIDs(ctx, tx, kind, id)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "SAVEPOINT validate_dependents"); err != nil {
			return err
		}
		for policyID := range ids {
			for _, depKind := range []string{"access", "rules"} {
				raw, err := s.policySnapshot(ctx, tx, depKind, policyID)
				if err != nil {
					return err
				}
				if err = s.applyPolicy(ctx, tx, depKind, policyID, raw); err != nil {
					return fmt.Errorf("dependent policy %s: %w", policyID, err)
				}
			}
		}
		if _, err = tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT validate_dependents"); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "RELEASE SAVEPOINT validate_dependents"); err != nil {
			return err
		}
	}
	after, e := s.policySnapshot(ctx, tx, kind, id)
	if e != nil {
		return e
	}
	// A changed policy invalidates its existing grants. Disconnect workers use the
	// stored grant/session generation, not username, so other access stays intact.
	if string(after) != string(live) {
		ids, e := s.affectedPolicyIDs(ctx, tx, kind, id)
		if e != nil {
			return e
		}
		for p := range ids {
			if _, e = tx.ExecContext(ctx, s.SQL("UPDATE access_grants SET reason='policy published: reauthentication required',next_attempt=0 WHERE policy_id=? AND reason=''"), p); e != nil {
				return e
			}
		}
	}
	if _, e = tx.ExecContext(ctx, s.SQL("INSERT INTO policy_releases(id,kind,policy_id,before_payload,after_payload,actor,created_at) VALUES(?,?,?,?,?,?,?)"), uuid.NewString(), kind, id, string(live), string(after), actor, time.Now().Unix()); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, s.SQL("DELETE FROM policy_drafts WHERE kind=? AND policy_id=?"), kind, id); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) DiscardPolicyDraft(ctx context.Context, kind, id string, revision int64) error {
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.ExecContext(ctx, s.SQL("DELETE FROM policy_drafts WHERE kind=? AND policy_id=? AND revision=?"), kind, id, revision)
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return fmt.Errorf("draft changed; reload")
	}
	return tx.Commit()
}
func (s *Store) RollbackPolicyDraft(ctx context.Context, release, actor string) error {
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var kind, id, raw string
	if e = tx.QueryRowContext(ctx, s.SQL("SELECT kind,policy_id,before_payload FROM policy_releases WHERE id=?"), release).Scan(&kind, &id, &raw); e != nil {
		return e
	}
	if raw == "null" {
		return fmt.Errorf("first publication has no previous version; disable the policy through a draft")
	}
	if kind == "rules" {
		live, e := s.policySnapshot(ctx, tx, kind, id)
		if e != nil {
			return e
		}
		var old, current RuleSet
		json.Unmarshal([]byte(raw), &old)
		json.Unmarshal(live, &current)
		old.Version = current.Version
		raw = string(policyJSON(old))
	}
	return s.savePolicyDraftTx(ctx, tx, PolicyDraft{Kind: kind, PolicyID: id, Payload: json.RawMessage(raw)}, actor)
}
