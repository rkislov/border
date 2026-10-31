// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
)

type ChangeDevice struct {
	Address, Name, Dictionary, LocationID string
	policy, bindings                      string
}
type ChangeSession struct {
	NAS, ID, Username, Status, Generation, PolicyID string
	ReauthenticationRequested                       bool
}
type PublicationChange struct {
	Draft   PolicyDraft
	After   json.RawMessage
	Authors []string
}
type PublicationSnapshot struct {
	ImpactAvailable                 bool
	Requester, Reviewer             string `json:",omitempty"`
	RequestComment, DecisionComment string `json:",omitempty"`
	Devices                         []ChangeDevice
	Sessions, UnlinkedSessions      []ChangeSession
	Changes                         []PublicationChange
	GrantCount                      int
}

func (s *Store) journalDevices(ctx context.Context, tx *sql.Tx) ([]ChangeDevice, error) {
	rows, e := tx.QueryContext(ctx, "SELECT n.address,n.name,n.dictionary,COALESCE(n.location_id,''),COALESCE(n.access_policy_id,''),COALESCE(p.config,'') FROM nas n LEFT JOIN nas_policy_sets p ON p.nas=n.address")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ChangeDevice{}
	for rows.Next() {
		var d ChangeDevice
		if e = rows.Scan(&d.Address, &d.Name, &d.Dictionary, &d.LocationID, &d.policy, &d.bindings); e != nil {
			return nil, e
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
func (s *Store) journalPublication(ctx context.Context, tx *sql.Tx, actor, batch, review string, ds []PolicyDraft, after []json.RawMessage, t impactTargets, before []ChangeDevice, grants int) error {
	snapshot := PublicationSnapshot{ImpactAvailable: true, Devices: []ChangeDevice{}, Sessions: []ChangeSession{}, UnlinkedSessions: []ChangeSession{}, Changes: []PublicationChange{}, GrantCount: grants}
	if review != "" {
		if e := tx.QueryRowContext(ctx, s.SQL("SELECT requester,reviewer,request_comment,decision_comment FROM policy_reviews WHERE id=?"), review).Scan(&snapshot.Requester, &snapshot.Reviewer, &snapshot.RequestComment, &snapshot.DecisionComment); e != nil {
			return e
		}
	}
	current, e := s.journalDevices(ctx, tx)
	if e != nil {
		return e
	}
	devices := map[string]ChangeDevice{}
	for _, n := range append(before, current...) {
		match := t.matches(n.Address, n.policy)
		if n.bindings != "" {
			var set NASPolicySet
			if e = json.Unmarshal([]byte(n.bindings), &set); e != nil {
				return e
			}
			for _, b := range set.Bindings {
				match = match || t.matches(n.Address, b.PolicyID)
			}
		}
		if match {
			devices[n.Address] = n
		}
	}
	grantsToObserve, e := s.publicationGrants(ctx, tx, t, devices)
	if e != nil {
		return e
	}
	rows, e := tx.QueryContext(ctx, "SELECT s.nas,s.session_id,s.username,s.status,s.generation,COALESCE(g.policy_id,''),COALESCE(g.token,''),COALESCE(g.reason,'') FROM sessions s LEFT JOIN access_grants g ON g.token=s.grant_token AND g.nas=s.nas WHERE s.status IN ('active','stale') ORDER BY s.nas,s.session_id")
	if e != nil {
		return e
	}
	type item struct {
		v             ChangeSession
		token, reason string
	}
	items := []item{}
	for rows.Next() {
		var i item
		if e = rows.Scan(&i.v.NAS, &i.v.ID, &i.v.Username, &i.v.Status, &i.v.Generation, &i.v.PolicyID, &i.token, &i.reason); e != nil {
			rows.Close()
			return e
		}
		items = append(items, i)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	// First determine all affected NAS, then classify unlinked sessions independently of row order.
	for _, i := range items {
		if i.token != "" && t.matches(i.v.NAS, i.v.PolicyID) {
			if _, ok := devices[i.v.NAS]; !ok {
				devices[i.v.NAS] = ChangeDevice{Address: i.v.NAS}
			}
		}
	}
	for _, i := range items {
		if i.token != "" && t.matches(i.v.NAS, i.v.PolicyID) {
			i.v.ReauthenticationRequested = i.reason == ""
			snapshot.Sessions = append(snapshot.Sessions, i.v)
		} else if i.token == "" {
			if _, ok := devices[i.v.NAS]; ok {
				snapshot.UnlinkedSessions = append(snapshot.UnlinkedSessions, i.v)
			}
		}
	}
	for _, n := range devices {
		snapshot.Devices = append(snapshot.Devices, n)
	}
	sort.Slice(snapshot.Devices, func(i, j int) bool { return snapshot.Devices[i].Address < snapshot.Devices[j].Address })
	refs := []DraftRef{}
	for i, d := range ds {
		change := PublicationChange{Draft: d, After: after[i], Authors: []string{}}
		rows, e = tx.QueryContext(ctx, s.SQL("SELECT username FROM policy_draft_authors WHERE kind=? AND policy_id=? ORDER BY username"), d.Kind, d.PolicyID)
		if e != nil {
			return e
		}
		for rows.Next() {
			var name string
			if e = rows.Scan(&name); e != nil {
				rows.Close()
				return e
			}
			change.Authors = append(change.Authors, name)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		snapshot.Changes = append(snapshot.Changes, change)
		refs = append(refs, DraftRef{d.Kind, d.PolicyID, d.Revision})
	}
	if e = s.appendChange(ctx, tx, ChangeEvent{Action: "published", Actor: actor, BatchID: batch, ReviewID: review}, refs, snapshot); e != nil {
		return e
	}
	return s.startPublicationResult(ctx, tx, batch, review, snapshot, grantsToObserve)
}
