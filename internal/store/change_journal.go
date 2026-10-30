// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrChangeJournalFilter = errors.New("invalid journal filter")

type ChangeEvent struct {
	Seq, OccurredAt                                           int64
	ID, Action, Actor, ReviewID, BatchID, ScheduleID, Summary string
	Legacy                                                    bool
	Detail                                                    json.RawMessage `json:",omitempty"`
	ReleaseID                                                 string          `json:"-"`
}
type ChangeObject struct {
	Kind, PolicyID string
	Revision       int64
	CycleID        string
}
type ChangeDetail struct {
	Event             ChangeEvent
	Objects           []ChangeObject
	Timeline          []ChangeEvent
	TimelineTruncated bool
}
type ChangePage struct {
	Items      []ChangeEvent
	NextBefore int64
}

const changeColumns = "seq,id,occurred_at,action,actor,review_id,batch_id,schedule_id,summary,legacy,release_id"

func scanChange(scan func(...any) error) (ChangeEvent, error) {
	var v ChangeEvent
	e := scan(&v.Seq, &v.ID, &v.OccurredAt, &v.Action, &v.Actor, &v.ReviewID, &v.BatchID, &v.ScheduleID, &v.Summary, &v.Legacy, &v.ReleaseID)
	return v, e
}
func (s *Store) appendChange(ctx context.Context, tx *sql.Tx, v ChangeEvent, refs []DraftRef, detail any) error {
	v.ID = uuid.NewString()
	v.OccurredAt = time.Now().Unix()
	raw, e := json.Marshal(detail)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, s.SQL("INSERT INTO change_journal(seq,id,occurred_at,action,actor,review_id,batch_id,schedule_id,summary,detail) SELECT COALESCE(MAX(seq),0)+1,?,?,?,?,?,?,?,?,? FROM change_journal"), v.ID, v.OccurredAt, v.Action, v.Actor, v.ReviewID, v.BatchID, v.ScheduleID, v.Summary, string(raw))
	if e != nil {
		return e
	}
	for _, ref := range refs {
		var cycle string
		if v.ReviewID != "" {
			e = tx.QueryRowContext(ctx, s.SQL("SELECT o.cycle_id FROM change_journal_objects o JOIN change_journal j ON j.id=o.event_id WHERE j.review_id=? AND o.kind=? AND o.policy_id=? ORDER BY j.seq LIMIT 1"), v.ReviewID, ref.Kind, ref.PolicyID).Scan(&cycle)
			if e != nil && e != sql.ErrNoRows {
				return e
			}
		}
		if cycle == "" {
			e = tx.QueryRowContext(ctx, s.SQL("SELECT cycle_id FROM draft_journal_cycles WHERE kind=? AND policy_id=?"), ref.Kind, ref.PolicyID).Scan(&cycle)
			if e == sql.ErrNoRows {
				cycle = uuid.NewString()
				_, e = tx.ExecContext(ctx, s.SQL("INSERT INTO draft_journal_cycles(kind,policy_id,cycle_id) VALUES(?,?,?)"), ref.Kind, ref.PolicyID, cycle)
			}
			if e != nil {
				return e
			}
		}
		if _, e = tx.ExecContext(ctx, s.SQL("INSERT INTO change_journal_objects(event_id,kind,policy_id,revision,cycle_id) VALUES(?,?,?,?,?)"), v.ID, ref.Kind, ref.PolicyID, ref.Revision, cycle); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) appendReviewChange(ctx context.Context, tx *sql.Tx, id, action, actor, summary, schedule string) error {
	v, e := scanReview(tx.QueryRowContext(ctx, s.SQL("SELECT "+reviewColumns+" FROM policy_reviews WHERE id=?"), id).Scan)
	if e != nil {
		return e
	}
	return s.appendChange(ctx, tx, ChangeEvent{Action: action, Actor: actor, ReviewID: id, BatchID: v.BatchID, ScheduleID: schedule, Summary: summary}, v.Drafts, map[string]any{"Requester": v.Requester, "Reviewer": v.Reviewer, "Authors": v.Authors, "RequestComment": v.RequestComment, "DecisionComment": v.DecisionComment, "State": v.State})
}
func (s *Store) journalReviewAudit(ctx context.Context, tx *sql.Tx, actor, action string) error {
	for _, v := range [][2]string{{"submit policy approval ", "review_requested"}, {"approved policy approval ", "review_approved"}, {"rejected policy approval ", "review_rejected"}} {
		if strings.HasPrefix(action, v[0]) {
			return s.appendReviewChange(ctx, tx, strings.TrimPrefix(action, v[0]), v[1], actor, "", "")
		}
	}
	for _, prefix := range []string{"schedule policy publication ", "cancel policy schedule ", "scheduled policy publication "} {
		if strings.HasPrefix(action, prefix) {
			id := strings.TrimSuffix(strings.Fields(strings.TrimPrefix(action, prefix))[0], ":")
			var review, state, reason string
			var due, expires int64
			if e := tx.QueryRowContext(ctx, s.SQL("SELECT review_id,state,reason,due_at,expires_at FROM policy_schedules WHERE id=?"), id).Scan(&review, &state, &reason, &due, &expires); e != nil {
				return e
			}
			return s.appendReviewChange(ctx, tx, review, "schedule_"+state, actor, fmt.Sprintf("%s; DueAt=%d; ExpiresAt=%d", reason, due, expires), id)
		}
	}
	return s.appendChange(ctx, tx, ChangeEvent{Action: "configuration", Actor: actor, Summary: action}, nil, nil)
}
func (s *Store) ChangeJournal(ctx context.Context, q, actor, action string, before int64, limit int) (ChangePage, error) {
	out := ChangePage{Items: []ChangeEvent{}}
	if limit < 1 || limit > 100 || before < 0 || len(q) > 200 || len(actor) > 200 || len(action) > 50 {
		return out, ErrChangeJournalFilter
	}
	where := "1=1"
	args := []any{}
	if before > 0 {
		where += " AND seq<?"
		args = append(args, before)
	}
	if actor != "" {
		where += " AND actor=?"
		args = append(args, actor)
	}
	if action != "" {
		where += " AND action=?"
		args = append(args, action)
	}
	if q != "" {
		pattern := "%" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(strings.ToLower(q)) + "%"
		where += " AND (LOWER(actor||' '||review_id||' '||batch_id||' '||schedule_id||' '||summary) LIKE ? ESCAPE '!' OR EXISTS(SELECT 1 FROM change_journal_objects o WHERE o.event_id=change_journal.id AND LOWER(o.kind||' '||o.policy_id) LIKE ? ESCAPE '!'))"
		args = append(args, pattern, pattern)
	}
	args = append(args, limit+1)
	rows, e := s.DB.QueryContext(ctx, s.SQL("SELECT "+changeColumns+" FROM change_journal WHERE "+where+" ORDER BY seq DESC LIMIT ?"), args...)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		v, e := scanChange(rows.Scan)
		if e != nil {
			return out, e
		}
		out.Items = append(out.Items, v)
	}
	if e = rows.Err(); e != nil {
		return out, e
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextBefore = out.Items[limit-1].Seq
	}
	return out, nil
}
func (s *Store) ChangeJournalDetail(ctx context.Context, id string) (ChangeDetail, error) {
	out := ChangeDetail{Objects: []ChangeObject{}, Timeline: []ChangeEvent{}}
	v, e := scanChange(s.Row(ctx, "SELECT "+changeColumns+" FROM change_journal WHERE id=?", id).Scan)
	if e != nil {
		return out, e
	}
	var raw string
	if e = s.Row(ctx, "SELECT detail FROM change_journal WHERE id=?", id).Scan(&raw); e != nil {
		return out, e
	}
	v.Detail = json.RawMessage(raw)
	if v.Legacy && v.ReleaseID != "" {
		var release PolicyRelease
		var b, a string
		e = s.Row(ctx, "SELECT id,kind,policy_id,actor,created_at,batch_id,before_payload,after_payload FROM policy_releases WHERE id=?", v.ReleaseID).Scan(&release.ID, &release.Kind, &release.PolicyID, &release.Actor, &release.CreatedAt, &release.BatchID, &b, &a)
		if e != nil {
			return out, e
		}
		release.Before = json.RawMessage(b)
		release.After = json.RawMessage(a)
		v.Detail = policyJSON(map[string]any{"Release": release, "ImpactAvailable": false})
	}
	out.Event = v
	rows, e := s.DB.QueryContext(ctx, s.SQL("SELECT kind,policy_id,revision,cycle_id FROM change_journal_objects WHERE event_id=? ORDER BY kind,policy_id"), id)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var o ChangeObject
		if e = rows.Scan(&o.Kind, &o.PolicyID, &o.Revision, &o.CycleID); e != nil {
			rows.Close()
			return out, e
		}
		out.Objects = append(out.Objects, o)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	rows, e = s.DB.QueryContext(ctx, s.SQL("SELECT "+changeColumns+" FROM change_journal WHERE id=? OR (review_id<>'' AND review_id=?) OR (batch_id<>'' AND batch_id=?) OR EXISTS(SELECT 1 FROM change_journal_objects a JOIN change_journal_objects b ON a.cycle_id=b.cycle_id WHERE a.event_id=change_journal.id AND b.event_id=?) ORDER BY seq DESC LIMIT 501"), id, v.ReviewID, v.BatchID, id)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		item, e := scanChange(rows.Scan)
		if e != nil {
			return out, e
		}
		out.Timeline = append(out.Timeline, item)
	}
	if len(out.Timeline) > 500 {
		out.Timeline = out.Timeline[:500]
		out.TimelineTruncated = true
	}
	return out, rows.Err()
}
