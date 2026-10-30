// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	"time"
)

type PolicySchedule struct {
	ID, ReviewID, Actor, State, Reason, BatchID string
	DueAt, CreatedAt, UpdatedAt, ExpiresAt      int64
}

func (s *Store) scheduledReview(ctx context.Context, tx *sql.Tx, id, actor string) ([]DraftRef, error) {
	settings, e := s.reviewSettingsTx(ctx, tx)
	if e != nil {
		return nil, e
	}
	if !settings.Required {
		return nil, fmt.Errorf("approval: review mode is disabled")
	}
	v, e := scanReview(tx.QueryRowContext(ctx, s.SQL("SELECT "+reviewColumns+" FROM policy_reviews WHERE id=?"), id).Scan)
	if e != nil {
		return nil, e
	}
	if v.State != "approved" {
		return nil, fmt.Errorf("approval: request is no longer approved")
	}
	ds, e := s.batchDrafts(ctx, tx, v.Drafts)
	if e != nil {
		return nil, e
	}
	approved, e := s.requireBatchApproval(ctx, tx, ds, actor)
	if e != nil {
		return nil, e
	}
	if approved != id {
		return nil, fmt.Errorf("approval: package changed")
	}
	return v.Drafts, nil
}
func (s *Store) SchedulePolicyReview(ctx context.Context, reviewID string, due int64, actor string) (string, error) {
	tx, e := s.policyTx(ctx)
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if due <= now || due > now+366*86400 {
		return "", fmt.Errorf("schedule: choose a future time within one year")
	}
	revision, e := s.reviewAdmin(ctx, tx, actor)
	if e != nil {
		return "", e
	}
	refs, e := s.scheduledReview(ctx, tx, reviewID, actor)
	if e != nil {
		return "", e
	}
	ds, e := s.batchDrafts(ctx, tx, refs)
	if e != nil {
		return "", e
	}
	if e = s.validateReviewBatch(ctx, tx, ds); e != nil {
		return "", e
	}
	var n int
	if e = tx.QueryRowContext(ctx, s.SQL("SELECT COUNT(*) FROM policy_schedules WHERE review_id=? AND state='pending'"), reviewID).Scan(&n); e != nil {
		return "", e
	}
	if n > 0 {
		return "", fmt.Errorf("schedule: cancel the existing schedule first")
	}
	settings, e := s.publicationWindowsTx(ctx, tx)
	if e != nil {
		return "", e
	}
	if e = settings.Validate(); e != nil {
		return "", e
	}
	id := uuid.NewString()
	_, e = tx.ExecContext(ctx, s.SQL("INSERT INTO policy_schedules(id,review_id,actor,actor_revision,due_at,state,created_at,updated_at,expires_at) VALUES(?,?,?,?,?,'pending',?,?,?)"), id, reviewID, actor, revision, due, now, now, due+settings.MaxDelaySeconds)
	if e != nil {
		return "", e
	}
	if e = s.reviewAudit(ctx, tx, actor, fmt.Sprintf("schedule policy publication %s review %s at %d", id, reviewID, due)); e != nil {
		return "", e
	}
	return id, tx.Commit()
}
func (s *Store) CancelPolicySchedule(ctx context.Context, id, actor string) error {
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = s.reviewAdmin(ctx, tx, actor); e != nil {
		return e
	}
	result, e := tx.ExecContext(ctx, s.SQL("UPDATE policy_schedules SET state='cancelled',reason='cancelled by administrator',updated_at=? WHERE id=? AND state='pending'"), time.Now().Unix(), id)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return fmt.Errorf("schedule: schedule is no longer pending")
	}
	if e = s.reviewAudit(ctx, tx, actor, "cancel policy schedule "+id); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) PolicySchedules(ctx context.Context) ([]PolicySchedule, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT id,review_id,actor,state,reason,batch_id,due_at,created_at,updated_at,expires_at FROM policy_schedules WHERE state='pending' OR id IN (SELECT id FROM policy_schedules ORDER BY updated_at DESC,id DESC LIMIT 100) ORDER BY due_at,id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []PolicySchedule{}
	for rows.Next() {
		var v PolicySchedule
		if e = rows.Scan(&v.ID, &v.ReviewID, &v.Actor, &v.State, &v.Reason, &v.BatchID, &v.DueAt, &v.CreatedAt, &v.UpdatedAt, &v.ExpiresAt); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// RunPolicySchedules is restart safe: configuration and the terminal job state
// commit together under the same cross-process policy lock as manual publication.
func (s *Store) RunPolicySchedules(ctx context.Context, now time.Time) error {
	started := time.Now()
	rows, e := s.DB.QueryContext(ctx, s.SQL("SELECT id FROM policy_schedules WHERE state='pending' AND due_at<=? ORDER BY due_at,id LIMIT 100"), now.Unix())
	if e != nil {
		return e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, id := range ids {
		if e = s.runPolicySchedule(ctx, id, now.Add(time.Since(started)).Unix()); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) runPolicySchedule(ctx context.Context, id string, now int64) error {
	started := time.Now()
	clock := func() int64 { return now + int64(time.Since(started)/time.Second) }
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var review, actor string
	var revision, due, expires int64
	e = tx.QueryRowContext(ctx, s.SQL("SELECT review_id,actor,actor_revision,due_at,expires_at FROM policy_schedules WHERE id=? AND state='pending' AND due_at<=?"), id, now).Scan(&review, &actor, &revision, &due, &expires)
	if e == sql.ErrNoRows {
		return nil
	}
	if e != nil {
		return e
	}

	settings, e := s.publicationWindowsTx(ctx, tx)
	if e != nil {
		return e
	}
	deadline := expires
	if current := due + settings.MaxDelaySeconds; current < deadline {
		deadline = current
	}
	expire := func() error {
		if _, e = tx.ExecContext(ctx, s.SQL("UPDATE policy_schedules SET state='expired',reason='maximum publication delay exceeded',updated_at=? WHERE id=?"), clock(), id); e != nil {
			return e
		}
		if e = s.reviewAudit(ctx, tx, actor, "scheduled policy publication "+id+": expired maximum publication delay exceeded"); e != nil {
			return e
		}
		return tx.Commit()
	}
	if clock() >= deadline {
		return expire()
	}
	allowed, e := settings.Allows(time.Unix(clock(), 0))
	if e != nil {
		return e
	}
	if !allowed {
		if _, e = tx.ExecContext(ctx, s.SQL("UPDATE policy_schedules SET reason='waiting for maintenance window',updated_at=? WHERE id=? AND reason<>'waiting for maintenance window'"), clock(), id); e != nil {
			return e
		}
		return tx.Commit()
	}
	if _, e = tx.ExecContext(ctx, "SAVEPOINT scheduled_publication"); e != nil {
		return e
	}
	publish := func() error {
		current, e := s.reviewAdmin(ctx, tx, actor)
		if e != nil {
			return e
		}
		if current != revision {
			return fmt.Errorf("approval: scheduling administrator account changed")
		}
		refs, e := s.scheduledReview(ctx, tx, review, actor)
		if e != nil {
			return e
		}
		return s.publishPolicyBatchTx(ctx, tx, refs, actor)
	}
	state, reason, batch := "published", "", ""
	if e = publish(); e != nil {
		state = "blocked"
		reason = e.Error()
		if _, e = tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT scheduled_publication"); e != nil {
			return e
		}
	} else {
		if e = tx.QueryRowContext(ctx, s.SQL("SELECT batch_id FROM policy_reviews WHERE id=?"), review).Scan(&batch); e != nil {
			return e
		}
	}

	// Do not commit if validation or lock contention crossed the deadline/window.
	if state == "published" {
		if clock() >= deadline {
			if _, e = tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT scheduled_publication"); e != nil {
				return e
			}
			return expire()
		}
		if e = s.checkPublicationWindow(ctx, tx, time.Unix(clock(), 0)); e != nil {
			if _, e = tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT scheduled_publication"); e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, s.SQL("UPDATE policy_schedules SET reason='waiting for maintenance window',updated_at=? WHERE id=?"), clock(), id); e != nil {
				return e
			}
			return tx.Commit()
		}
	}
	if _, e = tx.ExecContext(ctx, "RELEASE SAVEPOINT scheduled_publication"); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, s.SQL("UPDATE policy_schedules SET state=?,reason=?,batch_id=?,updated_at=? WHERE id=?"), state, reason, batch, now, id); e != nil {
		return e
	}
	if e = s.reviewAudit(ctx, tx, actor, "scheduled policy publication "+id+": "+state+" "+reason); e != nil {
		return e
	}
	return tx.Commit()
}
