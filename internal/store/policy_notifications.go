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

type PolicyNotificationTarget struct {
	EndpointHash                              string `json:"-"`
	ID, Username, Channel, Scope, Destination string
	Enabled                                   bool
	Revision                                  int64
}
type PolicyDelivery struct {
	ID, EventID, Username, Channel, State, Message, LastError string
	Attempts                                                  int
	NextAttempt, UpdatedAt                                    int64
}
type PolicyDeliveryJob struct {
	ID, Token, Message string
	Target             PolicyNotificationTarget
}

func (s *Store) PolicyNotificationTargets(ctx context.Context, user string) ([]PolicyNotificationTarget, error) {
	rows, e := s.DB.QueryContext(ctx, s.SQL("SELECT id,username,channel,scope,destination,enabled,revision FROM policy_notification_targets WHERE username=?"), user)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []PolicyNotificationTarget{}
	for rows.Next() {
		var v PolicyNotificationTarget
		if e = rows.Scan(&v.ID, &v.Username, &v.Channel, &v.Scope, &v.Destination, &v.Enabled, &v.Revision); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) SavePolicyNotificationTarget(ctx context.Context, v PolicyNotificationTarget) error {
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = s.reviewAdmin(ctx, tx, v.Username); e != nil {
		return e
	}
	if v.Channel != "email" && v.Channel != "sms" && v.Channel != "push" {
		return fmt.Errorf("invalid channel")
	}
	v.ID = v.Username + ":" + v.Channel
	var previous PolicyNotificationTarget
	e = tx.QueryRowContext(ctx, s.SQL("SELECT scope,destination,endpoint_hash,enabled FROM policy_notification_targets WHERE id=?"), v.ID).Scan(&previous.Scope, &previous.Destination, &previous.EndpointHash, &previous.Enabled)
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	if e == nil && previous.Scope == v.Scope && previous.Destination == v.Destination && previous.EndpointHash == v.EndpointHash && previous.Enabled == v.Enabled {
		return nil
	}

	_, e = tx.ExecContext(ctx, s.SQL("INSERT INTO policy_notification_targets(id,username,channel,scope,destination,endpoint_hash,enabled,revision) VALUES(?,?,?,?,?,?,?,1) ON CONFLICT(id) DO UPDATE SET scope=excluded.scope,destination=excluded.destination,endpoint_hash=excluded.endpoint_hash,enabled=excluded.enabled,revision=policy_notification_targets.revision+1"), v.ID, v.Username, v.Channel, v.Scope, v.Destination, v.EndpointHash, integer(v.Enabled))
	if e != nil {
		return e
	}
	// A changed address or subscription never receives deliveries created for its predecessor.
	_, e = tx.ExecContext(ctx, s.SQL("UPDATE policy_notification_deliveries SET state='cancelled',last_error='recipient settings changed',updated_at=? WHERE target_id=? AND state IN ('pending','failed')"), time.Now().Unix(), v.ID)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) enqueuePolicyEvent(ctx context.Context, tx *sql.Tx, key, message string) error {
	id := uuid.NewString()
	now := time.Now().Unix()
	result, e := tx.ExecContext(ctx, s.SQL("INSERT INTO policy_notification_events(id,event_key,message,created_at) VALUES(?,?,?,?) ON CONFLICT(event_key) DO NOTHING"), id, key, message, now)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil || n == 0 {
		return e
	}
	rows, e := tx.QueryContext(ctx, "SELECT t.id,t.revision FROM policy_notification_targets t JOIN admins a ON a.username=t.username WHERE t.enabled=1 AND a.enabled=1 AND a.role='admin'")
	if e != nil {
		return e
	}
	type dest struct {
		id  string
		rev int64
	}
	items := []dest{}
	for rows.Next() {
		var v dest
		if e = rows.Scan(&v.id, &v.rev); e != nil {
			rows.Close()
			return e
		}
		items = append(items, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, v := range items {
		if _, e = tx.ExecContext(ctx, s.SQL("INSERT INTO policy_notification_deliveries(id,event_id,target_id,target_revision,state,next_attempt,updated_at) VALUES(?,?,?,?,'pending',?,?) ON CONFLICT(event_id,target_id) DO NOTHING"), uuid.NewString(), id, v.id, v.rev, now, now); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) PolicyDeliveries(ctx context.Context) ([]PolicyDelivery, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT d.id,d.event_id,t.username,t.channel,d.state,e.message,d.last_error,d.attempts,d.next_attempt,d.updated_at FROM policy_notification_deliveries d JOIN policy_notification_events e ON e.id=d.event_id JOIN policy_notification_targets t ON t.id=d.target_id ORDER BY d.updated_at DESC,d.id DESC LIMIT 200")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []PolicyDelivery{}
	for rows.Next() {
		var v PolicyDelivery
		if e = rows.Scan(&v.ID, &v.EventID, &v.Username, &v.Channel, &v.State, &v.Message, &v.LastError, &v.Attempts, &v.NextAttempt, &v.UpdatedAt); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) ClaimPolicyDelivery(ctx context.Context, now int64) (*PolicyDeliveryJob, error) {
	tx, e := s.policyTx(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if e = s.refreshReviewAccounts(ctx, tx); e != nil {
		return nil, e
	}

	// Expired leases are recoverable after a process restart. Exhausted leases do not loop forever.
	_, e = tx.ExecContext(ctx, s.SQL("UPDATE policy_notification_deliveries SET state='failed',last_error='delivery outcome unknown after worker interruption',updated_at=? WHERE state='sending' AND lease_until<=? AND attempts>=6"), now, now)
	if e != nil {
		return nil, e
	}
	var j PolicyDeliveryJob
	var targetRevision int64
	e = tx.QueryRowContext(ctx, s.SQL("SELECT d.id,e.message,t.id,t.username,t.channel,t.scope,t.destination,t.enabled,t.revision,d.target_revision FROM policy_notification_deliveries d JOIN policy_notification_events e ON e.id=d.event_id JOIN policy_notification_targets t ON t.id=d.target_id WHERE (d.state='pending' AND d.next_attempt<=?) OR (d.state='sending' AND d.lease_until<=? AND d.attempts<6) ORDER BY d.next_attempt,d.id LIMIT 1"), now, now).Scan(&j.ID, &j.Message, &j.Target.ID, &j.Target.Username, &j.Target.Channel, &j.Target.Scope, &j.Target.Destination, &j.Target.Enabled, &j.Target.Revision, &targetRevision)
	if e == sql.ErrNoRows {
		return nil, tx.Commit()
	}
	if e != nil {
		return nil, e
	}
	_, adminErr := s.reviewAdmin(ctx, tx, j.Target.Username)
	if !j.Target.Enabled || targetRevision != j.Target.Revision || adminErr != nil {
		_, e = tx.ExecContext(ctx, s.SQL("UPDATE policy_notification_deliveries SET state='cancelled',last_error='recipient disabled or changed',updated_at=? WHERE id=?"), now, j.ID)
		if e != nil {
			return nil, e
		}
		return nil, tx.Commit()
	}
	j.Token = uuid.NewString()
	_, e = tx.ExecContext(ctx, s.SQL("UPDATE policy_notification_deliveries SET state='sending',attempts=attempts+1,lease_token=?,lease_until=?,updated_at=? WHERE id=?"), j.Token, now+120, now, j.ID)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return &j, nil
}
func (s *Store) FinishPolicyDelivery(ctx context.Context, j PolicyDeliveryJob, delivered bool, reason string, now int64) error {
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var attempts int
	e = tx.QueryRowContext(ctx, s.SQL("SELECT attempts FROM policy_notification_deliveries WHERE id=? AND state='sending' AND lease_token=?"), j.ID, j.Token).Scan(&attempts)
	if e == sql.ErrNoRows {
		return nil
	}
	if e != nil {
		return e
	}
	state := "sent"
	next := int64(0)
	if !delivered {
		state = "pending"
		next = now + int64(30*(1<<uint(attempts-1)))
		if attempts >= 6 {
			state = "failed"
		}
	}
	_, e = tx.ExecContext(ctx, s.SQL("UPDATE policy_notification_deliveries SET state=?,next_attempt=?,last_error=?,lease_until=0,lease_token='',updated_at=? WHERE id=?"), state, next, reason, now, j.ID)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) RetryPolicyDelivery(ctx context.Context, id, actor string) error {
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = s.reviewAdmin(ctx, tx, actor); e != nil {
		return e
	}
	res, e := tx.ExecContext(ctx, s.SQL("UPDATE policy_notification_deliveries SET state='pending',attempts=0,next_attempt=?,last_error='',updated_at=? WHERE id=? AND state='failed'"), time.Now().Unix(), time.Now().Unix(), id)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return fmt.Errorf("only failed deliveries can be retried")
	}
	return tx.Commit()
}
