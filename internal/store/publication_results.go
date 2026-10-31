// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

const publicationObservationSeconds int64 = 600
const publicationStopSeconds int64 = 300

type PublicationSessionResult struct {
	NAS, ID, Generation, Username, PolicyID, State, SessionStatus      string
	Attempts                                                           int
	LastAttempt, NextAttempt, ErrorCause, AckAt, DeadlineAt, UpdatedAt int64
	Response, LastError                                                string
	NASResponse                                                        string
	NASCause                                                           int64
}
type PublicationAttempt struct {
	NAS, ID, Generation, Response, Message string
	At, ErrorCause                         int64
	NASResponse                            string
	NASCause                               int64
}
type PublicationPendingGrant struct {
	NAS, Username, PolicyID, State string
	DeadlineAt                     int64
}
type PublicationResult struct {
	BatchID, State                       string
	CreatedAt, UpdatedAt                 int64
	Sessions                             []PublicationSessionResult
	Attempts                             []PublicationAttempt
	AttemptsTruncated                    bool
	WaitingAccounting, AccountingTimeout int
	PendingGrants                        []PublicationPendingGrant
}
type RevocationNASResponse struct {
	Code  string
	Cause int64
}

type publicationGrant struct {
	token, nas, user, policy string
	expires                  int64
}

func lockAccountingNAS(ctx context.Context, s *Store, tx *sql.Tx, nas string) error {
	_, e := tx.ExecContext(ctx, s.SQL("INSERT INTO accounting_nas(nas) VALUES(?) ON CONFLICT(nas) DO UPDATE SET nas=excluded.nas"), nas)
	return e
}

// Policy writers acquire the policy lock before NAS locks; accounting never takes
// the policy lock. This freezes generations while publication targets are saved.
func (s *Store) publicationGrants(ctx context.Context, tx *sql.Tx, t impactTargets, devices map[string]ChangeDevice) ([]publicationGrant, error) {
	rows, e := tx.QueryContext(ctx, "SELECT token,nas,username,policy_id,expires_at FROM access_grants")
	if e != nil {
		return nil, e
	}
	grants := []publicationGrant{}
	nas := map[string]bool{}
	for n := range devices {
		nas[n] = true
	}
	for rows.Next() {
		var g publicationGrant
		if e = rows.Scan(&g.token, &g.nas, &g.user, &g.policy, &g.expires); e != nil {
			rows.Close()
			return nil, e
		}
		if t.matches(g.nas, g.policy) {
			grants = append(grants, g)
			nas[g.nas] = true
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	names := []string{}
	for n := range nas {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if e = lockAccountingNAS(ctx, s, tx, n); e != nil {
			return nil, e
		}
	}
	return grants, nil
}
func (s *Store) startPublicationResult(ctx context.Context, tx *sql.Tx, batch, review string, snapshot PublicationSnapshot, grants []publicationGrant) error {
	now := time.Now().Unix()
	if _, e := tx.ExecContext(ctx, s.SQL("INSERT INTO publication_results(batch_id,review_id,created_at,updated_at) VALUES(?,?,?,?)"), batch, review, now, now); e != nil {
		return e
	}
	for _, v := range append(snapshot.Sessions, snapshot.UnlinkedSessions...) {
		if e := s.insertPublicationSession(ctx, tx, batch, v.NAS, v.ID, v.Generation, now); e != nil {
			return e
		}
	}
	for _, g := range grants {
		// A grant with prior accounting is represented by its recorded generations;
		// only an unobserved, unexpired grant needs recovery from a late Start/Interim.
		if g.expires <= now {
			continue
		}
		var n int
		if e := tx.QueryRowContext(ctx, s.SQL("SELECT COUNT(*) FROM accounting_grants WHERE nas=? AND token=?"), g.nas, g.token).Scan(&n); e != nil {
			return e
		}
		if n > 0 {
			continue
		}
		if _, e := tx.ExecContext(ctx, s.SQL("INSERT INTO publication_pending_grants(batch_id,token,nas,username,policy_id,deadline_at) VALUES(?,?,?,?,?,?)"), batch, g.token, g.nas, g.user, g.policy, now+publicationObservationSeconds); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) insertPublicationSession(ctx context.Context, tx *sql.Tx, batch, nas, id, generation string, now int64) error {
	_, e := tx.ExecContext(ctx, s.SQL(`INSERT INTO publication_session_results(batch_id,nas,session_id,generation,grant_token,username,policy_id,state,session_status,started_at,event_at,deadline_at,updated_at)
 SELECT ?,s.nas,s.session_id,s.generation,s.grant_token,s.username,COALESCE(g.policy_id,''),CASE WHEN g.token IS NULL THEN 'unlinked' ELSE 'pending' END,s.status,s.started_at,s.event_at,?,? FROM sessions s LEFT JOIN access_grants g ON g.token=s.grant_token AND g.nas=s.nas WHERE s.nas=? AND s.session_id=? AND s.generation=?
 ON CONFLICT(batch_id,nas,session_id,generation) DO NOTHING`), batch, now+publicationObservationSeconds, now, nas, id, generation)
	return e
}
func publicationTerminal(state string) bool {
	return state == "stopped" || state == "nas_on" || state == "nas_off" || state == "adapter_confirmed"
}

// Called under the NAS accounting lock. Preserve outcomes independently of the
// live session row so reconnects, retention and process restarts cannot erase them.
func (s *Store) observePublicationSessions(ctx context.Context, tx *sql.Tx, nas string, now int64) error {
	rows, e := tx.QueryContext(ctx, s.SQL(`SELECT p.batch_id,s.session_id,s.generation,p.token FROM publication_pending_grants p JOIN sessions s ON s.nas=p.nas AND s.grant_token=p.token WHERE p.nas=? AND p.state<>'observed'`), nas)
	if e != nil {
		return e
	}
	pending := [][4]string{}
	for rows.Next() {
		var v [4]string
		if e = rows.Scan(&v[0], &v[1], &v[2], &v[3]); e != nil {
			rows.Close()
			return e
		}
		pending = append(pending, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, v := range pending {
		if e = s.insertPublicationSession(ctx, tx, v[0], nas, v[1], v[2], now); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, s.SQL("UPDATE publication_pending_grants SET state='observed' WHERE batch_id=? AND token=?"), v[0], v[3]); e != nil {
			return e
		}
	}
	rows, e = tx.QueryContext(ctx, s.SQL(`SELECT p.batch_id,p.session_id,p.generation,p.state,p.deadline_at,p.ack_at,COALESCE(s.generation,''),COALESCE(s.status,''),COALESCE(s.event_at,0) FROM publication_session_results p LEFT JOIN sessions s ON s.nas=p.nas AND s.session_id=p.session_id WHERE p.nas=? AND p.state NOT IN ('stopped','nas_on','nas_off','adapter_confirmed')`), nas)
	if e != nil {
		return e
	}
	type observation struct {
		batch, id, gen, state, liveGen, status string
		deadline, ack, event                   int64
	}
	list := []observation{}
	for rows.Next() {
		var v observation
		if e = rows.Scan(&v.batch, &v.id, &v.gen, &v.state, &v.deadline, &v.ack, &v.liveGen, &v.status, &v.event); e != nil {
			rows.Close()
			return e
		}
		list = append(list, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, v := range list {
		state := v.state
		switch {
		case v.liveGen == "":
			state = "missing"
		case v.liveGen != v.gen:
			state = "superseded"
		case v.status == "stopped":
			state = "stopped"
		case v.status == "nas-on":
			state = "nas_on"
		case v.status == "nas-off":
			state = "nas_off"
		case v.status == "disconnect-ack":
			if v.ack == 0 {
				v.ack = now
				v.deadline = now + publicationStopSeconds
			}
			state = "awaiting_stop"
		}
		if !publicationTerminal(state) && state != "superseded" && state != "missing" && state != "unlinked" && now >= v.deadline {
			state = "timeout"
		}
		// Never copy a new generation's status/timestamp onto the old result.
		if v.liveGen != v.gen {
			v.status = ""
			v.event = 0
		}
		if _, e = tx.ExecContext(ctx, s.SQL(`UPDATE publication_session_results SET state=?,ack_at=?,deadline_at=?,session_status=CASE WHEN ?='' THEN session_status ELSE ? END,event_at=CASE WHEN ?>event_at THEN ? ELSE event_at END,updated_at=CASE WHEN state<>? THEN ? ELSE updated_at END WHERE batch_id=? AND nas=? AND session_id=? AND generation=?`), state, v.ack, v.deadline, v.status, v.status, v.event, v.event, state, now, v.batch, nas, v.id, v.gen); e != nil {
			return e
		}
	}
	return nil
}

func (s *Store) BeginPublicationRevocation(ctx context.Context, v Session) error {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = lockAccountingNAS(ctx, s, tx, v.NAS); e != nil {
		return e
	}
	if e = s.observePublicationSessions(ctx, tx, v.NAS, time.Now().Unix()); e != nil {
		return e
	}
	var current int
	if e = tx.QueryRowContext(ctx, s.SQL("SELECT COUNT(*) FROM sessions WHERE nas=? AND session_id=? AND generation=? AND status IN ('active','stale')"), v.NAS, v.ID, v.Generation).Scan(&current); e != nil {
		return e
	}
	if current != 1 {
		return fmt.Errorf("session changed before disconnect")
	}
	_, e = tx.ExecContext(ctx, s.SQL("UPDATE publication_session_results SET state='sending',updated_at=? WHERE nas=? AND session_id=? AND generation=? AND state IN ('pending','retrying','sending')"), time.Now().Unix(), v.NAS, v.ID, v.Generation)
	if e != nil {
		return e
	}
	return tx.Commit()
}

func (s *Store) recordPublicationRevocation(ctx context.Context, tx *sql.Tx, v Session, response string, cause int64, message string, next, now int64, nasResponse RevocationNASResponse) error {
	rows, e := tx.QueryContext(ctx, s.SQL("SELECT batch_id FROM publication_session_results WHERE nas=? AND session_id=? AND generation=?"), v.NAS, v.ID, v.Generation)
	if e != nil {
		return e
	}
	batches := []string{}
	for rows.Next() {
		var b string
		if e = rows.Scan(&b); e != nil {
			rows.Close()
			return e
		}
		batches = append(batches, b)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, b := range batches {
		if _, e = tx.ExecContext(ctx, s.SQL("INSERT INTO publication_revocation_attempts(id,batch_id,nas,session_id,generation,attempted_at,response,error_cause,message,nas_response,nas_cause) VALUES(?,?,?,?,?,?,?,?,?,?,?)"), uuid.NewString(), b, v.NAS, v.ID, v.Generation, now, response, cause, message, nasResponse.Code, nasResponse.Cause); e != nil {
			return e
		}
	}
	state := "retrying"
	ack := int64(0)
	deadline := int64(0)
	if response == "Disconnect-ACK" {
		state = "awaiting_stop"
		ack = now
		deadline = now + publicationStopSeconds
	}
	if response == "RouterOS-SSH-Disconnect" {
		state = "adapter_confirmed"
		ack = now
	}
	_, e = tx.ExecContext(ctx, s.SQL(`UPDATE publication_session_results SET attempts=attempts+1,last_attempt=?,next_attempt=?,response=?,nas_response=?,nas_cause=?,error_cause=?,last_error=?,updated_at=?,state=CASE WHEN state IN ('stopped','nas_on','nas_off','adapter_confirmed','superseded','missing') THEN state ELSE ? END,ack_at=CASE WHEN ?>0 THEN ? ELSE ack_at END,deadline_at=CASE WHEN ?>0 THEN ? ELSE deadline_at END WHERE nas=? AND session_id=? AND generation=?`), now, next, response, nasResponse.Code, nasResponse.Cause, cause, message, now, state, ack, ack, deadline, deadline, v.NAS, v.ID, v.Generation)
	if e != nil {
		return e
	}
	return s.observePublicationSessions(ctx, tx, v.NAS, now)
}

// RunPublicationResults reconciles and queues each problem/completion once. It
// owns no network I/O; delivery retries remain in the existing outbox worker.
func (s *Store) RunPublicationResults(ctx context.Context, now time.Time) error {
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	rows, e := tx.QueryContext(ctx, "SELECT batch_id,review_id,state FROM publication_results WHERE state<>'completed' ORDER BY checked_at,created_at,batch_id LIMIT 100")
	if e != nil {
		return e
	}
	runs := [][3]string{}
	args := []any{}
	marks := []string{}
	for rows.Next() {
		var r [3]string
		if e = rows.Scan(&r[0], &r[1], &r[2]); e != nil {
			rows.Close()
			return e
		}
		runs = append(runs, r)
		args = append(args, r[0])
		marks = append(marks, "?")
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if len(runs) == 0 {
		return tx.Commit()
	}
	selection := strings.Join(marks, ",")
	rows, e = tx.QueryContext(ctx, s.SQL("SELECT DISTINCT nas FROM publication_session_results WHERE batch_id IN ("+selection+") AND state NOT IN ('stopped','nas_on','nas_off','adapter_confirmed') UNION SELECT nas FROM publication_pending_grants WHERE batch_id IN ("+selection+") AND state<>'observed' ORDER BY nas"), append(append([]any{}, args...), args...)...)
	if e != nil {
		return e
	}
	names := []string{}
	for rows.Next() {
		var n string
		if e = rows.Scan(&n); e != nil {
			rows.Close()
			return e
		}
		names = append(names, n)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, n := range names {
		if e = lockAccountingNAS(ctx, s, tx, n); e != nil {
			return e
		}
		if e = s.observePublicationSessions(ctx, tx, n, now.Unix()); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, s.SQL("UPDATE publication_pending_grants SET state='accounting_timeout' WHERE batch_id IN ("+selection+") AND state='waiting_accounting' AND deadline_at<=?"), append(append([]any{}, args...), now.Unix())...); e != nil {
		return e
	}
	for _, r := range runs {
		var total, done, issues, pending, unknown int
		if e = tx.QueryRowContext(ctx, s.SQL(`SELECT COUNT(*),COALESCE(SUM(CASE WHEN state IN ('stopped','nas_on','nas_off','adapter_confirmed') THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN state IN ('retrying','timeout','unlinked','superseded','missing') THEN 1 ELSE 0 END),0) FROM publication_session_results WHERE batch_id=?`), r[0]).Scan(&total, &done, &issues); e != nil {
			return e
		}
		if e = tx.QueryRowContext(ctx, s.SQL(`SELECT COALESCE(SUM(CASE WHEN state='waiting_accounting' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN state='accounting_timeout' THEN 1 ELSE 0 END),0) FROM publication_pending_grants WHERE batch_id=?`), r[0]).Scan(&pending, &unknown); e != nil {
			return e
		}
		state := "in_progress"
		if total == done && pending+unknown == 0 {
			state = "completed"
		}
		if issues+unknown > 0 {
			state = "attention"
		}
		if _, e = tx.ExecContext(ctx, s.SQL("UPDATE publication_results SET checked_at=? WHERE batch_id=?"), now.Unix(), r[0]); e != nil {
			return e
		}
		if state == r[2] {
			continue
		}
		if _, e = tx.ExecContext(ctx, s.SQL("UPDATE publication_results SET state=?,updated_at=? WHERE batch_id=?"), state, now.Unix(), r[0]); e != nil {
			return e
		}
		summary := fmt.Sprintf("Пакет %s: подтверждено завершение %d из %d сессий; требуют внимания %d; ожидание accounting %d; accounting не получен %d.", r[0], done, total, issues, pending, unknown)
		if e = s.appendChange(ctx, tx, ChangeEvent{Action: "revocation_" + state, Actor: "system", BatchID: r[0], ReviewID: r[1], Summary: summary}, nil, nil); e != nil {
			return e
		}
		if state == "attention" || state == "completed" {
			if e = s.enqueuePolicyEvent(ctx, tx, "publication result "+state+" "+r[0], "Border: "+summary); e != nil {
				return e
			}
		}
	}
	return tx.Commit()
}

func (s *Store) PublicationResult(ctx context.Context, batch string) (*PublicationResult, error) {
	v := &PublicationResult{BatchID: batch, Sessions: []PublicationSessionResult{}, Attempts: []PublicationAttempt{}, PendingGrants: []PublicationPendingGrant{}}
	e := s.Row(ctx, "SELECT state,created_at,updated_at FROM publication_results WHERE batch_id=?", batch).Scan(&v.State, &v.CreatedAt, &v.UpdatedAt)
	if e == sql.ErrNoRows {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	rows, e := s.DB.QueryContext(ctx, s.SQL("SELECT nas,session_id,generation,username,policy_id,state,session_status,attempts,last_attempt,next_attempt,response,nas_response,nas_cause,error_cause,last_error,ack_at,deadline_at,updated_at FROM publication_session_results WHERE batch_id=? ORDER BY nas,session_id,generation"), batch)
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		var r PublicationSessionResult
		if e = rows.Scan(&r.NAS, &r.ID, &r.Generation, &r.Username, &r.PolicyID, &r.State, &r.SessionStatus, &r.Attempts, &r.LastAttempt, &r.NextAttempt, &r.Response, &r.NASResponse, &r.NASCause, &r.ErrorCause, &r.LastError, &r.AckAt, &r.DeadlineAt, &r.UpdatedAt); e != nil {
			rows.Close()
			return nil, e
		}
		v.Sessions = append(v.Sessions, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if e = s.Row(ctx, `SELECT COALESCE(SUM(CASE WHEN state='waiting_accounting' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN state='accounting_timeout' THEN 1 ELSE 0 END),0) FROM publication_pending_grants WHERE batch_id=?`, batch).Scan(&v.WaitingAccounting, &v.AccountingTimeout); e != nil {
		return nil, e
	}
	rows, e = s.DB.QueryContext(ctx, s.SQL("SELECT nas,username,policy_id,state,deadline_at FROM publication_pending_grants WHERE batch_id=? AND state<>'observed' ORDER BY nas,username,token"), batch)
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		var g PublicationPendingGrant
		if e = rows.Scan(&g.NAS, &g.Username, &g.PolicyID, &g.State, &g.DeadlineAt); e != nil {
			rows.Close()
			return nil, e
		}
		v.PendingGrants = append(v.PendingGrants, g)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	rows, e = s.DB.QueryContext(ctx, s.SQL("SELECT nas,session_id,generation,attempted_at,response,nas_response,nas_cause,error_cause,message FROM publication_revocation_attempts WHERE batch_id=? ORDER BY attempted_at DESC,id DESC LIMIT 201"), batch)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var a PublicationAttempt
		if e = rows.Scan(&a.NAS, &a.ID, &a.Generation, &a.At, &a.Response, &a.NASResponse, &a.NASCause, &a.ErrorCause, &a.Message); e != nil {
			return nil, e
		}
		v.Attempts = append(v.Attempts, a)
	}
	if len(v.Attempts) > 200 {
		v.Attempts = v.Attempts[:200]
		v.AttemptsTruncated = true
	}
	return v, rows.Err()
}

// A late Stop for a replaced grant may finish its historical publication target,
// but must never close the new live generation using the same NAS/session ID.
func (s *Store) observeHistoricalPublicationStop(ctx context.Context, tx *sql.Tx, e AccountingEvent, token string, now int64) error {
	_, err := tx.ExecContext(ctx, s.SQL(`UPDATE publication_session_results SET state='stopped',session_status='stopped',event_at=?,updated_at=? WHERE nas=? AND session_id=? AND grant_token=? AND event_at<=? AND (?='' OR username='' OR username=?) AND (?=0 OR ?>=started_at-5) AND state NOT IN ('stopped','nas_on','nas_off','adapter_confirmed')`), e.At, now, e.NAS, e.ID, token, e.At, e.Username, e.Username, integer(e.HasSeconds), e.At-e.Seconds)
	return err
}
