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

type AccountingEvent struct {
	NAS, ID, MAC, Username, Kind, Key string
	Classes                           []string
	At, Seconds                       int64
	Timed, HasSeconds                 bool
}

// ApplyAccounting serializes events per NAS, including restart boundaries.
// Ignored duplicates and stale events still receive an Accounting-Response.
func (s *Store) ApplyAccounting(ctx context.Context, e AccountingEvent) error {
	now := time.Now().Unix()
	if e.At == 0 {
		e.At = now
	}
	if e.At > now+300 || e.At < 0 || e.Seconds < 0 {
		return fmt.Errorf("invalid accounting time")
	}
	if e.Kind != "on" && e.Kind != "off" && (e.ID == "" || (e.Kind != "start" && e.Kind != "interim" && e.Kind != "stop")) {
		return fmt.Errorf("invalid accounting event")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	exec := func(q string, args ...any) error { _, err := tx.ExecContext(ctx, s.SQL(q), args...); return err }
	// PostgreSQL ON CONFLICT takes a row lock; SQLite serializes writers.
	if err = exec("INSERT INTO accounting_nas(nas) VALUES(?) ON CONFLICT(nas) DO UPDATE SET nas=excluded.nas", e.NAS); err != nil {
		return err
	}
	var reset int64
	if err = tx.QueryRowContext(ctx, s.SQL("SELECT reset_at FROM accounting_nas WHERE nas=?"), e.NAS).Scan(&reset); err != nil {
		return err
	}
	if e.Key != "" {
		var received int64
		err = tx.QueryRowContext(ctx, s.SQL("SELECT received_at FROM accounting_events WHERE nas=? AND event_key=?"), e.NAS, e.Key).Scan(&received)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if err == nil && (e.Timed || e.HasSeconds || now-received < 120) {
			return tx.Commit()
		}
		if err = exec("INSERT INTO accounting_events(nas,event_key,received_at) VALUES(?,?,?) ON CONFLICT(nas,event_key) DO UPDATE SET received_at=excluded.received_at", e.NAS, e.Key, now); err != nil {
			return err
		}
	}
	ignore := func(reason string) error {
		if err := exec("INSERT INTO auth_log(id,occurred_at,source,identity,result,reason) VALUES(?,?,?,?,?,?)", uuid.NewString(), now, "accounting", e.NAS+"/"+e.ID, "ignored", reason); err != nil {
			return err
		}
		return tx.Commit()
	}
	if reset > 0 && e.At <= reset {
		return ignore("event before NAS restart")
	}
	if e.Kind == "on" || e.Kind == "off" {
		if e.At <= reset {
			return tx.Commit()
		}
		if err = exec("UPDATE accounting_nas SET reset_at=?,reset_kind=? WHERE nas=?", e.At, e.Kind, e.NAS); err != nil {
			return err
		}
		if err = exec("UPDATE sessions SET status=?,updated_at=?,revoke_next=0 WHERE nas=? AND status IN ('active','stale') AND event_at<=?", "nas-"+e.Kind, now, e.NAS, e.At); err != nil {
			return err
		}
		if err = exec("INSERT INTO auth_log(id,occurred_at,source,identity,result,reason) VALUES(?,?,?,?,?,?)", uuid.NewString(), now, "accounting", e.NAS, "nas-"+e.Kind, "Accounting-"+e.Kind); err != nil {
			return err
		}
		return tx.Commit()
	}
	token := ""
	for _, candidate := range e.Classes {
		var known string
		err = tx.QueryRowContext(ctx, s.SQL("SELECT token FROM access_grants WHERE token=? AND nas=?"), candidate, e.NAS).Scan(&known)
		if err == nil {
			token = known
			break
		}
		if err != sql.ErrNoRows {
			return err
		}
	}
	var oldToken, oldStatus, oldMAC, oldUser, generation string
	var last, started, seconds int64
	err = tx.QueryRowContext(ctx, s.SQL("SELECT grant_token,status,mac,username,generation,event_at,started_at,session_seconds FROM sessions WHERE nas=? AND session_id=?"), e.NAS, e.ID).Scan(&oldToken, &oldStatus, &oldMAC, &oldUser, &generation, &last, &started, &seconds)
	exists := err == nil
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	newGeneration := !exists
	if exists {
		if e.At < last {
			return ignore("out-of-order accounting event")
		}
		if token != "" && token != oldToken {
			if e.Kind == "stop" {
				return ignore("Stop belongs to another grant")
			}
			var seen int
			err = tx.QueryRowContext(ctx, s.SQL("SELECT 1 FROM accounting_grants WHERE nas=? AND session_id=? AND token=?"), e.NAS, e.ID, token).Scan(&seen)
			if err == nil {
				return ignore("old grant replay")
			}
			if err != sql.ErrNoRows {
				return err
			}
			// A different valid Class identifies a new authorization generation.
			newGeneration = true
		} else {
			if token == "" && oldToken != "" {
				if e.Kind == "start" {
					return ignore("ambiguous Start without Class")
				}
				// Require Class for tracked sessions: a missing value cannot prove identity.
				return ignore("missing Class for tracked session")
			}
			if oldStatus != "active" && oldStatus != "stale" {
				if token != "" || e.Kind != "start" || !e.Timed || e.At <= last {
					return ignore("closed session cannot be resurrected")
				}
				newGeneration = true
			} else if e.Kind == "start" && token == "" && e.Timed && e.At > last {
				newGeneration = true
			} else {
				if e.MAC != "" && oldMAC != "" && e.MAC != oldMAC || e.Username != "" && oldUser != "" && e.Username != oldUser {
					return ignore("session identity changed")
				}
				if e.HasSeconds && e.Seconds < seconds {
					return ignore("session time moved backwards")
				}
				if e.HasSeconds && e.At-e.Seconds < started-5 {
					return ignore("event belongs to older session generation")
				}
				if token == "" && generation != "" && e.Kind == "stop" && !e.Timed && !e.HasSeconds {
					return ignore("ambiguous Stop without timing")
				}
			}
		}
	}
	if newGeneration {
		generation = uuid.NewString()
		started = e.At
		if e.HasSeconds {
			started = e.At - e.Seconds
		}
		if token != "" {
			if err = exec("INSERT INTO accounting_grants(nas,session_id,token) VALUES(?,?,?) ON CONFLICT(nas,session_id,token) DO NOTHING", e.NAS, e.ID, token); err != nil {
				return err
			}
		}
	} else {
		if e.MAC == "" {
			e.MAC = oldMAC
		}
		if e.Username == "" {
			e.Username = oldUser
		}
		if !e.HasSeconds {
			e.Seconds = seconds
		}
	}
	status := "active"
	if e.Kind == "stop" {
		status = "stopped"
	}
	if err = exec(`INSERT INTO sessions(nas,session_id,mac,username,status,updated_at,grant_token,generation,event_at,started_at,session_seconds,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
 ON CONFLICT(nas,session_id) DO UPDATE SET mac=excluded.mac,username=excluded.username,status=excluded.status,updated_at=excluded.updated_at,grant_token=excluded.grant_token,generation=excluded.generation,event_at=excluded.event_at,started_at=excluded.started_at,session_seconds=excluded.session_seconds,last_seen=excluded.last_seen`, e.NAS, e.ID, e.MAC, e.Username, status, now, token, generation, e.At, started, e.Seconds, min(e.At, now)); err != nil {
		return err
	}
	if newGeneration {
		if err = exec("UPDATE sessions SET revoke_attempts=0,revoke_next=0,revoke_last=0,revoke_response='',revoke_error='',revoke_cause=0 WHERE nas=? AND session_id=?", e.NAS, e.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Missing updates mean unknown reachability, not proof of disconnection.
func (s *Store) MarkStaleSessions(ctx context.Context) error {
	if err := s.Exec(ctx, "UPDATE sessions SET status='stale' WHERE status='active' AND last_seen<?", time.Now().Unix()-900); err != nil {
		return err
	}
	return s.Exec(ctx, "DELETE FROM accounting_events WHERE received_at<?", time.Now().Add(-7*24*time.Hour).Unix())
}

func (s *Store) RecordRevocation(ctx context.Context, v Session, response string, cause int64, message string, next int64) error {
	return s.Exec(ctx, "UPDATE sessions SET revoke_attempts=revoke_attempts+1,revoke_last=?,revoke_next=CASE WHEN status IN ('active','stale') THEN ? ELSE 0 END,revoke_response=?,revoke_error=?,revoke_cause=? WHERE nas=? AND session_id=? AND generation=?", time.Now().Unix(), next, response, message, cause, v.NAS, v.ID, v.Generation)
}
func (s *Store) RetryRevocation(ctx context.Context, v Session) error {
	result, err := s.DB.ExecContext(ctx, s.SQL(`UPDATE sessions SET revoke_next=0 WHERE nas=? AND session_id=? AND generation=? AND status IN ('active','stale') AND EXISTS(SELECT 1 FROM access_grants g WHERE g.token=sessions.grant_token AND g.nas=sessions.nas AND g.reason<>'')`), v.NAS, v.ID, v.Generation)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("revocable session changed or no longer active")
	}
	return nil
}

// Serialize terminal transitions with accounting, so an in-flight Interim
// cannot overwrite a confirmed Disconnect-ACK.
func (s *Store) ConfirmDisconnect(ctx context.Context, v Session) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, s.SQL("INSERT INTO accounting_nas(nas) VALUES(?) ON CONFLICT(nas) DO UPDATE SET nas=excluded.nas"), v.NAS); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, s.SQL("UPDATE sessions SET status='disconnect-ack',updated_at=?,revoke_next=0 WHERE nas=? AND session_id=? AND mac=? AND username=? AND grant_token=? AND generation=? AND status IN ('active','stale')"), time.Now().Unix(), v.NAS, v.ID, v.MAC, v.Username, v.GrantToken, v.Generation)
	if err != nil {
		return err
	}
	return tx.Commit()
}
