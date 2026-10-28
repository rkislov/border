// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"context"
	"github.com/rkislov/border/internal/store"
	"log/slog"
	"time"
)

// StartRevocations owns a worker for exactly one tenant store.
func StartRevocations(parent context.Context, s *store.Store, syncStatus ...func(context.Context) error) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	statusDone := make(chan struct{})
	go func() {
		defer close(statusDone)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			for _, sync := range syncStatus {
				if err := sync(ctx); err != nil && ctx.Err() == nil {
					slog.Error("account status sync failed", "error", err)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {

			if err := RevokeSessions(ctx, s); err != nil && ctx.Err() == nil {
				slog.Error("access revocation scan failed", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { cancel(); <-done; <-statusDone }
}
func RevokeSessions(ctx context.Context, s *store.Store) error {
	if err := s.MarkStaleSessions(ctx); err != nil {
		return err
	}
	if err := s.RefreshRevocations(ctx); err != nil {
		return err
	}
	rows, err := s.DB.QueryContext(ctx, s.SQL(`SELECT s.nas,s.session_id,s.mac,s.username,s.updated_at,g.token,s.generation FROM sessions s JOIN access_grants g ON g.token=s.grant_token AND g.nas=s.nas WHERE s.status IN ('active','stale') AND g.reason<>'' AND s.revoke_next<=? ORDER BY s.revoke_next LIMIT 100`), time.Now().Unix())
	if err != nil {
		return err
	}
	type pending struct {
		session store.Session
		token   string
	}
	list := []pending{}
	for rows.Next() {
		var p pending
		if err = rows.Scan(&p.session.NAS, &p.session.ID, &p.session.MAC, &p.session.Username, &p.session.Updated, &p.token, &p.session.Generation); err != nil {
			rows.Close()
			return err
		}
		p.session.GrantToken = p.token
		list = append(list, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, p := range list {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Recheck grant association immediately before addressing the NAS.
		var token string
		if err = s.Row(ctx, "SELECT grant_token FROM sessions WHERE nas=? AND session_id=?", p.session.NAS, p.session.ID).Scan(&token); err != nil {
			return err
		}
		if token != p.token {
			continue
		}
		result, e := ChangeSession(ctx, s, p.session.NAS, p.session.ID, "disconnect", 0, p.session)
		outcome := "retry"
		if e == nil && result.Acknowledged {
			outcome = "acknowledged"
		}
		next := time.Now().Add(time.Minute).Unix()
		message := ""
		if e != nil {
			message = e.Error()
		}
		if result.Acknowledged {
			next = 0
		}
		if err = s.RecordRevocation(ctx, p.session, result.Code, int64(result.ErrorCause), message, next); err != nil {
			return err
		}

		if err = s.Audit(ctx, "revocation", p.session.NAS+"/"+p.session.ID, outcome, "automatic access revocation"); err != nil {
			return err
		}
	}
	return nil
}
