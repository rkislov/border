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
	if err := s.RefreshRevocations(ctx); err != nil {
		return err
	}
	rows, err := s.DB.QueryContext(ctx, s.SQL(`SELECT s.nas,s.session_id,s.mac,s.username,s.updated_at,g.token FROM sessions s JOIN access_grants g ON g.token=s.grant_token AND g.nas=s.nas WHERE s.status='active' AND g.reason<>'' AND g.next_attempt<=? ORDER BY g.next_attempt LIMIT 100`), time.Now().Unix())
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
		if err = rows.Scan(&p.session.NAS, &p.session.ID, &p.session.MAC, &p.session.Username, &p.session.Updated, &p.token); err != nil {
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
		if err = s.Exec(ctx, "UPDATE access_grants SET attempts=attempts+1,next_attempt=? WHERE token=?", time.Now().Add(time.Minute).Unix(), p.token); err != nil {
			return err
		}
		if err = s.Audit(ctx, "revocation", p.session.NAS+"/"+p.session.ID, outcome, "automatic access revocation"); err != nil {
			return err
		}
	}
	return nil
}
