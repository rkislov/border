// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"context"
	"errors"
	"github.com/rkislov/border/internal/store"
	"log/slog"
	"time"
)

// StartRevocations owns a worker for exactly one tenant store.
func StartRevocations(parent context.Context, s *store.Store, syncStatus ...func(context.Context) error) func() {
	return StartRevocationsWithFallback(parent, s, nil, syncStatus...)
}
func StartRevocationsWithFallback(parent context.Context, s *store.Store, fallback DisconnectFallback, syncStatus ...func(context.Context) error) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	statusDone := make(chan struct{})
	retentionDone := make(chan struct{})
	scheduleDone := make(chan struct{})
	go func() {
		defer close(scheduleDone)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			run, cancelRun := context.WithTimeout(ctx, 30*time.Second)
			started := time.Now()
			err := s.RunPolicySchedules(run, started)
			s.Metrics.Finish("policy_schedule", started, err)
			cancelRun()
			if err != nil && ctx.Err() == nil {
				slog.Error("policy schedule scan failed", "error", err)
			}
			run, cancelRun = context.WithTimeout(ctx, 10*time.Second)
			started = time.Now()
			err = s.RunPublicationResults(run, started)
			s.Metrics.Finish("publication_results", started, err)
			cancelRun()
			if err != nil && ctx.Err() == nil {
				slog.Error("publication result scan failed", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	go func() {
		defer close(retentionDone)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			run, cancelRun := context.WithTimeout(ctx, 10*time.Second)
			started := time.Now()
			err := s.PruneHistory(run, time.Now())
			s.Metrics.Finish("retention", started, err)
			cancelRun()
			if err != nil && ctx.Err() == nil {
				slog.Error("history cleanup failed", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	go func() {
		defer close(statusDone)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			for _, sync := range syncStatus {
				started := time.Now()
				err := sync(ctx)
				s.Metrics.Finish("account_sync", started, err)
				if err != nil && ctx.Err() == nil {
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

			started := time.Now()
			err := RevokeSessions(ctx, s, fallback)
			s.Metrics.Finish("revocation", started, err)
			if err != nil && ctx.Err() == nil {
				slog.Error("access revocation scan failed", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { cancel(); <-done; <-statusDone; <-retentionDone; <-scheduleDone }
}
func RevokeSessions(ctx context.Context, s *store.Store, fallbacks ...DisconnectFallback) error {
	var fallback DisconnectFallback
	if len(fallbacks) > 0 {
		fallback = fallbacks[0]
	}
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
		result, e := ChangeSessionWithFallback(ctx, s, p.session.NAS, p.session.ID, "disconnect", 0, fallback, p.session)
		if errors.Is(e, errRevocationRecord) {
			return e
		}
		outcome := "retry"
		if e == nil && result.Acknowledged {
			outcome = "acknowledged"
		}
		if err = s.Audit(ctx, "revocation", p.session.NAS+"/"+p.session.ID, outcome, "automatic access revocation"); err != nil {
			return err
		}
	}
	return nil
}
