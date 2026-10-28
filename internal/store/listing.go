// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"fmt"
	"strings"
)

type ListFilter struct {
	Query, Status, Result string
	From, Until           int64
	Page, Limit           int
}
type ListPage[T any] struct {
	Items       []T
	Total       int64
	Page, Limit int
}

func (f ListFilter) Validate() error {
	if len(f.Query) > 200 || len(f.Result) > 80 || f.Page < 1 || f.Page > 1000000 || f.Limit < 1 || f.Limit > 200 || f.From < 0 || f.Until < 0 || (f.From > 0 && f.Until > 0 && f.From > f.Until) {
		return fmt.Errorf("invalid pagination or filters")
	}
	switch f.Status {
	case "", "active", "stale", "stopped", "nas-on", "nas-off", "disconnect-ack":
	default:
		return fmt.Errorf("invalid session status")
	}
	return nil
}
func listWhere(f ListFilter, session bool) (string, []any) {
	clauses := []string{"1=1"}
	args := []any{}
	cols := []string{"source", "identity", "result", "reason"}
	stamp := "occurred_at"
	if session {
		cols = []string{"s.nas", "s.session_id", "s.mac", "s.username"}
		stamp = "s.updated_at"
	}
	if f.Query != "" {
		pattern := "%" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(f.Query) + "%"
		ors := []string{}
		for _, c := range cols {
			ors = append(ors, "LOWER("+c+") LIKE LOWER(?) ESCAPE '!'")
			args = append(args, pattern)
		}
		clauses = append(clauses, "("+strings.Join(ors, " OR ")+")")
	}
	if session && f.Status != "" {
		clauses = append(clauses, "s.status=?")
		args = append(args, f.Status)
	}
	if !session && f.Result != "" {
		clauses = append(clauses, "result=?")
		args = append(args, f.Result)
	}
	if f.From > 0 {
		clauses = append(clauses, stamp+">=?")
		args = append(args, f.From)
	}
	if f.Until > 0 {
		clauses = append(clauses, stamp+"<=?")
		args = append(args, f.Until)
	}
	return strings.Join(clauses, " AND "), args
}
func (s *Store) EventsPage(ctx context.Context, f ListFilter) (ListPage[Event], error) {
	page := ListPage[Event]{Items: []Event{}, Page: f.Page, Limit: f.Limit}
	if err := f.Validate(); err != nil {
		return page, err
	}
	where, args := listWhere(f, false)
	if err := s.Row(ctx, "SELECT COUNT(*) FROM auth_log WHERE "+where, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	last := max(1, int((page.Total+int64(f.Limit)-1)/int64(f.Limit)))
	page.Page = min(f.Page, last)
	args = append(args, f.Limit, (page.Page-1)*f.Limit)
	rows, err := s.DB.QueryContext(ctx, s.SQL("SELECT occurred_at,source,identity,result,reason FROM auth_log WHERE "+where+" ORDER BY occurred_at DESC,id DESC LIMIT ? OFFSET ?"), args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var v Event
		if err = rows.Scan(&v.Time, &v.Source, &v.Identity, &v.Result, &v.Reason); err != nil {
			return page, err
		}
		page.Items = append(page.Items, v)
	}
	return page, rows.Err()
}
func (s *Store) SessionsPage(ctx context.Context, f ListFilter) (ListPage[Session], error) {
	page := ListPage[Session]{Items: []Session{}, Page: f.Page, Limit: f.Limit}
	if err := f.Validate(); err != nil {
		return page, err
	}
	where, args := listWhere(f, true)
	if err := s.Row(ctx, "SELECT COUNT(*) FROM sessions s WHERE "+where, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	last := max(1, int((page.Total+int64(f.Limit)-1)/int64(f.Limit)))
	page.Page = min(f.Page, last)
	args = append(args, f.Limit, (page.Page-1)*f.Limit)
	rows, err := s.DB.QueryContext(ctx, s.SQL("SELECT s.nas,s.session_id,s.mac,s.username,s.status,s.updated_at,COALESCE(g.reason,''),s.revoke_attempts,s.generation,s.last_seen,s.event_at,s.started_at,s.session_seconds,s.revoke_next,s.revoke_last,s.revoke_cause,s.revoke_response,s.revoke_error,s.input_bytes,s.output_bytes,s.input_gigawords,s.output_gigawords,s.traffic_warning FROM sessions s LEFT JOIN access_grants g ON g.token=s.grant_token AND g.nas=s.nas WHERE "+where+" ORDER BY s.updated_at DESC,s.nas,s.session_id LIMIT ? OFFSET ?"), args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var v Session
		if err = rows.Scan(&v.NAS, &v.ID, &v.MAC, &v.Username, &v.Status, &v.Updated, &v.RevocationReason, &v.RevocationAttempts, &v.Generation, &v.LastSeen, &v.EventAt, &v.StartedAt, &v.SessionSeconds, &v.RevocationNext, &v.RevocationLast, &v.RevocationCause, &v.RevocationResponse, &v.RevocationError, &v.InputBytes, &v.OutputBytes, &v.InputGigawords, &v.OutputGigawords, &v.TrafficWarning); err != nil {
			return page, err
		}
		page.Items = append(page.Items, v)
	}
	return page, rows.Err()
}
