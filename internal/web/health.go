// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"context"
	"fmt"
	"github.com/rkislov/border/internal/telemetry"
	"net/http"
	"sort"
	"time"
)

type healthSnapshot struct {
	Telemetry                                         telemetry.Snapshot
	DatabaseOK                                        bool
	DatabaseSeconds                                   float64
	ActiveSessions, StaleSessions, PendingRevocations int64
}

func (a *app) health(ctx context.Context) healthSnapshot {
	h := healthSnapshot{Telemetry: a.s.Metrics.Snapshot()}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	start := time.Now()
	err := a.s.Row(ctx, `SELECT (SELECT COUNT(*) FROM sessions WHERE status='active'), (SELECT COUNT(*) FROM sessions WHERE status='stale'), (SELECT COUNT(*) FROM sessions s JOIN access_grants g ON g.token=s.grant_token AND g.nas=s.nas WHERE s.status IN ('active','stale') AND g.reason<>'')`).Scan(&h.ActiveSessions, &h.StaleSessions, &h.PendingRevocations)
	h.DatabaseSeconds = time.Since(start).Seconds()
	h.DatabaseOK = err == nil
	return h
}
func (a *app) healthRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		h := a.health(r.Context())
		if !h.DatabaseOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(503)
		}
		reply(w, h)
	})
	m.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		h := a.health(r.Context())
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		gauge := func(name string, value any) {
			fmt.Fprintf(w, "# TYPE border_%s gauge\nborder_%s %v\n", name, name, value)
		}
		gauge("runtime_started_seconds", h.Telemetry.StartedAt)
		up := 0
		if h.DatabaseOK {
			up = 1
		}
		gauge("database_up", up)
		gauge("database_query_seconds", h.DatabaseSeconds)
		if h.DatabaseOK {
			gauge("active_sessions", h.ActiveSessions)
			gauge("stale_sessions", h.StaleSessions)
			gauge("pending_revocations", h.PendingRevocations)
		}
		for _, family := range []struct{ name, kind string }{{"operations_total", "counter"}, {"failures_total", "counter"}, {"operation_duration_seconds_sum", "counter"}, {"operation_duration_seconds_count", "counter"}, {"operation_duration_seconds_max", "gauge"}, {"last_operation_seconds", "gauge"}, {"results_total", "counter"}} {
			fmt.Fprintf(w, "# TYPE border_%s %s\n", family.name, family.kind)
			for _, o := range h.Telemetry.Operations {
				var value any
				switch family.name {
				case "operations_total", "operation_duration_seconds_count":
					value = o.Count
				case "failures_total":
					value = o.Failures
				case "operation_duration_seconds_sum":
					value = o.TotalSeconds
				case "operation_duration_seconds_max":
					value = o.MaxSeconds
				case "last_operation_seconds":
					value = o.LastAt
				case "results_total":
					keys := make([]string, 0, len(o.Results))
					for k := range o.Results {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					for _, k := range keys {
						fmt.Fprintf(w, "border_results_total{operation=%q,result=%q} %d\n", o.Name, k, o.Results[k])
					}
					continue
				}
				fmt.Fprintf(w, "border_%s{operation=%q} %v\n", family.name, o.Name, value)
			}
		}
	})
}
