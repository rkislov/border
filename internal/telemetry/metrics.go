// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"sort"
	"sync"
	"time"
)

type Operation struct {
	Name                     string
	Count, Failures          uint64
	Results                  map[string]uint64
	TotalSeconds, MaxSeconds float64
	LastAt                   int64
	LastResult               string
}
type Snapshot struct {
	StartedAt  int64
	Operations []Operation
}
type Registry struct {
	mu         sync.Mutex
	started    int64
	operations map[string]*Operation
}

var names = []string{"radius_auth", "radius_accounting", "routing", "transport_drop", "identity_auth", "identity_status", "smtp", "sms", "push", "revocation", "account_sync", "retention", "session_action", "policy_schedule", "publication_results", "policy_notifications", "policy_notification_delivery"}

func New() *Registry {
	r := &Registry{started: time.Now().Unix(), operations: map[string]*Operation{}}
	for _, name := range names {
		r.operations[name] = &Operation{Name: name, Results: map[string]uint64{}}
	}
	return r
}
func (r *Registry) Observe(name, result string, failed bool, elapsed time.Duration) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v := r.operations[name]
	if v == nil {
		return
	}
	switch result {
	case "success", "error", "accept", "reject", "challenge", "response", "drop", "ack", "nak", "empty":
	default:
		return
	}
	seconds := max(0, elapsed.Seconds())
	v.Count++
	if failed {
		v.Failures++
	}
	v.Results[result]++
	v.TotalSeconds += seconds
	v.MaxSeconds = max(v.MaxSeconds, seconds)
	v.LastAt = time.Now().Unix()
	v.LastResult = result
}
func (r *Registry) Finish(name string, start time.Time, err error) {
	result := "success"
	if err != nil {
		result = "error"
	}
	r.Observe(name, result, err != nil, time.Since(start))
}
func (r *Registry) Snapshot() Snapshot {
	if r == nil {
		return Snapshot{Operations: []Operation{}}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := Snapshot{StartedAt: r.started, Operations: []Operation{}}
	for _, v := range r.operations {
		copy := *v
		copy.Results = map[string]uint64{}
		for k, n := range v.Results {
			copy.Results[k] = n
		}
		out.Operations = append(out.Operations, copy)
	}
	sort.Slice(out.Operations, func(i, j int) bool { return out.Operations[i].Name < out.Operations[j].Name })
	return out
}
