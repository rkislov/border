// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"strings"
)

// BindingTrace stops at the first matching binding, exactly like live selection.
type BindingTrace struct {
	ID, PolicyID, Reason string
	Priority             int
}

func bindingMismatch(b PolicyBinding, r PolicyRequest) string {
	switch {
	case !b.Enabled:
		return "disabled"
	case b.Protocol != r.Protocol:
		return "protocol"
	case b.ServiceType != 0 && b.ServiceType != r.ServiceType:
		return "service_type"
	case b.SSID != "" && b.SSID != r.SSID:
		return "ssid"
	case b.NASPortType != nil && (r.NASPortType == nil || *b.NASPortType != *r.NASPortType):
		return "nas_port_type"
	}
	if b.IdentitySource != "" {
		source, _, qualified := strings.Cut(strings.ToLower(r.Username), "/")
		if !qualified || source != b.IdentitySource {
			return "identity_source"
		}
	}
	return "selected"
}

// ExplainPolicy runs the same read-only selection path as RADIUS. It does not
// authenticate an identity, evaluate access rules, or create an access grant.
func (s *Store) ExplainPolicy(ctx context.Context, nas string, request PolicyRequest) (*BoundPolicy, bool, []BindingTrace, error) {
	trace := []BindingTrace{}
	p, configured, err := s.selectPolicy(ctx, nas, request, &trace)
	return p, configured, trace, err
}
