// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/rkislov/border/internal/store"
)

func NormalizeMAC(raw string) (string, error) {
	if len(raw) == 12 {
		raw = raw[0:2] + ":" + raw[2:4] + ":" + raw[4:6] + ":" + raw[6:8] + ":" + raw[8:10] + ":" + raw[10:12]
	}
	m, err := net.ParseMAC(raw)
	if err != nil || len(m) != 6 {
		return "", fmt.Errorf("invalid MAC address")
	}
	return strings.ToLower(m.String()), nil
}

type Decision struct {
	Accept bool
	VLAN   int
	Voice  bool
	Reason string
}

// Decide never falls back to isolation on a database error or disabled device.
func Decide(ctx context.Context, s *store.Store, mac string) (Decision, error) {
	d, err := s.Device(ctx, mac)
	if err == nil {
		if !d.Active {
			return Decision{Reason: "device disabled"}, nil
		}
		return Decision{Accept: true, VLAN: d.VLAN, Voice: d.Voice, Reason: "registered MAC"}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Decision{}, err
	}
	vlan, err := s.Isolation(ctx)
	if err != nil {
		return Decision{}, err
	}
	if vlan > 0 {
		return Decision{Accept: true, VLAN: vlan, Reason: "unknown MAC: isolation"}, nil
	}
	return Decision{Reason: "unknown MAC"}, nil
}
