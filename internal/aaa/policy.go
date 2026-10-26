// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"context"
	"database/sql"
	"errors"

	"github.com/rkislov/border/internal/identity"
	"github.com/rkislov/border/internal/store"
	"time"
)

func NormalizeMAC(raw string) (string, error) { return identity.MAC(raw) }

type Decision struct {
	Accept  bool
	VLAN    int
	Voice   bool
	Reason  string
	Timeout uint32
}

// Decide never falls back to isolation on a database error or disabled device.
func Decide(ctx context.Context, s *store.Store, mac string) (Decision, error) {
	return DecideForNAS(ctx, s, "", mac)
}
func DecideForNAS(ctx context.Context, s *store.Store, nas, mac string) (Decision, error) {
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
	if nas != "" {
		vlan, expires, err := s.GuestAccess(ctx, nas, mac)
		if err == nil {
			remaining := expires - time.Now().Unix()
			if remaining > 0 {
				return Decision{Accept: true, VLAN: vlan, Reason: "guest SMS grant", Timeout: uint32(remaining)}, nil
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return Decision{}, err
		}
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
