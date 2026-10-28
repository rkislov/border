// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"context"
	"encoding/binary"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
)

func setAccountingInterval(ctx context.Context, s *store.Store, nas string, out *radius.Packet) error {
	var seconds uint32
	if err := s.Row(ctx, "SELECT interim_seconds FROM nas WHERE address=?", nas).Scan(&seconds); err != nil {
		return err
	}
	out.Attributes.Set(85, binary.BigEndian.AppendUint32(nil, seconds))
	return nil
}
