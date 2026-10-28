// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import "strconv"

type TrafficCounter struct {
	Bytes     uint64
	Gigawords bool
}

// Counters are cumulative snapshots, never increments. Missing values preserve
// the last observation; regressions cannot undo traffic or prevent a Stop.
func mergeTraffic(previous string, wide bool, incoming *TrafficCounter) (string, bool, bool, error) {
	if incoming == nil {
		return previous, wide, false, nil
	}
	if previous != "" {
		old, err := strconv.ParseUint(previous, 10, 64)
		if err != nil {
			return "", false, false, err
		}
		if incoming.Bytes < old {
			return previous, wide, true, nil
		}
	}
	return strconv.FormatUint(incoming.Bytes, 10), incoming.Gigawords, false, nil
}
