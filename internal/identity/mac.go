// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package identity

import (
	"fmt"
	"net"
	"strings"
)

func MAC(raw string) (string, error) {
	if len(raw) == 12 {
		raw = raw[:2] + ":" + raw[2:4] + ":" + raw[4:6] + ":" + raw[6:8] + ":" + raw[8:10] + ":" + raw[10:12]
	}
	m, err := net.ParseMAC(raw)
	if err != nil || len(m) != 6 {
		return "", fmt.Errorf("invalid MAC address")
	}
	return strings.ToLower(m.String()), nil
}
