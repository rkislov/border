// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"layeh.com/radius"
)

// RouterOS IPsec does not echo Class. Preserve the complete connection tuple,
// including binary NAS-Port-Id. Reject absent/duplicate discriminators.
func vpnAccountingKey(p *radius.Packet) string {
	h := sha256.New()
	for _, t := range []radius.Type{4, 6, 30, 31, 32, 61, 87} {
		var v []byte
		count := 0
		for _, a := range p.Attributes {
			if a.Type == t {
				v = a.Attribute
				count++
			}
		}
		if count != 1 || len(v) == 0 {
			return ""
		}
		if (t == 6 || t == 61) && len(v) != 4 {
			return ""
		}
		if t == 6 && binary.BigEndian.Uint32(v) != 2 {
			return ""
		}
		if t == 61 && binary.BigEndian.Uint32(v) != 5 {
			return ""
		}
		h.Write([]byte{byte(t), byte(len(v))})
		h.Write(v)
	}
	return hex.EncodeToString(h.Sum(nil))
}
