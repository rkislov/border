// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package mschap

import (
	"bytes"
	"crypto/sha1"
	"golang.org/x/crypto/md4"
)

// SessionKey derives RFC 3079 server receive || send keys (16 bytes each).
// The input is the authenticated password-hash-hash, never a raw password.
func SessionKey(hh, response []byte) []byte {
	if len(hh) != 16 || len(response) != 24 {
		return nil
	}
	h := sha1.New()
	h.Write(hh)
	h.Write(response)
	h.Write([]byte("This is the MPPE Master Key"))
	master := h.Sum(nil)
	defer clear(master)
	out := make([]byte, 0, 32)
	for _, magic := range []string{"On the client side, this is the send key; on the server side, it is the receive key.", "On the client side, this is the receive key; on the server side, it is the send key."} {
		h.Reset()
		h.Write(master[:16])
		h.Write(make([]byte, 40))
		h.Write([]byte(magic))
		h.Write(bytes.Repeat([]byte{0xf2}, 40))
		out = append(out, h.Sum(nil)[:16]...)
	}
	return out
}
func SessionKeyFromHash(hash, response []byte) []byte {
	if len(hash) != 16 {
		return nil
	}
	h := md4.New()
	h.Write(hash)
	hh := h.Sum(nil)
	defer clear(hh)
	return SessionKey(hh, response)
}
