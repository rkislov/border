// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
// Package eaptunnel implements PEAPv0/MSCHAPv2 and TTLSv0/PAP phase two.
package eaptunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"github.com/rkislov/border/internal/eap"
	"github.com/rkislov/border/internal/eapmschap"
	"io"
)

var denied = fmt.Errorf("inner authentication rejected")

type PasswordVerifier func(context.Context, string, string) (eap.Authorization, error)

// TTLS supports only non-vendor User-Name and User-Password AVPs. Unknown
// mandatory AVPs, duplicate credentials and malformed padding fail closed.
func TTLS(ctx context.Context, c io.Reader, verify PasswordVerifier) (eap.Authorization, error) {
	var user, password []byte
	total := 0
	var pending []byte
	defer func() { clear(password); clear(pending) }()
	for {
		if len(pending) == 0 && user != nil && password != nil {
			break
		}
		for len(pending) < 8 {
			b := make([]byte, 8192)
			n, err := c.Read(b)
			if err != nil {
				return eap.Authorization{}, err
			}
			if n == 0 {
				return eap.Authorization{}, io.ErrNoProgress
			}
			pending = append(pending, b[:n]...)
			clear(b)
		}
		h := pending[:8]
		size := int(h[5])<<16 | int(h[6])<<8 | int(h[7])
		flags := h[4]
		if size < 8 || size > 4096 || total+size > 8192 || flags & ^byte(0xc0) != 0 {
			return eap.Authorization{}, denied
		}
		total += size
		padded := (size + 3) &^ 3
		for len(pending) < padded {
			b := make([]byte, padded-len(pending))
			if _, err := io.ReadFull(c, b); err != nil {
				return eap.Authorization{}, err
			}
			pending = append(pending, b...)
			clear(b)
		}
		body := bytes.Clone(pending[8:padded])
		pending = pending[padded:]

		for _, v := range body[size-8:] {
			if v != 0 {
				return eap.Authorization{}, denied
			}
		}
		body = body[:size-8]
		code := binary.BigEndian.Uint32(h)
		if flags&0x80 != 0 {
			if len(body) < 4 || flags&0x40 != 0 {
				return eap.Authorization{}, denied
			}
			continue
		}
		switch code {
		case 1:
			if user != nil || len(body) == 0 || len(body) > 253 {
				return eap.Authorization{}, denied
			}
			user = body
		case 2:
			if password != nil || len(body) == 0 || len(body) > 256 {
				return eap.Authorization{}, denied
			}
			password = body
		default:
			if flags&0x40 != 0 {
				return eap.Authorization{}, denied
			}
		}
	}
	defer clear(password)
	password = bytes.TrimRight(password, "\x00")
	if bytes.IndexByte(user, 0) >= 0 || bytes.IndexByte(password, 0) >= 0 {
		return eap.Authorization{}, denied
	}
	return verify(ctx, string(user), string(password))
}

// PEAPv0 uses header compression for inner EAP except the Result TLV.
// Session resumption and optional cryptobinding are not negotiated here.
func PEAP(ctx context.Context, c *tls.Conn, verify eapmschap.Verify) (eap.Authorization, error) {
	read := func() ([]byte, error) {
		b := make([]byte, 2048)
		n, e := c.Read(b)
		if e != nil {
			return nil, e
		}
		if n == len(b) {
			return nil, denied
		}
		return b[:n], nil
	}
	if _, err := c.Write([]byte{1, 0, 0, 5, 1}); err != nil {
		return eap.Authorization{}, err
	}
	identity, err := read()
	if err != nil || len(identity) < 2 || identity[0] != 1 || len(identity) > 254 {
		return eap.Authorization{}, denied
	}
	user := string(identity[1:])
	msg := append([]byte{2, 0, 0, 0}, identity...)
	binary.BigEndian.PutUint16(msg[2:], uint16(len(msg)))
	engine := eapmschap.New()
	defer engine.Close()
	reply := engine.Handle(ctx, "inner", user, nil, msg, verify)
	for i := 0; i < 3; i++ {
		if reply.Reject {
			return eap.Authorization{}, denied
		}
		if reply.Accept {
			defer clear(reply.Key)
			request := []byte{1, reply.Message[1] + 1, 0, 11, 33, 0x80, 3, 0, 2, 0, 1}
			if _, err = c.Write(request); err != nil {
				return eap.Authorization{}, err
			}
			response, err := read()
			request[0] = 2
			if err != nil || !bytes.Equal(request, response) {
				return eap.Authorization{}, denied
			}
			return eap.Authorization{Identity: reply.Identity, Groups: reply.Groups}, nil
		}
		if len(reply.Message) < 5 {
			return eap.Authorization{}, denied
		}
		if _, err = c.Write(reply.Message[4:]); err != nil {
			return eap.Authorization{}, err
		}
		response, err := read()
		if err != nil {
			return eap.Authorization{}, err
		}
		msg = append([]byte{2, reply.Message[1], 0, 0}, response...)
		binary.BigEndian.PutUint16(msg[2:], uint16(len(msg)))
		reply = engine.Handle(ctx, "inner", user, reply.State, msg, verify)
	}
	return eap.Authorization{}, denied
}
