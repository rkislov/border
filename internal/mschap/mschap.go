// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
// Package mschap implements the RFC 2759 primitives for non-EAP MS-CHAPv2.
package mschap

import (
	"crypto/des"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/md4"
	"layeh.com/radius"
	"strings"
	"unicode/utf16"
)

type Request struct {
	ID                        byte
	Challenge, Peer, Response []byte
}

// Parse rejects duplicate, partial, mixed and unsupported Microsoft credentials.
func Parse(p *radius.Packet) (*Request, error) {
	var challenge, response []byte
	for _, a := range p.Attributes {
		if a.Type != 26 {
			continue
		}
		vendor, b, err := radius.VendorSpecific(a.Attribute)
		if err != nil {
			return nil, fmt.Errorf("malformed vendor attribute")
		}
		if vendor != 311 {
			continue
		}
		for len(b) > 0 {
			if len(b) < 2 || int(b[1]) < 2 || int(b[1]) > len(b) {
				return nil, fmt.Errorf("malformed Microsoft attribute")
			}
			n := int(b[1])
			v := b[2:n]
			switch b[0] {
			case 11:
				if challenge != nil || len(v) != 16 {
					return nil, fmt.Errorf("invalid MS-CHAP challenge")
				}
				challenge = v
			case 25:
				if response != nil || len(v) != 50 || v[1] != 0 {
					return nil, fmt.Errorf("invalid MS-CHAP2 response")
				}
				for _, x := range v[18:26] {
					if x != 0 {
						return nil, fmt.Errorf("nonzero reserved response")
					}
				}
				response = v
			case 1, 3, 4, 5, 6, 27:
				return nil, fmt.Errorf("unsupported MS-CHAP operation")
			}
			b = b[n:]
		}
	}
	if challenge == nil && response == nil {
		return nil, nil
	}
	if challenge == nil || response == nil || len(p.Attributes.Get(2)) > 0 || len(p.Attributes.Get(3)) > 0 || len(p.Attributes.Get(79)) > 0 {
		return nil, fmt.Errorf("incomplete or mixed MS-CHAPv2 credentials")
	}
	return &Request{response[0], challenge, response[2:18], response[26:50]}, nil
}

func PasswordHash(password string) []byte {
	units := utf16.Encode([]rune(password))
	b := make([]byte, len(units)*2)
	for i, v := range units {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	h := md4.New()
	h.Write(b)
	clear(b)
	return h.Sum(nil)
}
func challengeHash(challenge, peer []byte, user string) []byte {
	// RFC 2759 strips only the Windows domain prefix; username case is significant.
	if i := strings.LastIndex(user, "\\"); i >= 0 {
		user = user[i+1:]
	}
	h := sha1.New()
	h.Write(peer)
	h.Write(challenge)
	h.Write([]byte(user))
	return h.Sum(nil)[:8]
}
func NTResponse(hash, challenge, peer []byte, user string) []byte {
	if len(hash) != 16 || len(challenge) != 16 || len(peer) != 16 {
		return nil
	}
	padded := make([]byte, 21)
	copy(padded, hash)
	defer clear(padded)
	out := make([]byte, 24)
	c := challengeHash(challenge, peer, user)
	for i := 0; i < 3; i++ {
		b := padded[i*7 : i*7+7]
		key := []byte{b[0], b[0]<<7 | b[1]>>1, b[1]<<6 | b[2]>>2, b[2]<<5 | b[3]>>3, b[3]<<4 | b[4]>>4, b[4]<<3 | b[5]>>5, b[5]<<2 | b[6]>>6, b[6] << 1}
		// DES ignores parity bits.
		for j := range key {
			key[j] &= 0xfe
		}
		block, _ := des.NewCipher(key)
		block.Encrypt(out[i*8:], c)
		clear(key)
	}
	return out
}
func (r *Request) Verify(hash []byte, user string) (string, bool) {
	if len(hash) != 16 || len(r.Response) != 24 {
		return "", false
	}
	expected := NTResponse(hash, r.Challenge, r.Peer, user)
	if len(expected) != 24 || subtle.ConstantTimeCompare(expected, r.Response) != 1 {
		return "", false
	}
	h := md4.New()
	h.Write(hash)
	hh := h.Sum(nil)
	defer clear(hh)
	return r.AuthenticatorResponse(hh, user), true
}

func (r *Request) ChallengeHash(user string) []byte { return challengeHash(r.Challenge, r.Peer, user) }
func (r *Request) AuthenticatorResponse(hh []byte, user string) string {
	s := sha1.New()
	s.Write(hh)
	s.Write(r.Response)
	s.Write([]byte("Magic server to client signing constant"))
	digest := s.Sum(nil)
	s.Reset()
	s.Write(digest)
	s.Write(challengeHash(r.Challenge, r.Peer, user))
	s.Write([]byte("Pad to make it do more than one iteration"))
	return "S=" + strings.ToUpper(hex.EncodeToString(s.Sum(nil)))
}
func (r *Request) AddSuccess(p *radius.Packet, success string) error {
	value := append([]byte{26, 45, r.ID}, []byte(success)...)
	a, err := radius.NewVendorSpecific(311, value)
	if err == nil {
		p.Attributes.Add(26, a)
	}
	return err
}
