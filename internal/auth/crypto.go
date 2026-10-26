// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

type Vault struct{ aead cipher.AEAD }

func NewVault(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("BORDER_MASTER_KEY must decode to 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: a}, nil
}
func (v *Vault) Seal(plain []byte, context string) string {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(v.aead.Seal(nonce, nonce, plain, []byte(context)))
}
func (v *Vault) Open(encrypted, context string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil || len(b) < v.aead.NonceSize() {
		return nil, fmt.Errorf("invalid encrypted value")
	}
	n := v.aead.NonceSize()
	return v.aead.Open(nil, b[:n], b[n:], []byte(context))
}
