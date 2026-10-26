// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package guest

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/rkislov/border/internal/identity"
	"net"
	"strings"
	"time"
)

type Redirect struct {
	Version   int    `json:"v"`
	NAS       string `json:"n"`
	MAC       string `json:"m"`
	SessionID string `json:"s"`
	Expires   int64  `json:"e"`
	Nonce     string `json:"r"`
}

func randomID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func proofMAC(secret, payload string) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("Border guest redirect v1\x00" + payload))
	return m.Sum(nil)
}

// SignRedirect is for a trusted NAS/adapter. Never expose the shared secret to
// the guest browser; only the short-lived token belongs in the redirect URL.
func SignRedirect(r Redirect, secret string) (string, error) {
	mac, err := identity.MAC(r.MAC)
	if err != nil || net.ParseIP(r.NAS) == nil || len(secret) < 16 || len(r.SessionID) > 253 {
		return "", fmt.Errorf("invalid NAS redirect")
	}
	r.MAC = mac
	r.NAS = net.ParseIP(r.NAS).String()
	r.Version = 1
	if r.Expires == 0 {
		r.Expires = time.Now().Add(2 * time.Minute).Unix()
	}
	if r.Nonce == "" {
		r.Nonce = randomID()
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return payload + "." + base64.RawURLEncoding.EncodeToString(proofMAC(secret, payload)), nil
}
func (s *Service) redirect(ctx context.Context, token string) (Redirect, error) {
	bad := fmt.Errorf("нужен действующий переход с доверенного NAS")
	if len(token) > 2048 {
		return Redirect{}, bad
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return Redirect{}, bad
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Redirect{}, bad
	}
	var r Redirect
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&r); err != nil {
		return Redirect{}, bad
	}
	now := time.Now().Unix()
	if r.Version != 1 || r.Expires < now || r.Expires > now+120 || len(r.Nonce) != 64 || len(r.SessionID) > 253 {
		return Redirect{}, bad
	}
	mac, err := identity.MAC(r.MAC)
	if err != nil || mac != r.MAC || net.ParseIP(r.NAS) == nil || net.ParseIP(r.NAS).String() != r.NAS {
		return Redirect{}, bad
	}
	var secret string
	if err = s.Store.Row(ctx, "SELECT secret FROM nas WHERE address=? AND portal_enabled=1", r.NAS).Scan(&secret); err != nil {
		return Redirect{}, bad
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(signature, proofMAC(secret, parts[0])) {
		return Redirect{}, bad
	}
	return r, nil
}
