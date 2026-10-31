// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package adminauth

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/store"
)

func fixture(t *testing.T) (*Service, store.AdminAccount) {
	t.Helper()
	db, e := store.Open("sqlite", filepath.Join(t.TempDir(), "root.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.DB.Close() })
	if e = db.Migrate(t.Context()); e != nil {
		t.Fatal(e)
	}
	if e = db.Admin(t.Context(), "admin", "test-password-123", false); e != nil {
		t.Fatal(e)
	}
	key := make([]byte, 32)
	rand.Read(key)
	v, e := auth.NewVault(key)
	if e != nil {
		t.Fatal(e)
	}
	p, e := db.AdminAccount(t.Context(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	return &Service{Store: db, Vault: v}, p
}
func enabled(t *testing.T, s *Service, p store.AdminAccount) (store.AdminAccount, Enrollment, []string) {
	t.Helper()
	v, e := s.Begin(t.Context(), p)
	if e != nil {
		t.Fatal(e)
	}
	code, e := totp.GenerateCode(v.Secret, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	codes, e := s.Confirm(t.Context(), p, code)
	if e != nil {
		t.Fatal(e)
	}
	p, e = s.Store.AdminAccount(t.Context(), p.Username)
	if e != nil {
		t.Fatal(e)
	}
	return p, v, codes
}
func TestTOTPReplayEncryptedStorageAndRecoveryRace(t *testing.T) {
	s, p := fixture(t)
	p, v, codes := enabled(t, s, p)
	ctx := t.Context()
	var cipher string
	s.Store.Row(ctx, "SELECT mfa_secret FROM admins WHERE username=?", p.Username).Scan(&cipher)
	if cipher == "" || strings.Contains(cipher, v.Secret) {
		t.Fatal("plaintext secret")
	}
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), v.Secret) || !p.MFAEnabled {
		t.Fatal("incorrect public status")
	}
	var last int64
	s.Store.Row(ctx, "SELECT mfa_last_step FROM admins WHERE username=?", p.Username).Scan(&last)
	code, _ := totp.GenerateCode(v.Secret, time.Unix(last*30, 0))
	if e := s.Verify(ctx, p, code); !errors.Is(e, ErrCredentials) {
		t.Fatal("enrollment code reused", e)
	}
	next, _ := totp.GenerateCode(v.Secret, time.Unix((last+1)*30, 0))
	if e := s.Verify(ctx, p, next); e != nil {
		t.Fatal(e)
	}
	if e := s.Verify(ctx, p, next); !errors.Is(e, ErrCredentials) {
		t.Fatal("TOTP replay", e)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- s.Verify(ctx, p, codes[0]) }()
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("recovery race", success)
	}
	status, e := s.Status(ctx, p.Username)
	if e != nil || status.RecoveryRemaining != 9 {
		t.Fatal(status, e)
	}
	var digest string
	s.Store.Row(ctx, "SELECT digest FROM admin_recovery_codes WHERE username=? LIMIT 1", p.Username).Scan(&digest)
	for _, c := range codes {
		if digest == c {
			t.Fatal("raw recovery code stored")
		}
	}
}
func TestMFAFailuresRevisionAndRecoveryRotation(t *testing.T) {
	s, p := fixture(t)
	ctx := t.Context()
	p, _, codes := enabled(t, s, p)
	for i := 0; i < 5; i++ {
		if e := s.Verify(ctx, p, "not-a-code"); e == nil {
			t.Fatal("bad code accepted")
		}
	}
	restarted := &Service{Store: s.Store, Vault: s.Vault}
	if e := restarted.Verify(ctx, p, codes[0]); e == nil {
		t.Fatal("restart bypassed block")
	}
	s.Store.Exec(ctx, "UPDATE admins SET mfa_blocked_until=? WHERE username=?", time.Now().Unix()-1, p.Username)
	if e := restarted.Verify(ctx, p, codes[0]); e != nil {
		t.Fatal(e)
	}
	fresh, e := s.Regenerate(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	if len(fresh) != 10 {
		t.Fatal(fresh)
	}
	if e = s.Verify(ctx, p, fresh[0]); e == nil {
		t.Fatal("stale revision accepted")
	}
	p, _ = s.Store.AdminAccount(ctx, p.Username)
	if e = s.Verify(ctx, p, codes[1]); e == nil {
		t.Fatal("old recovery retained")
	}
	if e = s.Verify(ctx, p, fresh[0]); e != nil {
		t.Fatal(e)
	}
	if e = s.Reset(ctx, p.Username); e != nil {
		t.Fatal(e)
	}
	v, e := s.Status(ctx, p.Username)
	if e != nil || v.Enabled || v.RecoveryRemaining != 0 || v.PendingUntil != 0 {
		t.Fatal(v, e)
	}
}
func TestEnrollmentExpiryRevisionAndUnavailableVault(t *testing.T) {
	s, p := fixture(t)
	ctx := t.Context()
	v, e := s.Begin(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	code, _ := totp.GenerateCode(v.Secret, time.Now())
	s.Store.Exec(ctx, "UPDATE admins SET mfa_pending_until=1 WHERE username=?", p.Username)
	if _, e = s.Confirm(ctx, p, code); e == nil {
		t.Fatal("expired enrollment accepted")
	}
	v, e = s.Begin(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	code, _ = totp.GenerateCode(v.Secret, time.Now())
	if e = s.Store.Admin(ctx, p.Username, "changed-password-123", true); e != nil {
		t.Fatal(e)
	}
	p, _ = s.Store.AdminAccount(ctx, p.Username)
	if _, e = s.Confirm(ctx, p, code); e == nil {
		t.Fatal("old enrollment survived password change")
	}
	s.Vault = nil
	if _, e = s.Begin(ctx, p); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
}
func TestMonitoringTokenScopesExpiryRevocationAndOwnerChanges(t *testing.T) {
	s, p := fixture(t)
	ctx := t.Context()
	expires := time.Now().Add(time.Hour * 24).Unix()
	if _, _, e := s.CreateToken(ctx, p, "bad", []string{"admin"}, expires); e == nil {
		t.Fatal("arbitrary scope")
	}
	if _, _, e := s.CreateToken(ctx, p, "bad", []string{"metrics:read"}, time.Now().Unix()); e == nil {
		t.Fatal("expired token")
	}
	info, token, e := s.CreateToken(ctx, p, "prometheus", []string{"metrics:read"}, expires)
	if e != nil {
		t.Fatal(e)
	}
	principal, ok := s.TokenPrincipal(ctx, token)
	if !ok || principal.Role != "monitor" || !HasScope(principal.MonitoringScopes, "metrics:read") || HasScope(principal.MonitoringScopes, "health:read") {
		t.Fatal(principal, ok)
	}
	if _, ok = s.TokenPrincipal(ctx, token[:len(token)-1]+"!"); ok {
		t.Fatal("invalid token accepted")
	}
	list, e := s.Tokens(ctx)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), token) || strings.Contains(string(raw), "token_hash") {
		t.Fatal("token exposed")
	}
	other, _ := fixture(t)
	if _, ok = other.TokenPrincipal(ctx, token); ok {
		t.Fatal("cross-tenant token")
	}
	if e = s.RevokeToken(ctx, p, info.ID); e != nil {
		t.Fatal(e)
	}
	if _, ok = s.TokenPrincipal(ctx, token); ok {
		t.Fatal("revoked token accepted")
	}
	info, token, e = s.CreateToken(ctx, p, "expiring", []string{"health:read"}, expires)
	if e != nil {
		t.Fatal(e)
	}
	s.Store.Exec(ctx, "UPDATE monitoring_tokens SET expires_at=1 WHERE id=?", info.ID)
	if _, ok = s.TokenPrincipal(ctx, token); ok {
		t.Fatal("expired token accepted")
	}
	_, token, e = s.CreateToken(ctx, p, "owner", []string{"health:read"}, expires)
	if e != nil {
		t.Fatal(e)
	}
	p, _, _ = enabled(t, s, p)
	if _, ok = s.TokenPrincipal(ctx, token); ok {
		t.Fatal("MFA change retained token")
	}
	_, token, e = s.CreateToken(ctx, p, "new owner", []string{"health:read"}, expires)
	if e != nil {
		t.Fatal(e)
	}
	s.Store.Exec(ctx, "UPDATE admins SET enabled=0 WHERE username=?", p.Username)
	if _, ok = s.TokenPrincipal(ctx, token); ok {
		t.Fatal("blocked owner retained token")
	}
}
