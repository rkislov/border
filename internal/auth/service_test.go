package auth

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/rkislov/border/internal/directory"
	"github.com/rkislov/border/internal/store"
)

type fakeMail struct {
	body string
	fail bool
}

func (m *fakeMail) Send(ctx context.Context, to, subject, body string) error {
	if m.fail {
		return errors.New("delivery failed")
	}
	if to != "user@example.test" {
		return errors.New("wrong recipient")
	}
	m.body = body
	return nil
}
func setup(t *testing.T) (*Service, *fakeMail) {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.DB.Close() })
	if err = db.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	m := &fakeMail{}
	s, err := New(db, make([]byte, 32), m, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Register(t.Context(), directory.Identity{Username: "user", Email: "user@example.test"}); err != nil {
		t.Fatal(err)
	}
	return s, m
}
func TestVault(t *testing.T) {
	v, err := NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	encrypted := v.Seal([]byte("secret"), "user:a")
	if strings.Contains(encrypted, "secret") {
		t.Fatal("plaintext")
	}
	p, err := v.Open(encrypted, "user:a")
	if err != nil || string(p) != "secret" {
		t.Fatal(err)
	}
	if _, err = v.Open(encrypted, "user:b"); err == nil {
		t.Fatal("AAD not bound")
	}
	if _, err = v.Open("invalid", "user:a"); err == nil {
		t.Fatal("invalid ciphertext")
	}
	if _, err = NewVault([]byte("short")); err == nil {
		t.Fatal("short key")
	}
}
func TestEmailCode(t *testing.T) {
	s, m := setup(t)
	if err := s.EmailCode(t.Context(), "user"); err != nil {
		t.Fatal(err)
	}
	code := strings.Split(strings.Split(m.body, "code: ")[1], "\n")[0]
	if len(code) != 8 {
		t.Fatal(code)
	}
	if err := s.EmailCode(t.Context(), "user"); err == nil {
		t.Fatal("resend rate limit")
	}
	ok, err := s.Verify(t.Context(), "USER", code)
	if err != nil || !ok {
		t.Fatal("valid code rejected", err)
	}
	ok, err = s.Verify(t.Context(), "user", code)
	if err != nil || ok {
		t.Fatal("email code replay")
	}
	var digest string
	if err = s.Store.Row(t.Context(), "SELECT digest FROM user_codes LIMIT 1").Scan(&digest); err == nil && strings.Contains(digest, code) {
		t.Fatal("plaintext code stored")
	}
}
func TestDeliveryFailureInvalidatesCode(t *testing.T) {
	s, m := setup(t)
	m.fail = true
	if err := s.EmailCode(t.Context(), "user"); err == nil {
		t.Fatal("missing mail error")
	}
	var n int
	if err := s.Store.Row(t.Context(), "SELECT COUNT(*) FROM user_codes").Scan(&n); err != nil || n != 0 {
		t.Fatal("undelivered code active")
	}
}
func TestTOTPRecoveryAndReplay(t *testing.T) {
	s, _ := setup(t)
	secret, uri, err := s.Enrollment(t.Context(), "user")
	if err != nil || !strings.HasPrefix(uri, "otpauth://") {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	codes, err := s.Confirm(t.Context(), "user", code)
	if err != nil || len(codes) != 10 {
		t.Fatal(err)
	}
	if ok, err := s.Verify(t.Context(), "user", code); err != nil || ok {
		t.Fatal("enrollment code replay")
	}
	if ok, err := s.Verify(t.Context(), "user", codes[0]); err != nil || !ok {
		t.Fatal("recovery rejected", err)
	}
	if ok, _ := s.Verify(t.Context(), "user", codes[0]); ok {
		t.Fatal("recovery replay")
	}
	newCodes, err := s.Recovery(t.Context(), "user")
	if err != nil || len(newCodes) != 10 {
		t.Fatal(err)
	}
	if ok, _ := s.Verify(t.Context(), "user", codes[1]); ok {
		t.Fatal("old recovery code accepted")
	}
	if ok, err := s.Verify(t.Context(), "user", newCodes[0]); err != nil || !ok {
		t.Fatal("new recovery rejected", err)
	}
	var encrypted string
	if err = s.Store.Row(t.Context(), "SELECT totp_secret FROM identities WHERE username='user'").Scan(&encrypted); err != nil || strings.Contains(encrypted, secret) {
		t.Fatal("plaintext secret")
	}
}
func TestAttemptLimit(t *testing.T) {
	s, m := setup(t)
	if err := s.EmailCode(t.Context(), "user"); err != nil {
		t.Fatal(err)
	}
	code := strings.Split(strings.Split(m.body, "code: ")[1], "\n")[0]
	for i := 0; i < 5; i++ {
		if ok, err := s.Verify(t.Context(), "user", "bad-code"); err != nil || ok {
			t.Fatal(err)
		}
	}
	if ok, _ := s.Verify(t.Context(), "user", code); ok {
		t.Fatal("locked account allowed")
	}
	if err := s.Register(t.Context(), directory.Identity{Username: "user", Email: "user@example.test"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Verify(t.Context(), "user", code); err != nil || !ok {
		t.Fatal("domain login did not unlock", err)
	}
}
func TestConcurrentCodeUse(t *testing.T) {
	s, m := setup(t)
	if err := s.EmailCode(t.Context(), "user"); err != nil {
		t.Fatal(err)
	}
	code := strings.Split(strings.Split(m.body, "code: ")[1], "\n")[0]
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.Verify(t.Context(), "user", code)
			if err != nil {
				t.Error(err)
			}
			results <- ok
		}()
	}
	wg.Wait()
	close(results)
	n := 0
	for ok := range results {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatal("single-use failure", n)
	}
}

func TestMFAOnlyDoesNotConsumeRecoveryOrEmail(t *testing.T) {
	s, m := setup(t)
	ctx := t.Context()
	if e := s.EmailCode(ctx, "user"); e != nil {
		t.Fatal(e)
	}
	code := strings.Split(strings.Split(m.body, "code: ")[1], "\n")[0]
	if ok, e := s.VerifyTOTP(ctx, "user", code); ok || e != nil {
		t.Fatal("email accepted as MFA", e)
	}
	if ok, e := s.Verify(ctx, "user", code); !ok || e != nil {
		t.Fatal("email consumed by MFA rejection", e)
	}
	secret, _, e := s.Enrollment(ctx, "user")
	if e != nil {
		t.Fatal(e)
	}
	otp, _ := totp.GenerateCode(secret, time.Now())
	if _, e = s.Confirm(ctx, "user", otp); e != nil {
		t.Fatal(e)
	}
	recovery, e := s.Recovery(ctx, "user")
	if e != nil {
		t.Fatal(e)
	}
	if ok, _ := s.VerifyTOTP(ctx, "user", recovery[0]); ok {
		t.Fatal("recovery accepted as MFA")
	}
	if ok, e := s.Verify(ctx, "user", recovery[0]); !ok || e != nil {
		t.Fatal("recovery consumed", e)
	}
}
