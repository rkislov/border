// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/store"
)

var ErrCredentials = errors.New("неверные данные подтверждения или код уже использован")
var ErrUnavailable = errors.New("защита входа недоступна: проверьте ключ шифрования")

type Service struct {
	Store *store.Store
	Vault *auth.Vault
}
type Status struct {
	Enabled, Available bool
	RecoveryRemaining  int
	PendingUntil       int64
}
type Enrollment struct {
	Secret, URL string
	ExpiresAt   int64
}
type factorState struct {
	secret, pending                       string
	until, pendingRevision, last, blocked int64
	failures                              int
}

// All mutations lock the account first, including on PostgreSQL. The revision
// binds enrollment and challenges to the exact password/permissions checked.
func (s *Service) locked(ctx context.Context, p store.AdminAccount) (*sql.Tx, factorState, error) {
	var f factorState
	tx, e := s.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, f, e
	}
	fail := func(e error) (*sql.Tx, factorState, error) { tx.Rollback(); return nil, f, e }
	r, e := tx.ExecContext(ctx, s.Store.SQL("UPDATE admins SET revision=revision WHERE username=? AND revision=? AND enabled=1"), p.Username, p.Revision)
	if e != nil {
		return fail(e)
	}
	n, e := r.RowsAffected()
	if e != nil {
		return fail(e)
	}
	if n != 1 {
		return fail(ErrCredentials)
	}
	e = tx.QueryRowContext(ctx, s.Store.SQL("SELECT mfa_secret,mfa_pending,mfa_pending_until,mfa_pending_revision,mfa_last_step,mfa_failures,mfa_blocked_until FROM admins WHERE username=?"), p.Username).Scan(&f.secret, &f.pending, &f.until, &f.pendingRevision, &f.last, &f.failures, &f.blocked)
	if e != nil {
		return fail(e)
	}
	return tx, f, nil
}
func (s *Service) Status(ctx context.Context, user string) (Status, error) {
	v := Status{Available: s.Vault != nil}
	e := s.Store.Row(ctx, "SELECT mfa_secret<>'',mfa_pending_until,(SELECT COUNT(*) FROM admin_recovery_codes WHERE username=? AND used_at=0) FROM admins WHERE username=?", user, user).Scan(&v.Enabled, &v.PendingUntil, &v.RecoveryRemaining)
	return v, e
}
func (s *Service) Begin(ctx context.Context, p store.AdminAccount) (Enrollment, error) {
	if s.Vault == nil {
		return Enrollment{}, ErrUnavailable
	}
	key, e := totp.Generate(totp.GenerateOpts{Issuer: "Border Admin", AccountName: p.Username, Period: 30, SecretSize: 20, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if e != nil {
		return Enrollment{}, e
	}
	tx, f, e := s.locked(ctx, p)
	if e != nil {
		return Enrollment{}, e
	}
	defer tx.Rollback()
	if f.secret != "" {
		return Enrollment{}, errors.New("TOTP уже включён")
	}
	until := time.Now().Add(10 * time.Minute).Unix()
	_, e = tx.ExecContext(ctx, s.Store.SQL("UPDATE admins SET mfa_pending=?,mfa_pending_until=?,mfa_pending_revision=? WHERE username=?"), s.Vault.Seal([]byte(key.Secret()), "admin-totp:"+p.Username), until, p.Revision, p.Username)
	if e == nil {
		e = audit(ctx, tx, s.Store, p.Username, "mfa_enrollment_started")
	}
	if e != nil {
		return Enrollment{}, e
	}
	return Enrollment{key.Secret(), key.URL(), until}, tx.Commit()
}
func step(code, secret string, now time.Time) (int64, bool) {
	current := now.Unix() / 30
	for _, n := range []int64{current, current - 1, current + 1} {
		ok, e := totp.ValidateCustom(code, secret, time.Unix(n*30, 0), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if e == nil && ok {
			return n, true
		}
	}
	return 0, false
}
func recoveryDigest(user, code string) string {
	h := sha256.Sum256([]byte("Border admin recovery v1\x00" + user + "\x00" + strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))))
	return hex.EncodeToString(h[:])
}
func (s *Service) failed(ctx context.Context, tx *sql.Tx, p store.AdminAccount, f factorState) error {
	now := time.Now().Unix()
	if f.blocked > now {
		return ErrCredentials
	}
	count := f.failures + 1
	if f.blocked != 0 {
		count = 1
	}
	until := int64(0)
	if count >= 5 {
		until = now + 300
	}
	_, e := tx.ExecContext(ctx, s.Store.SQL("UPDATE admins SET mfa_failures=?,mfa_blocked_until=? WHERE username=?"), count, until, p.Username)
	if e == nil {
		e = audit(ctx, tx, s.Store, p.Username, "mfa_verification_failed")
	}
	if e == nil {
		e = tx.Commit()
	}
	if e != nil {
		return e
	}
	return ErrCredentials
}
func (s *Service) Confirm(ctx context.Context, p store.AdminAccount, code string) ([]string, error) {
	if s.Vault == nil {
		return nil, ErrUnavailable
	}
	tx, f, e := s.locked(ctx, p)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if f.blocked > time.Now().Unix() {
		return nil, ErrCredentials
	}
	if f.secret != "" || f.pending == "" || f.until <= time.Now().Unix() || f.pendingRevision != p.Revision {
		return nil, ErrCredentials
	}
	plain, e := s.Vault.Open(f.pending, "admin-totp:"+p.Username)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer clear(plain)
	n, ok := step(strings.TrimSpace(code), string(plain), time.Now())
	if !ok {
		return nil, s.failed(ctx, tx, p, f)
	}
	_, e = tx.ExecContext(ctx, s.Store.SQL("UPDATE admins SET mfa_secret=mfa_pending,mfa_pending='',mfa_pending_until=0,mfa_last_step=?,mfa_failures=0,mfa_blocked_until=0,revision=revision+1 WHERE username=?"), n, p.Username)
	if e != nil {
		return nil, e
	}
	codes, e := s.replaceRecovery(ctx, tx, p.Username)
	if e == nil {
		e = audit(ctx, tx, s.Store, p.Username, "mfa_enabled")
	}
	if e != nil {
		return nil, e
	}
	return codes, tx.Commit()
}

// Verify atomically consumes a TOTP time step or a recovery code. Account-level
// failure counters survive process restarts and changes of IP/challenge.
func (s *Service) Verify(ctx context.Context, p store.AdminAccount, code string) error {
	if s.Vault == nil {
		return ErrUnavailable
	}
	tx, f, e := s.locked(ctx, p)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if f.secret == "" || f.blocked > time.Now().Unix() {
		return ErrCredentials
	}
	valid := false
	usedRecovery := false
	code = strings.TrimSpace(code)
	if len(code) == 6 {
		plain, e := s.Vault.Open(f.secret, "admin-totp:"+p.Username)
		if e != nil {
			return ErrUnavailable
		}
		n, ok := step(code, string(plain), time.Now())
		clear(plain)
		if ok && n > f.last {
			_, e = tx.ExecContext(ctx, s.Store.SQL("UPDATE admins SET mfa_last_step=? WHERE username=?"), n, p.Username)
			if e != nil {
				return e
			}
			valid = true
		}
	} else if len(code) >= 32 && len(code) <= 40 {
		r, e := tx.ExecContext(ctx, s.Store.SQL("UPDATE admin_recovery_codes SET used_at=? WHERE username=? AND digest=? AND used_at=0"), time.Now().Unix(), p.Username, recoveryDigest(p.Username, code))
		if e != nil {
			return e
		}
		n, e := r.RowsAffected()
		if e != nil {
			return e
		}
		valid = n == 1
		usedRecovery = valid
	}
	if !valid {
		return s.failed(ctx, tx, p, f)
	}
	if _, e = tx.ExecContext(ctx, s.Store.SQL("UPDATE admins SET mfa_failures=0,mfa_blocked_until=0 WHERE username=?"), p.Username); e != nil {
		return e
	}
	if usedRecovery {
		if e = audit(ctx, tx, s.Store, p.Username, "mfa_recovery_used"); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Service) replaceRecovery(ctx context.Context, tx *sql.Tx, user string) ([]string, error) {
	if _, e := tx.ExecContext(ctx, s.Store.SQL("DELETE FROM admin_recovery_codes WHERE username=?"), user); e != nil {
		return nil, e
	}
	codes := make([]string, 10)
	for i := range codes {
		raw := make([]byte, 16)
		if _, e := rand.Read(raw); e != nil {
			return nil, e
		}
		h := hex.EncodeToString(raw)
		codes[i] = fmt.Sprintf("%s-%s-%s-%s", h[:8], h[8:16], h[16:24], h[24:])
		if _, e := tx.ExecContext(ctx, s.Store.SQL("INSERT INTO admin_recovery_codes(username,digest,created_at) VALUES(?,?,?)"), user, recoveryDigest(user, codes[i]), time.Now().Unix()); e != nil {
			return nil, e
		}
	}
	return codes, nil
}

// Caller verifies password + factor first. Revision guards against concurrent
// password, role, MFA or recovery-code changes between verification and mutation.
func (s *Service) Regenerate(ctx context.Context, p store.AdminAccount) ([]string, error) {
	tx, f, e := s.locked(ctx, p)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if f.secret == "" {
		return nil, ErrCredentials
	}
	codes, e := s.replaceRecovery(ctx, tx, p.Username)
	if e == nil {
		_, e = tx.ExecContext(ctx, s.Store.SQL("UPDATE admins SET revision=revision+1 WHERE username=?"), p.Username)
	}
	if e == nil {
		e = audit(ctx, tx, s.Store, p.Username, "mfa_recovery_rotated")
	}
	if e != nil {
		return nil, e
	}
	return codes, tx.Commit()
}
func (s *Service) Disable(ctx context.Context, p store.AdminAccount) error {
	tx, _, e := s.locked(ctx, p)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = clearMFA(ctx, tx, s.Store, p.Username); e != nil {
		return e
	}
	if e = audit(ctx, tx, s.Store, p.Username, "mfa_disabled"); e != nil {
		return e
	}
	return tx.Commit()
}
func clearMFA(ctx context.Context, tx *sql.Tx, s *store.Store, user string) error {
	_, e := tx.ExecContext(ctx, s.SQL("UPDATE admins SET mfa_secret='',mfa_pending='',mfa_pending_until=0,mfa_pending_revision=0,mfa_last_step=-1,mfa_failures=0,mfa_blocked_until=0,revision=revision+1 WHERE username=?"), user)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, s.SQL("DELETE FROM admin_recovery_codes WHERE username=?"), user)
	return e
}

// Reset is an explicit host-administrator recovery command, never a web route.
func (s *Service) Reset(ctx context.Context, user string) error {
	tx, e := s.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.ExecContext(ctx, s.Store.SQL("UPDATE admins SET revision=revision WHERE username=?"), user)
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return errors.New("учётная запись не найдена")
	}
	if e = clearMFA(ctx, tx, s.Store, user); e != nil {
		return e
	}
	if e = audit(ctx, tx, s.Store, user, "mfa_reset_cli"); e != nil {
		return e
	}
	return tx.Commit()
}
func audit(ctx context.Context, tx *sql.Tx, s *store.Store, user, action string) error {
	_, e := tx.ExecContext(ctx, s.SQL("INSERT INTO auth_log(id,occurred_at,source,identity,result,reason) VALUES(?,?,?,?,?,?)"), uuid.NewString(), time.Now().Unix(), "admin_security", user, "updated", action)
	return e
}
