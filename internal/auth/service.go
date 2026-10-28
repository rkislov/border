// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rkislov/border/internal/directory"
	"github.com/rkislov/border/internal/mail"
	"github.com/rkislov/border/internal/store"
)

type Service struct {
	Store       *store.Store
	Vault       *Vault
	Mail        mail.Sender
	NetworkVLAN int
	digestKey   []byte
}

func New(s *store.Store, key []byte, sender mail.Sender, vlan int) (*Service, error) {
	v, err := NewVault(key)
	if err != nil {
		return nil, err
	}
	if vlan < 0 || vlan > 4094 {
		return nil, fmt.Errorf("invalid portal VLAN")
	}
	digestKey := hmac.New(sha256.New, key)
	digestKey.Write([]byte("Border user codes v1"))
	return &Service{Store: s, Vault: v, Mail: sender, NetworkVLAN: vlan, digestKey: digestKey.Sum(nil)}, nil
}
func (s *Service) VLAN() int { return s.NetworkVLAN }
func (s *Service) Register(ctx context.Context, i directory.Identity) error {
	return s.Store.Exec(ctx, "INSERT INTO identities(username,email,phone) VALUES (?,?,?) ON CONFLICT(username) DO UPDATE SET email=excluded.email,phone=excluded.phone,failures=0", i.Username, i.Email, i.Phone)
}
func (s *Service) digest(user, code string) string {
	m := hmac.New(sha256.New, s.digestKey)
	m.Write([]byte(user + "\x00" + code))
	return hex.EncodeToString(m.Sum(nil))
}
func (s *Service) Notify(ctx context.Context, user, subject, body string) error {
	if s.Mail == nil {
		return fmt.Errorf("SMTP is not configured")
	}
	var email string
	if err := s.Store.Row(ctx, "SELECT email FROM identities WHERE username=?", user).Scan(&email); err != nil {
		return err
	}
	if sender, ok := s.Mail.(interface {
		Notify(context.Context, string, string, string, string) error
	}); ok {
		return sender.Notify(ctx, user, email, subject, body)
	}
	return s.Mail.Send(ctx, email, subject, body)
}
func (s *Service) EmailCode(ctx context.Context, user string) error {
	if s.Mail == nil {
		return fmt.Errorf("SMTP is not configured")
	}
	now := time.Now().Unix()
	r, err := s.Store.DB.ExecContext(ctx, s.Store.SQL("UPDATE identities SET last_email=? WHERE username=? AND last_email<=?"), now, user, now-60)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("повторная отправка доступна через 60 секунд")
	}
	value, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return err
	}
	code := fmt.Sprintf("%08d", value.Int64())
	digest := s.digest(user, code)
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, s.Store.SQL("DELETE FROM user_codes WHERE username=? AND kind='network'"), user); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, s.Store.SQL("INSERT INTO user_codes(digest,username,kind,expires_at) VALUES (?,?,'network',?)"), digest, user, now+300); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if err = s.deliverCode(ctx, user, "Border network access code", "Your one-time network access code: "+code+"\nValid for 5 minutes. Do not share this code."); err != nil {
		_ = s.Store.Exec(ctx, "DELETE FROM user_codes WHERE digest=?", digest)
		return fmt.Errorf("отправка не удалась; код аннулирован")
	}
	return s.Store.Audit(ctx, "portal", user, "sent", "network code issued")
}
func (s *Service) Enrollment(ctx context.Context, user string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Border", AccountName: user, Period: 30, SecretSize: 20, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		return "", "", err
	}
	if err = s.Store.Exec(ctx, "UPDATE identities SET pending_secret=? WHERE username=?", s.Vault.Seal([]byte(key.Secret()), "totp:"+user), user); err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}
func (s *Service) Confirm(ctx context.Context, user, code string) ([]string, error) {
	var pending string
	if err := s.Store.Row(ctx, "SELECT pending_secret FROM identities WHERE username=?", user).Scan(&pending); err != nil {
		return nil, err
	}
	plain, err := s.Vault.Open(pending, "totp:"+user)
	if err != nil {
		return nil, fmt.Errorf("начните настройку TOTP")
	}
	defer clear(plain)
	step, valid := totpStep(code, string(plain), time.Now())
	if !valid {
		return nil, fmt.Errorf("неверный TOTP код")
	}
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, s.Store.SQL("UPDATE identities SET totp_secret=pending_secret,pending_secret='',last_step=?,failures=0 WHERE username=? AND pending_secret=?"), step, user, pending)
	if err != nil {
		return nil, err
	}
	n, err := r.RowsAffected()
	if err != nil || n != 1 {
		return nil, fmt.Errorf("настройка изменилась, повторите")
	}
	codes := newRecovery()
	if _, err = tx.ExecContext(ctx, s.Store.SQL("DELETE FROM user_codes WHERE username=? AND kind='recovery'"), user); err != nil {
		return nil, err
	}
	for _, c := range codes {
		if _, err = tx.ExecContext(ctx, s.Store.SQL("INSERT INTO user_codes(digest,username,kind,expires_at) VALUES (?,?,'recovery',?)"), s.digest(user, c), user, time.Now().AddDate(1, 0, 0).Unix()); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}
func newRecovery() []string {
	codes := make([]string, 10)
	for i := range codes {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		codes[i] = hex.EncodeToString(b)
	}
	return codes
}
func (s *Service) Recovery(ctx context.Context, user string) ([]string, error) {
	var secret string
	if err := s.Store.Row(ctx, "SELECT totp_secret FROM identities WHERE username=?", user).Scan(&secret); err != nil {
		return nil, err
	}
	if secret == "" {
		return nil, fmt.Errorf("сначала включите TOTP")
	}
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, s.Store.SQL("DELETE FROM user_codes WHERE username=? AND kind='recovery'"), user); err != nil {
		return nil, err
	}
	codes := newRecovery()
	for _, c := range codes {
		if _, err = tx.ExecContext(ctx, s.Store.SQL("INSERT INTO user_codes(digest,username,kind,expires_at) VALUES (?,?,'recovery',?)"), s.digest(user, c), user, time.Now().AddDate(1, 0, 0).Unix()); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}
func totpStep(code, secret string, now time.Time) (int64, bool) {
	step := now.Unix() / 30
	for _, offset := range []int64{0, -1, 1} {
		value, err := totp.GenerateCodeCustom(secret, time.Unix((step+offset)*30, 0), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err == nil && subtle.ConstantTimeCompare([]byte(value), []byte(code)) == 1 {
			return step + offset, true
		}
	}
	return 0, false
}

// Verify accepts one email code, one recovery code or a non-replayed TOTP.
// Five failed attempts lock codes until a new successful domain login.
func (s *Service) Verify(ctx context.Context, user, code string) (bool, error) {
	return s.verify(ctx, user, code, false)
}

// VerifyTOTP requires the enrolled factor; email and recovery codes cannot satisfy MFA.
func (s *Service) VerifyTOTP(ctx context.Context, user, code string) (bool, error) {
	if len(code) != 6 {
		return false, nil
	}
	return s.verify(ctx, user, code, true)
}
func (s *Service) verify(ctx context.Context, user, code string, totpOnly bool) (bool, error) {
	user = strings.ToLower(user)
	if enabled, e := s.Store.IdentityEnabled(ctx, user); e != nil || !enabled {
		return false, e
	}
	if len(user) > 200 || len(code) > 100 || code == "" {
		return false, nil
	}
	r, err := s.Store.DB.ExecContext(ctx, s.Store.SQL("UPDATE identities SET failures=failures+1 WHERE username=? AND failures<5"), user)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	if err != nil || n != 1 {
		return false, err
	}
	if !totpOnly {
		r, err = s.Store.DB.ExecContext(ctx, s.Store.SQL("DELETE FROM user_codes WHERE username=? AND digest=? AND expires_at>?"), user, s.digest(user, code), time.Now().Unix())
		if err != nil {
			return false, err
		}
		n, err = r.RowsAffected()
		if err != nil {
			return false, err
		}
		if n == 1 {
			if err = s.Store.Exec(ctx, "UPDATE identities SET failures=0 WHERE username=?", user); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	var encrypted string
	var last int64
	if err = s.Store.Row(ctx, "SELECT totp_secret,last_step FROM identities WHERE username=?", user).Scan(&encrypted, &last); err != nil {
		return false, err
	}
	if encrypted == "" {
		return false, nil
	}
	secret, err := s.Vault.Open(encrypted, "totp:"+user)
	if err != nil {
		return false, err
	}
	defer clear(secret)
	step, valid := totpStep(code, string(secret), time.Now())
	if !valid || step <= last {
		return false, nil
	}
	r, err = s.Store.DB.ExecContext(ctx, s.Store.SQL("UPDATE identities SET last_step=?,failures=0 WHERE username=? AND last_step<? AND totp_secret=?"), step, user, step, encrypted)
	if err != nil {
		return false, err
	}
	n, err = r.RowsAffected()
	return n == 1, err
}

func (s *Service) deliverCode(ctx context.Context, user, subject, body string) error {
	var email string
	if err := s.Store.Row(ctx, "SELECT email FROM identities WHERE username=?", user).Scan(&email); err != nil {
		return err
	}
	if sender, ok := s.Mail.(interface {
		SendForIdentity(context.Context, string, string, string, string) error
	}); ok {
		return sender.SendForIdentity(ctx, user, email, subject, body)
	}
	return s.Mail.Send(ctx, email, subject, body)
}
