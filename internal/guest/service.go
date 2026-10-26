// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package guest

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/sms"
	"github.com/rkislov/border/internal/store"
)

type Service struct {
	PublicURL   string
	Store       *store.Store
	Vault       *auth.Vault
	key         []byte
	SMS         sms.SMSProvider
	Reconnect   func(context.Context, string, string, string, int) error
	mu          sync.Mutex
	provider    *sms.HTTPProvider
	fingerprint [32]byte
}
type Challenge struct {
	ID          string
	Expires     int64
	MaskedPhone string
}
type Grant struct {
	Expires           int64
	VLAN              int
	ReconnectRequired bool
}

func New(s *store.Store, key []byte) (*Service, error) {
	vault, err := auth.NewVault(key)
	if err != nil {
		return nil, err
	}
	derive := hmac.New(sha256.New, key)
	derive.Write([]byte("Border guest OTP v1"))
	return &Service{Store: s, Vault: vault, key: derive.Sum(nil)}, nil
}
func (s *Service) digest(context, value string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(context + "\x00" + value))
	return hex.EncodeToString(m.Sum(nil))
}
func (s *Service) Config(ctx context.Context) (sms.Config, error) {
	var raw string
	err := s.Store.Row(ctx, "SELECT value FROM settings WHERE name='sms_config'").Scan(&raw)
	if err == sql.ErrNoRows {
		return sms.Config{}, nil
	}
	if err != nil {
		return sms.Config{}, err
	}
	plain, err := s.Vault.Open(raw, "sms:config")
	if err != nil {
		return sms.Config{}, fmt.Errorf("SMS configuration unavailable")
	}
	defer clear(plain)
	var c sms.Config
	err = json.Unmarshal(plain, &c)
	return c, err
}
func (s *Service) SetConfig(ctx context.Context, c sms.Config) error {
	old, err := s.Config(ctx)
	if err != nil {
		return err
	}
	if c.Provider != "" {
		if c.Token == "" && c.Provider == old.Provider && c.URL == old.URL && c.AccountSID == old.AccountSID {
			c.Token = old.Token
		}
		provider, err := sms.New(c)
		if err != nil {
			return err
		}
		provider.Close()
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.Store.Exec(ctx, "INSERT INTO settings(name,value) VALUES ('sms_config',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", s.Vault.Seal(raw, "sms:config"))
}
func (s *Service) sender(ctx context.Context) (sms.SMSProvider, error) {
	if s.SMS != nil {
		return s.SMS, nil
	}
	c, err := s.Config(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	fingerprint := sha256.Sum256(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.provider != nil && s.fingerprint == fingerprint {
		return s.provider, nil
	}
	provider, err := sms.New(c)
	if err != nil {
		return nil, fmt.Errorf("SMS provider is not configured")
	}
	if s.provider != nil {
		s.provider.Close()
	}
	s.provider = provider
	s.fingerprint = fingerprint
	return provider, nil
}
func (s *Service) Ready(ctx context.Context) bool { _, err := s.sender(ctx); return err == nil }
func (s *Service) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.provider != nil {
		s.provider.Close()
	}
}
func (s *Service) StartCleanup(ctx context.Context) func() {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c, stop := context.WithTimeout(ctx, 2*time.Second)
				_ = s.Cleanup(c)
				stop()
			}
		}
	}()
	return func() { cancel(); wg.Wait() }
}
func (s *Service) Cleanup(ctx context.Context) error {
	now := time.Now().Unix()
	if err := s.Store.Exec(ctx, "DELETE FROM guest_sessions WHERE expires_at<=?", now); err != nil {
		return err
	}
	return s.Store.Exec(ctx, "DELETE FROM guest_challenges WHERE created_at<?", now-3600)
}
func (s *Service) Request(ctx context.Context, token, rawPhone string) (Challenge, error) {
	r, err := s.redirect(ctx, token)
	if err != nil {
		return Challenge{}, err
	}
	phone, err := sms.Phone(rawPhone)
	if err != nil {
		return Challenge{}, err
	}
	sender, err := s.sender(ctx)
	if err != nil {
		return Challenge{}, err
	}
	now := time.Now().Unix()
	phoneHash := s.digest("phone", phone)
	id := randomID()
	number, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return Challenge{}, err
	}
	code := fmt.Sprintf("%06d", number.Int64())
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return Challenge{}, err
	}
	defer tx.Rollback()
	q := "SELECT enabled FROM guest_policy WHERE id=1"
	if s.Store.Driver == "pgx" {
		q += " FOR UPDATE"
	}
	var enabled int
	if err = tx.QueryRowContext(ctx, q).Scan(&enabled); err != nil || enabled != 1 {
		return Challenge{}, fmt.Errorf("гостевой доступ выключен")
	}
	var allowed int
	if err = tx.QueryRowContext(ctx, s.Store.SQL("SELECT portal_enabled FROM nas WHERE address=?"), r.NAS).Scan(&allowed); err != nil || allowed != 1 {
		return Challenge{}, fmt.Errorf("гостевой доступ на NAS выключен")
	}
	var registered int
	err = tx.QueryRowContext(ctx, s.Store.SQL("SELECT active FROM mac_auth WHERE mac=?"), r.MAC).Scan(&registered)
	if err != nil && err != sql.ErrNoRows {
		return Challenge{}, err
	}
	if err == nil {
		return Challenge{}, fmt.Errorf("доступ устройства управляется администратором")
	}
	var total, limit int
	if err = tx.QueryRowContext(ctx, "SELECT max_per_hour FROM guest_policy WHERE id=1").Scan(&limit); err != nil {
		return Challenge{}, err
	}
	if err = tx.QueryRowContext(ctx, s.Store.SQL("SELECT COUNT(*) FROM guest_challenges WHERE created_at>?"), now-3600).Scan(&total); err != nil {
		return Challenge{}, err
	}
	if total >= limit {
		return Challenge{}, fmt.Errorf("часовой лимит SMS исчерпан")
	}
	if err = tx.QueryRowContext(ctx, s.Store.SQL("SELECT COUNT(*) FROM guest_challenges WHERE phone_hash=? AND created_at>?"), phoneHash, now-900).Scan(&total); err != nil {
		return Challenge{}, err
	}
	if total >= 5 {
		return Challenge{}, fmt.Errorf("лимит номера: 5 SMS за 15 минут")
	}
	if err = tx.QueryRowContext(ctx, s.Store.SQL("SELECT COUNT(*) FROM guest_challenges WHERE nas=? AND mac=? AND created_at>?"), r.NAS, r.MAC, now-900).Scan(&total); err != nil {
		return Challenge{}, err
	}
	if total >= 5 {
		return Challenge{}, fmt.Errorf("лимит устройства: 5 SMS за 15 минут")
	}
	if err = tx.QueryRowContext(ctx, s.Store.SQL("SELECT COUNT(*) FROM guest_challenges WHERE nas=? AND mac=? AND created_at>?"), r.NAS, r.MAC, now-60).Scan(&total); err != nil {
		return Challenge{}, err
	}
	if total > 0 {
		return Challenge{}, fmt.Errorf("повторная отправка через 60 секунд")
	}
	if _, err = tx.ExecContext(ctx, s.Store.SQL("UPDATE guest_challenges SET code_digest='',expires_at=? WHERE nas=? AND mac=? AND verified_at=0"), now, r.NAS, r.MAC); err != nil {
		return Challenge{}, err
	}
	if _, err = tx.ExecContext(ctx, s.Store.SQL("INSERT INTO guest_challenges(id,nas,mac,session_id,phone_hash,phone_cipher,code_digest,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?)"), id, r.NAS, r.MAC, r.SessionID, phoneHash, s.Vault.Seal([]byte(phone), "guest:"+id), s.digest(id, code), now, now+300); err != nil {
		return Challenge{}, err
	}
	if err = tx.Commit(); err != nil {
		return Challenge{}, err
	}
	if err = sender.Send(ctx, phone, "Border Wi-Fi code: "+code+". Valid for 5 minutes. Do not share."); err != nil {
		_ = s.Store.Exec(ctx, "UPDATE guest_challenges SET code_digest='',attempts=5,expires_at=? WHERE id=?", now, id)
		_ = s.Store.Audit(ctx, "guest", sms.Mask(phone)+"/"+r.MAC, "failed", "SMS delivery failed")
		return Challenge{}, fmt.Errorf("SMS не отправлено; код аннулирован")
	}
	if err = s.Store.Audit(ctx, "guest", sms.Mask(phone)+"/"+r.MAC, "sent", "SMS guest code issued"); err != nil {
		return Challenge{}, fmt.Errorf("SMS отправлено, но аудит недоступен")
	}
	return Challenge{ID: id, Expires: now + 300, MaskedPhone: sms.Mask(phone)}, nil
}
func (s *Service) Confirm(ctx context.Context, id, code string) (Grant, error) {
	if len(id) != 64 || len(code) != 6 {
		return Grant{}, fmt.Errorf("неверный код")
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return Grant{}, fmt.Errorf("неверный код")
		}
	}
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return Grant{}, err
	}
	defer tx.Rollback()
	q := "SELECT c.nas,c.mac,c.session_id,c.phone_cipher,c.code_digest,c.expires_at,c.attempts,c.verified_at,p.vlan,p.session_seconds FROM guest_challenges c JOIN nas n ON n.address=c.nas JOIN guest_policy p ON p.id=1 WHERE c.id=? AND p.enabled=1 AND n.portal_enabled=1"
	if s.Store.Driver == "pgx" {
		q += " FOR UPDATE OF c"
	}
	var nas, mac, sessionID, phoneCipher, digest string
	var expires, verified int64
	var attempts, ttl int
	var vlan sql.NullInt64
	if err = tx.QueryRowContext(ctx, s.Store.SQL(q), id).Scan(&nas, &mac, &sessionID, &phoneCipher, &digest, &expires, &attempts, &verified, &vlan, &ttl); err != nil {
		return Grant{}, fmt.Errorf("запрос не найден или доступ выключен")
	}
	now := time.Now().Unix()
	if expires <= now || attempts >= 5 || verified != 0 || !vlan.Valid {
		return Grant{}, fmt.Errorf("код истёк, использован или заблокирован")
	}
	if _, err = tx.ExecContext(ctx, s.Store.SQL("UPDATE guest_challenges SET attempts=attempts+1 WHERE id=?"), id); err != nil {
		return Grant{}, err
	}
	if subtle.ConstantTimeCompare([]byte(digest), []byte(s.digest(id, code))) != 1 {
		if err = tx.Commit(); err != nil {
			return Grant{}, err
		}
		return Grant{}, fmt.Errorf("неверный код")
	}
	var active int
	err = tx.QueryRowContext(ctx, s.Store.SQL("SELECT active FROM mac_auth WHERE mac=?"), mac).Scan(&active)
	if err != nil && err != sql.ErrNoRows {
		return Grant{}, err
	}
	if err == nil {
		return Grant{}, fmt.Errorf("доступ устройства управляется администратором")
	}
	plain, err := s.Vault.Open(phoneCipher, "guest:"+id)
	if err != nil {
		return Grant{}, fmt.Errorf("данные запроса недоступны")
	}
	masked := sms.Mask(string(plain))
	clear(plain)
	grant := Grant{Expires: now + int64(ttl), VLAN: int(vlan.Int64), ReconnectRequired: true}
	if _, err = tx.ExecContext(ctx, s.Store.SQL("INSERT INTO guest_sessions(nas,mac,masked_phone,vlan,expires_at) VALUES (?,?,?,?,?) ON CONFLICT(nas,mac) DO UPDATE SET masked_phone=excluded.masked_phone,vlan=excluded.vlan,expires_at=excluded.expires_at"), nas, mac, masked, grant.VLAN, grant.Expires); err != nil {
		return Grant{}, err
	}
	if _, err = tx.ExecContext(ctx, s.Store.SQL("UPDATE guest_challenges SET code_digest='',verified_at=? WHERE id=?"), now, id); err != nil {
		return Grant{}, err
	}
	if err = tx.Commit(); err != nil {
		return Grant{}, err
	}
	if err = s.Store.Audit(ctx, "guest", masked+"/"+mac, "accepted", "SMS verified for NAS "+nas); err != nil {
		return Grant{}, fmt.Errorf("доступ выдан, но аудит недоступен")
	}
	if s.Reconnect != nil && sessionID != "" {
		grant.ReconnectRequired = s.Reconnect(ctx, nas, sessionID, mac, grant.VLAN) != nil
	}
	return grant, nil
}
