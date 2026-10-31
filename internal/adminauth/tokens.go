// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rkislov/border/internal/store"
)

type Token struct {
	ID, Name, CreatedBy                         string
	Scopes                                      []string
	CreatedAt, ExpiresAt, RevokedAt, LastUsedAt int64
	Active                                      bool
}

func HasScope(scopes, scope string) bool {
	for _, v := range strings.Split(scopes, ",") {
		if v == scope {
			return true
		}
	}
	return false
}
func normalizeScopes(scopes []string) (string, error) {
	if len(scopes) < 1 || len(scopes) > 2 {
		return "", errors.New("выберите права мониторинга")
	}
	m := map[string]bool{}
	for _, v := range scopes {
		if (v != "metrics:read" && v != "health:read") || m[v] {
			return "", errors.New("неверные права мониторинга")
		}
		m[v] = true
	}
	out := []string{}
	for _, v := range []string{"metrics:read", "health:read"} {
		if m[v] {
			out = append(out, v)
		}
	}
	return strings.Join(out, ","), nil
}
func (s *Service) CreateToken(ctx context.Context, p store.AdminAccount, name string, scopes []string, expires int64) (Token, string, error) {
	var v Token
	name = strings.TrimSpace(name)
	now := time.Now().Unix()
	if p.Role != "admin" || name == "" || len(name) > 100 || strings.ContainsAny(name, "\x00\r\n") || expires < now+3600 || expires > now+365*86400 {
		return v, "", errors.New("имя обязательно; срок токена — от часа до 365 дней")
	}
	scope, e := normalizeScopes(scopes)
	if e != nil {
		return v, "", e
	}
	raw := make([]byte, 32)
	if _, e = rand.Read(raw); e != nil {
		return v, "", e
	}
	id := uuid.NewString()
	token := "brd_mon_" + id + "." + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	tx, _, e := s.locked(ctx, p)
	if e != nil {
		return v, "", e
	}
	defer tx.Rollback()
	var count int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM monitoring_tokens WHERE revoked_at=0 AND expires_at>"+s.Store.SQL("?"), now).Scan(&count); e != nil {
		return v, "", e
	}
	if count >= 100 {
		return v, "", errors.New("не более 100 действующих токенов")
	}
	_, e = tx.ExecContext(ctx, s.Store.SQL("INSERT INTO monitoring_tokens(id,name,created_by,creator_revision,token_hash,scopes,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)"), id, name, p.Username, p.Revision, hex.EncodeToString(sum[:]), scope, now, expires)
	if e == nil {
		e = audit(ctx, tx, s.Store, p.Username, "monitoring_token_created "+id)
	}
	if e != nil {
		return v, "", e
	}
	v = Token{ID: id, Name: name, CreatedBy: p.Username, Scopes: strings.Split(scope, ","), CreatedAt: now, ExpiresAt: expires, Active: true}
	return v, token, tx.Commit()
}
func (s *Service) Tokens(ctx context.Context) ([]Token, error) {
	rows, e := s.Store.DB.QueryContext(ctx, "SELECT t.id,t.name,t.created_by,t.scopes,t.created_at,t.expires_at,t.revoked_at,t.last_used_at,(t.revoked_at=0 AND t.expires_at>"+s.Store.SQL("?")+" AND a.enabled=1 AND a.role='admin' AND a.revision=t.creator_revision) FROM monitoring_tokens t JOIN admins a ON a.username=t.created_by ORDER BY t.created_at DESC,t.id LIMIT 200", time.Now().Unix())
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Token{}
	for rows.Next() {
		var v Token
		var scopes string
		if e = rows.Scan(&v.ID, &v.Name, &v.CreatedBy, &scopes, &v.CreatedAt, &v.ExpiresAt, &v.RevokedAt, &v.LastUsedAt, &v.Active); e != nil {
			return nil, e
		}
		v.Scopes = strings.Split(scopes, ",")
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Service) RevokeToken(ctx context.Context, p store.AdminAccount, id string) error {
	if p.Role != "admin" {
		return ErrCredentials
	}
	if _, e := uuid.Parse(id); e != nil {
		return errors.New("неверный ID токена")
	}
	tx, _, e := s.locked(ctx, p)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.ExecContext(ctx, s.Store.SQL("UPDATE monitoring_tokens SET revoked_at=? WHERE id=? AND revoked_at=0"), time.Now().Unix(), id)
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return errors.New("токен не найден или уже отозван")
	}
	if e = audit(ctx, tx, s.Store, p.Username, "monitoring_token_revoked "+id); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Service) TokenPrincipal(ctx context.Context, value string) (store.AdminAccount, bool) {
	var p store.AdminAccount
	if !strings.HasPrefix(value, "brd_mon_") || len(value) != 88 {
		return p, false
	}
	parts := strings.Split(strings.TrimPrefix(value, "brd_mon_"), ".")
	if len(parts) != 2 {
		return p, false
	}
	if _, e := uuid.Parse(parts[0]); e != nil {
		return p, false
	}
	var digest string
	e := s.Store.Row(ctx, "SELECT t.token_hash,t.scopes,t.created_by FROM monitoring_tokens t JOIN admins a ON a.username=t.created_by WHERE t.id=? AND t.revoked_at=0 AND t.expires_at>? AND a.enabled=1 AND a.role='admin' AND a.revision=t.creator_revision", parts[0], time.Now().Unix()).Scan(&digest, &p.MonitoringScopes, &p.Username)
	sum := sha256.Sum256([]byte(value))
	if e != nil || subtle.ConstantTimeCompare([]byte(digest), []byte(hex.EncodeToString(sum[:]))) != 1 {
		return store.AdminAccount{}, false
	}
	if _, e = normalizeScopes(strings.Split(p.MonitoringScopes, ",")); e != nil {
		return store.AdminAccount{}, false
	}
	p.Role = "monitor"
	p.Enabled = true
	_ = s.Store.Exec(ctx, "UPDATE monitoring_tokens SET last_used_at=? WHERE id=? AND last_used_at<?", time.Now().Unix(), parts[0], time.Now().Unix()-60)
	return p, true
}
