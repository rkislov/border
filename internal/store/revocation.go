// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"github.com/google/uuid"
	"strings"
	"time"
)

// IdentityEnabled checks locally authoritative account and domain switches.
// Directory account state is not inferred from an unavailable LDAP server.
func (s *Store) IdentityEnabled(ctx context.Context, user string) (bool, error) {
	var blocked int
	if e := s.Row(ctx, "SELECT blocked FROM identity_status WHERE username=?", strings.ToLower(user)).Scan(&blocked); e != nil && e != sql.ErrNoRows {
		return false, e
	}
	if blocked == 1 {
		return false, nil
	}
	source, login, qualified := strings.Cut(strings.ToLower(user), "/")
	if !qualified {
		return true, nil
	}
	var enabled int
	var err error
	if source == "local" {
		err = s.Row(ctx, "SELECT enabled FROM local_users WHERE username=?", login).Scan(&enabled)
	} else {
		err = s.Row(ctx, "SELECT enabled FROM domains WHERE id=?", source).Scan(&enabled)
	}
	if err == sql.ErrNoRows {
		return false, nil
	}
	return enabled == 1, err
}
func (s *Store) NewAccessGrant(ctx context.Context, nas, user, policy string, expires int64) (string, error) {
	user = strings.ToLower(user)
	token := "border:" + uuid.NewString()
	return token, s.Exec(ctx, "INSERT INTO access_grants(token,nas,username,policy_id,expires_at) VALUES(?,?,?,?,?)", token, nas, user, policy, expires)
}

// Latch revocation so re-enabling an account never restores an old grant.
func (s *Store) RevokeIdentity(ctx context.Context, user string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"UPDATE access_grants SET reason='user blocked',next_attempt=0 WHERE username=? AND reason=''", []any{user}},
		{"DELETE FROM user_codes WHERE username=?", []any{user}},
		{"UPDATE certificates SET revoked_at=? WHERE owner=? AND revoked_at=0", []any{time.Now().Unix(), user}},
	} {
		if _, err = tx.ExecContext(ctx, s.SQL(q.sql), q.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) RefreshRevocations(ctx context.Context) error {
	now := time.Now().Unix()
	return s.Exec(ctx, `UPDATE access_grants SET reason=CASE
 WHEN username IN (SELECT username FROM identity_status WHERE blocked=1) OR username IN (SELECT 'local/' || username FROM local_users WHERE enabled=0) THEN 'user blocked'
 WHEN EXISTS(SELECT 1 FROM domains d WHERE d.enabled=0 AND substr(access_grants.username,1,length(d.id)+1)=d.id || '/') THEN 'domain disabled'
 WHEN EXISTS(SELECT 1 FROM access_policies p WHERE p.id=access_grants.policy_id AND p.valid_until>0 AND p.valid_until<=?) THEN 'policy expired'
 WHEN expires_at<=? THEN 'session expired' ELSE 'policy unavailable' END,next_attempt=0 WHERE reason='' AND (
 expires_at<=? OR username IN (SELECT username FROM identity_status WHERE blocked=1) OR username IN (SELECT 'local/' || username FROM local_users WHERE enabled=0)
 OR EXISTS(SELECT 1 FROM domains d WHERE d.enabled=0 AND substr(access_grants.username,1,length(d.id)+1)=d.id || '/')
 OR (policy_id<>'' AND NOT EXISTS(SELECT 1 FROM access_policies p JOIN authentication_policies a ON a.id=p.authentication_id WHERE p.id=access_grants.policy_id AND p.enabled=1 AND a.enabled=1 AND (p.valid_until=0 OR p.valid_until>?) AND (p.valid_from=0 OR p.valid_from<=?))))`, now, now, now, now, now)
}
