// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"strings"
)

type AdminAccount struct {
	Username, Role, LocationID string
	Enabled                    bool
	Revision                   int64
}
type AdminChange struct {
	Username, Password, Role, LocationID string
	Enabled                              bool
}

func (s *Store) AdminAccount(ctx context.Context, user string) (AdminAccount, error) {
	var a AdminAccount
	err := s.Row(ctx, "SELECT username,role,location_id,enabled,revision FROM admins WHERE username=?", user).Scan(&a.Username, &a.Role, &a.LocationID, &a.Enabled, &a.Revision)
	return a, err
}
func (s *Store) AdminAccounts(ctx context.Context) ([]AdminAccount, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT username,role,location_id,enabled,revision FROM admins ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminAccount{}
	for rows.Next() {
		var a AdminAccount
		if err = rows.Scan(&a.Username, &a.Role, &a.LocationID, &a.Enabled, &a.Revision); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *Store) SaveAdminAccount(ctx context.Context, actor string, c AdminChange) error {
	if len(c.Username) < 1 || len(c.Username) > 100 || strings.TrimSpace(c.Username) != c.Username || strings.ContainsAny(c.Username, "\r\n\x00") {
		return fmt.Errorf("invalid username")
	}
	if c.Role != "admin" && c.Role != "operator" && c.Role != "viewer" {
		return fmt.Errorf("invalid role")
	}
	if (c.Role == "operator") != (c.LocationID != "") {
		return fmt.Errorf("only operator requires a location")
	}
	hash := ""
	if c.Password != "" {
		if len(c.Password) < 12 || len(c.Password) > 72 {
			return fmt.Errorf("password must be 12–72 bytes")
		}
		h, err := bcrypt.GenerateFromPassword([]byte(c.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		hash = string(h)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if s.Driver == "pgx" {
		if _, err = tx.ExecContext(ctx, "LOCK TABLE admins IN SHARE ROW EXCLUSIVE MODE"); err != nil {
			return err
		}
	}
	// Acquire the SQLite write lock before checking the last-admin invariant.
	if _, err = tx.ExecContext(ctx, "UPDATE admins SET revision=revision WHERE username="+s.SQL("?"), actor); err != nil {
		return err
	}
	var role string
	var enabled bool
	if err = tx.QueryRowContext(ctx, s.SQL("SELECT role,enabled FROM admins WHERE username=?"), actor).Scan(&role, &enabled); err != nil || role != "admin" || !enabled {
		return fmt.Errorf("administrator required")
	}
	if c.LocationID != "" {
		var n int
		if err = tx.QueryRowContext(ctx, s.SQL("SELECT 1 FROM locations WHERE id=?"), c.LocationID).Scan(&n); err != nil {
			return fmt.Errorf("location not found")
		}
	}
	var oldRole, oldHash string
	var oldEnabled bool
	err = tx.QueryRowContext(ctx, s.SQL("SELECT role,enabled,password_hash FROM admins WHERE username=?"), c.Username).Scan(&oldRole, &oldEnabled, &oldHash)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == sql.ErrNoRows && hash == "" {
		return fmt.Errorf("password required for new account")
	}
	if oldRole == "admin" && oldEnabled && (c.Role != "admin" || !c.Enabled) {
		var n int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM admins WHERE role='admin' AND enabled=1").Scan(&n); err != nil {
			return err
		}
		if n <= 1 {
			return fmt.Errorf("cannot remove the last enabled administrator")
		}
	}
	if hash == "" {
		hash = oldHash
	}
	_, err = tx.ExecContext(ctx, s.SQL("INSERT INTO admins(username,password_hash,role,location_id,enabled,revision) VALUES(?,?,?,?,?,1) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,role=excluded.role,location_id=excluded.location_id,enabled=excluded.enabled,revision=admins.revision+1"), c.Username, hash, c.Role, c.LocationID, integer(c.Enabled))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Capture the revision with the password hash so a concurrent credential change
// cannot authenticate an old password into a new revision's session.
func (s *Store) AuthenticateAdmin(ctx context.Context, user, password string) (AdminAccount, bool) {
	var a AdminAccount
	var hash string
	err := s.Row(ctx, "SELECT username,role,location_id,enabled,revision,password_hash FROM admins WHERE username=?", user).Scan(&a.Username, &a.Role, &a.LocationID, &a.Enabled, &a.Revision, &hash)
	if err != nil || !a.Enabled || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return AdminAccount{}, false
	}
	current, err := s.AdminAccount(ctx, user)
	return a, err == nil && current.Enabled && current.Revision == a.Revision
}
