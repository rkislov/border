// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package identitysource

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/directory"
	"github.com/rkislov/border/internal/sms"
	"github.com/rkislov/border/internal/store"
	"golang.org/x/crypto/bcrypt"
	"net/url"
	"regexp"
	"strings"
)

var IDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

type Domain struct {
	ID, Name                                           string
	Enabled                                            bool
	Endpoints                                          []string
	BaseDN, BindDN, BindPassword, UserAttribute, CAPEM string
	HasPassword                                        bool
}
type LocalUser struct {
	Username, Email, Password, Phone string
	Enabled                          bool
}
type Service struct {
	Store  *store.Store
	Vault  *auth.Vault
	Legacy directory.Authenticator
}

func (d Domain) Validate() error {
	if !IDPattern.MatchString(d.ID) || (d.ID == "local" || d.ID == "default") || d.Name == "" || len(d.Name) > 100 || len(d.Endpoints) == 0 || len(d.Endpoints) > 3 || d.BaseDN == "" || d.BindDN == "" || d.BindPassword == "" {
		return fmt.Errorf("domain ID, name, 1–3 LDAP endpoints and bind configuration required")
	}
	if d.UserAttribute != "uid" && d.UserAttribute != "sAMAccountName" && d.UserAttribute != "userPrincipalName" {
		return fmt.Errorf("unsupported LDAP login attribute")
	}
	for _, v := range d.Endpoints {
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "ldaps" && u.Scheme != "ldap") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("LDAP endpoint must use LDAPS or LDAP with StartTLS")
		}
	}
	if d.CAPEM != "" {
		p := x509.NewCertPool()
		if !p.AppendCertsFromPEM([]byte(d.CAPEM)) {
			return fmt.Errorf("invalid LDAP CA")
		}
	}
	return nil
}
func (s *Service) Domain(ctx context.Context, id string) (Domain, error) {
	var d Domain
	var raw string
	err := s.Store.Row(ctx, "SELECT id,name,enabled,config FROM domains WHERE id=?", id).Scan(&d.ID, &d.Name, &d.Enabled, &raw)
	if err != nil {
		return d, err
	}
	if s.Vault == nil {
		return d, fmt.Errorf("master key required")
	}
	plain, err := s.Vault.Open(raw, "domain:"+id)
	if err != nil {
		return d, fmt.Errorf("domain configuration unavailable")
	}
	defer clear(plain)
	err = json.Unmarshal(plain, &d)
	return d, err
}
func (s *Service) SaveDomain(ctx context.Context, d Domain) error {
	if s.Vault == nil {
		return fmt.Errorf("master key required")
	}
	if d.BindPassword == "" {
		old, err := s.Domain(ctx, d.ID)
		if err != nil {
			return fmt.Errorf("bind password required")
		}
		// Changing the credential destination requires explicitly entering a secret.
		if strings.Join(old.Endpoints, "\n") != strings.Join(d.Endpoints, "\n") || old.BindDN != d.BindDN {
			return fmt.Errorf("re-enter password when changing LDAP server or bind identity")
		}
		d.BindPassword = old.BindPassword
	}
	if err := d.Validate(); err != nil {
		return err
	}
	d.HasPassword = false
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	defer clear(raw)
	return s.Store.Exec(ctx, "INSERT INTO domains(id,name,config,enabled) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,config=excluded.config,enabled=excluded.enabled", d.ID, d.Name, s.Vault.Seal(raw, "domain:"+d.ID), boolInt(d.Enabled))
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func (s *Service) Domains(ctx context.Context) ([]Domain, error) {
	rows, err := s.Store.DB.QueryContext(ctx, "SELECT id FROM domains ORDER BY name")
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	out := []Domain{}
	for _, id := range ids {
		d, err := s.Domain(ctx, id)
		if err != nil {
			return nil, err
		}
		d.HasPassword = d.BindPassword != ""
		d.BindPassword = ""
		out = append(out, d)
	}
	return out, nil
}
func (s *Service) SaveLocal(ctx context.Context, u LocalUser) error {
	if u.Phone != "" {
		var err error
		u.Phone, err = sms.Phone(u.Phone)
		if err != nil {
			return err
		}
	}
	u.Username = strings.ToLower(strings.TrimSpace(u.Username))
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`).MatchString(u.Username) || len(u.Email) > 254 {
		return fmt.Errorf("invalid local username or email")
	}
	if u.Password == "" {
		r, err := s.Store.DB.ExecContext(ctx, s.Store.SQL("UPDATE local_users SET email=?,phone=?,enabled=? WHERE username=?"), u.Email, u.Phone, boolInt(u.Enabled), u.Username)
		if err != nil {
			return err
		}
		n, _ := r.RowsAffected()
		if n != 1 {
			return fmt.Errorf("password required for new user")
		}
		return nil
	}
	if len(u.Password) < 12 || len(u.Password) > 72 {
		return fmt.Errorf("password: 12–72 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.Store.Exec(ctx, "INSERT INTO local_users(username,email,password_hash,enabled,phone) VALUES(?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET email=excluded.email,password_hash=excluded.password_hash,enabled=excluded.enabled,phone=excluded.phone", u.Username, u.Email, string(hash), boolInt(u.Enabled), u.Phone)
}
func (s *Service) Locals(ctx context.Context) ([]LocalUser, error) {
	rows, err := s.Store.DB.QueryContext(ctx, "SELECT username,email,enabled,phone FROM local_users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LocalUser{}
	for rows.Next() {
		var u LocalUser
		if err = rows.Scan(&u.Username, &u.Email, &u.Enabled, &u.Phone); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
func (s *Service) Authenticate(ctx context.Context, user, password string) (directory.Identity, error) {
	fail := fmt.Errorf("authentication failed")
	if len(user) > 200 || len(password) > 1024 || password == "" {
		return directory.Identity{}, fail
	}
	source, login, qualified := strings.Cut(user, "/")
	if !qualified {
		if s.Legacy != nil {
			return s.Legacy.Authenticate(ctx, user, password)
		}
		return directory.Identity{}, fail
	}
	if source == "local" {
		login = strings.ToLower(login)
		var hash, email, phone string
		err := s.Store.Row(ctx, "SELECT password_hash,email,phone FROM local_users WHERE username=? AND enabled=1", login).Scan(&hash, &email, &phone)
		if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
			return directory.Identity{}, fail
		}
		return directory.Identity{Username: "local/" + login, Email: email, Phone: phone}, nil
	}
	d, err := s.Domain(ctx, source)
	if err != nil || !d.Enabled {
		return directory.Identity{}, fail
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if d.CAPEM != "" && !roots.AppendCertsFromPEM([]byte(d.CAPEM)) {
		return directory.Identity{}, fail
	}
	for _, endpoint := range d.Endpoints {
		u, _ := url.Parse(endpoint)
		l := directory.LDAP{URL: endpoint, BaseDN: d.BaseDN, BindDN: d.BindDN, BindPassword: d.BindPassword, UserAttribute: d.UserAttribute, TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: u.Hostname()}}
		i, err := l.Authenticate(ctx, login, password)
		if err == nil {
			i.Username = d.ID + "/" + i.Username
			return i, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return directory.Identity{}, fail
}
func (s *Service) Active(ctx context.Context, qualified string) bool {
	source, user, ok := strings.Cut(qualified, "/")
	if !ok {
		return false
	}
	var n int
	if source == "local" {
		return s.Store.Row(ctx, "SELECT enabled FROM local_users WHERE username=?", user).Scan(&n) == nil && n == 1
	}
	err := s.Store.Row(ctx, "SELECT enabled FROM domains WHERE id=?", source).Scan(&n)
	return err != sql.ErrNoRows && err == nil && n == 1
}
