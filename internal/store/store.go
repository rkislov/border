// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/rkislov/border/internal/telemetry"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	Metrics *telemetry.Registry
	DB      *sql.DB
	Driver  string
}
type NAS struct {
	InterimSeconds, StaleSeconds int
	Address, Name                string
	Dictionary, Mode, Credential string
	LocationID, AccessPolicyID   string
	CoAPort                      int
	PortalEnabled                bool
}
type VLAN struct {
	ID   int
	Name string
}
type Device struct {
	MAC           string
	VLAN          int
	Active, Voice bool
	Comment       string
}
type Event struct {
	Time                             int64
	Source, Identity, Result, Reason string
}
type Session struct {
	InputBytes, OutputBytes, TrafficWarning         string
	InputGigawords, OutputGigawords                 bool
	NAS, ID, MAC, Username, Status                  string
	Updated                                         int64
	GrantToken                                      string `json:"-"`
	RevocationReason                                string
	RevocationAttempts                              int
	Generation                                      string
	LastSeen, EventAt, StartedAt, SessionSeconds    int64
	RevocationNext, RevocationLast, RevocationCause int64
	RevocationResponse, RevocationError             string
}

func Open(driver, dsn string) (*Store, error) {
	if driver != "sqlite" && driver != "pgx" {
		return nil, fmt.Errorf("driver must be sqlite or pgx")
	}
	if driver == "sqlite" && dsn != ":memory:" && !strings.HasPrefix(dsn, "file:") {
		f, err := os.OpenFile(dsn, os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			return nil, err
		}
		if err = f.Chmod(0600); err != nil {
			f.Close()
			return nil, err
		}
		if err = f.Close(); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if driver == "sqlite" {
		if _, err = db.Exec("PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL;"); err != nil {
			db.Close()
			return nil, err
		}
	} else {
		db.SetMaxOpenConns(16)
		db.SetConnMaxLifetime(30 * time.Minute)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("database connection failed")
	}
	return &Store{DB: db, Driver: driver, Metrics: telemetry.New()}, nil
}
func (s *Store) Migrate(ctx context.Context) error {
	dialect := "sqlite3"
	if s.Driver == "pgx" {
		dialect = "postgres"
	}
	p, err := goose.NewProvider(goose.Dialect(dialect), s.DB, migrationFS())
	if err != nil {
		return err
	}
	_, err = p.Up(ctx)
	return err
}

func migrationFS() fs.FS {
	f, err := fs.Sub(migrations, "migrations")
	if err != nil {
		panic(err)
	}
	return f
}
func (s *Store) query(q string) string {
	if s.Driver != "pgx" {
		return q
	}
	var b strings.Builder
	n := 0
	for _, c := range q {
		if c == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}
func (s *Store) Exec(ctx context.Context, q string, args ...any) error {
	_, err := s.DB.ExecContext(ctx, s.query(q), args...)
	return err
}
func (s *Store) Row(ctx context.Context, q string, args ...any) *sql.Row {
	return s.DB.QueryRowContext(ctx, s.query(q), args...)
}
func (s *Store) Admin(ctx context.Context, name, password string, reset bool) error {
	if len(name) < 1 || len(name) > 100 || len(password) < 12 || len(password) > 72 {
		return fmt.Errorf("имя обязательно, пароль: 12–72 байта")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if reset {
		r, err := s.DB.ExecContext(ctx, s.query("UPDATE admins SET password_hash=? WHERE username=?"), string(hash), name)
		if err != nil {
			return err
		}
		n, err := r.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("administrator not found")
		}
		return nil
	}
	return s.Exec(ctx, "INSERT INTO admins(username,password_hash) VALUES (?,?)", name, string(hash))
}
func (s *Store) CheckAdmin(ctx context.Context, name, password string) bool {
	var hash string
	err := s.Row(ctx, "SELECT password_hash FROM admins WHERE username=?", name).Scan(&hash)
	if err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
func (s *Store) Secret(ctx context.Context, addr string) ([]byte, error) {
	var secret string
	err := s.Row(ctx, "SELECT secret FROM nas WHERE address=?", addr).Scan(&secret)
	return []byte(secret), err
}
func (s *Store) Device(ctx context.Context, mac string) (Device, error) {
	var d Device
	var vlan sql.NullInt64
	var active, voice int
	err := s.Row(ctx, "SELECT mac,vlan,active,voice,comment FROM mac_auth WHERE mac=?", mac).Scan(&d.MAC, &vlan, &active, &voice, &d.Comment)
	d.VLAN = int(vlan.Int64)
	d.Active = active == 1
	d.Voice = voice == 1
	return d, err
}
func (s *Store) Isolation(ctx context.Context) (int, error) {
	var v string
	err := s.Row(ctx, "SELECT value FROM settings WHERE name='isolation_vlan'").Scan(&v)
	if err != nil {
		return 0, err
	}
	var n int
	_, err = fmt.Sscan(v, &n)
	return n, err
}
func (s *Store) Audit(ctx context.Context, source, identity, result, reason string) error {
	return s.Exec(ctx, "INSERT INTO auth_log(id,occurred_at,source,identity,result,reason) VALUES (?,?,?,?,?,?)", uuid.NewString(), time.Now().Unix(), source, identity, result, reason)
}

// Accounting is a compatibility entry point for callers without timing fields.
// Network packets use ApplyAccounting with the complete event metadata.
func (s *Store) Accounting(ctx context.Context, source, id, mac, user, status string, classes ...string) error {
	kind := "interim"
	if status == "stopped" {
		kind = "stop"
	} else if status != "active" {
		return fmt.Errorf("invalid accounting status")
	}
	return s.ApplyAccounting(ctx, AccountingEvent{NAS: source, ID: id, MAC: mac, Username: user, Kind: kind, Classes: classes})
}

func (s *Store) NASList(ctx context.Context) ([]NAS, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT address,name,coa_port,portal_enabled,dictionary,access_mode,credential,COALESCE(location_id,''),COALESCE(access_policy_id,''),interim_seconds,stale_seconds FROM nas ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NAS{}
	for rows.Next() {
		var v NAS
		if err = rows.Scan(&v.Address, &v.Name, &v.CoAPort, &v.PortalEnabled, &v.Dictionary, &v.Mode, &v.Credential, &v.LocationID, &v.AccessPolicyID, &v.InterimSeconds, &v.StaleSeconds); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) VLANList(ctx context.Context) ([]VLAN, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT id,name FROM vlan_catalog ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VLAN{}
	for rows.Next() {
		var v VLAN
		if err = rows.Scan(&v.ID, &v.Name); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) DeviceList(ctx context.Context) ([]Device, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT mac,COALESCE(vlan,0),active,voice,comment FROM mac_auth ORDER BY mac")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Device{}
	for rows.Next() {
		var v Device
		var a, b int
		if err = rows.Scan(&v.MAC, &v.VLAN, &a, &b, &v.Comment); err != nil {
			return nil, err
		}
		v.Active = a == 1
		v.Voice = b == 1
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) Events(ctx context.Context) ([]Event, error) {
	page, err := s.EventsPage(ctx, ListFilter{Page: 1, Limit: 200})
	return page.Items, err
}
func (s *Store) Sessions(ctx context.Context) ([]Session, error) {
	page, err := s.SessionsPage(ctx, ListFilter{Page: 1, Limit: 200})
	return page.Items, err
}

// SQL binds portable placeholders for transactions owned by other packages.
func (s *Store) SQL(q string) string { return s.query(q) }
