// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package routeros

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/store"
	"golang.org/x/crypto/ssh"
)

// Config is stored encrypted in the tenant database, separately for each NAS.
// HostKey is an independently verified OpenSSH SHA256 fingerprint.
type Config struct {
	Enabled                              bool
	Address, Username, Password, HostKey string
}
type Service struct {
	Store *store.Store
	Vault *auth.Vault
}

func (s *Service) Config(ctx context.Context, nas string) (v Config, err error) {
	var raw string
	err = s.Store.Row(ctx, "SELECT config FROM nas_routeros WHERE nas=?", nas).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return v, nil
	}
	if err != nil {
		return
	}
	if s.Vault == nil {
		return v, fmt.Errorf("BORDER_MASTER_KEY required")
	}
	b, e := s.Vault.Open(raw, "routeros:"+nas)
	if e != nil {
		return v, fmt.Errorf("RouterOS configuration unavailable")
	}
	defer clear(b)
	err = json.Unmarshal(b, &v)
	return
}
func (s *Service) Save(ctx context.Context, nas string, v Config) error {
	if s.Vault == nil {
		return fmt.Errorf("BORDER_MASTER_KEY required")
	}
	var dictionary string
	if err := s.Store.Row(ctx, "SELECT dictionary FROM nas WHERE address=?", nas).Scan(&dictionary); err != nil || dictionary != "mikrotik" {
		return fmt.Errorf("registered MikroTik NAS required")
	}
	old, err := s.Config(ctx, nas)
	if err != nil {
		return err
	}
	if v.Password == "" && v.Address == old.Address && v.Username == old.Username && v.HostKey == old.HostKey {
		v.Password = old.Password
	}
	if v.Enabled {
		host, port, e := net.SplitHostPort(v.Address)
		n, _ := strconv.Atoi(port)
		if e != nil || host == "" || n < 1 || n > 65535 {
			return fmt.Errorf("RouterOS address must be host:port")
		}
		if len(v.Username) < 1 || len(v.Username) > 128 || strings.ContainsAny(v.Username, "\r\n\x00") || len(v.Password) < 16 || len(v.Password) > 1024 {
			return fmt.Errorf("service username and password of at least 16 characters required")
		}
		if !strings.HasPrefix(v.HostKey, "SHA256:") || len(v.HostKey) != 50 {
			return fmt.Errorf("verified SHA256 SSH host key fingerprint required")
		}
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	defer clear(raw)
	return s.Store.Exec(ctx, "INSERT INTO nas_routeros(nas,config) VALUES(?,?) ON CONFLICT(nas) DO UPDATE SET config=excluded.config", nas, s.Vault.Seal(raw, "routeros:"+nas))
}

type active struct {
	ID      string `json:".id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Via     string `json:"via"`
	When    string `json:"when"`
	Radius  bool   `json:"radius"`
}
type snapshot struct {
	Offset int64    `json:"offset"`
	Users  []active `json:"users"`
}

const listCommand = `:put [:serialize to=json value={"offset"=[/system clock get gmt-offset];"users"=[/user active print as-value]}]`

// match requires a unique RADIUS SSH login within the accounting timestamp's
// two-second precision window. Ambiguous entries are never removed.
func match(v store.Session, p snapshot) (active, error) {
	var found []active
	if v.StartedAt <= 0 || v.Username == "" || p.Offset < -86400 || p.Offset > 86400 {
		return active{}, fmt.Errorf("session start time unavailable")
	}
	for _, u := range p.Users {
		if !u.Radius || u.Via != "ssh" || u.Name != v.Username {
			continue
		}
		t, e := time.Parse("2006-01-02 15:04:05", u.When)
		if e != nil {
			continue
		}
		delta := t.Unix() - p.Offset - v.StartedAt
		if delta >= -2 && delta <= 2 {
			found = append(found, u)
		}
	}
	if len(found) != 1 {
		return active{}, fmt.Errorf("RouterOS SSH session correlation is absent or ambiguous")
	}
	u := found[0]
	if u.ID == "" || u.Address == "" {
		return active{}, fmt.Errorf("RouterOS session identity incomplete")
	}
	return u, nil
}
func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "\r", `\r`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}
func removeCommand(u active) string {
	// Evaluate all identity fields again on the router, in the same script as
	// removal; never remove all sessions belonging to a username.
	return `:local matches [/user active find where .id=` + quote(u.ID) + ` and name=` + quote(u.Name) + ` and address=` + quote(u.Address) + ` and via="ssh" and radius=yes and when=` + quote(u.When) + `]; :if ([:len $matches] != 1) do={:error "session changed"}; /user active remove $matches; :put "border-removed"`
}

type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 65536 {
		return 0, fmt.Errorf("RouterOS output too large")
	}
	return b.Buffer.Write(p)
}
func run(c *ssh.Client, command string) ([]byte, error) {
	session, e := c.NewSession()
	if e != nil {
		return nil, fmt.Errorf("RouterOS SSH channel unavailable")
	}
	defer session.Close()
	var out, stderr boundedBuffer
	session.Stdout = &out
	session.Stderr = &stderr
	if e = session.Run(command); e != nil {
		return nil, fmt.Errorf("RouterOS management command failed")
	}
	return out.Bytes(), nil
}
func read(c *ssh.Client) (snapshot, error) {
	b, e := run(c, listCommand)
	if e != nil {
		return snapshot{}, e
	}
	var v snapshot
	if e = json.Unmarshal(bytes.TrimSpace(b), &v); e != nil {
		return v, fmt.Errorf("RouterOS active-session response invalid (RouterOS 7 with JSON serialization required)")
	}
	return v, nil
}

// Disconnect is used only after an authenticated RADIUS Unsupported Extension.
func (s *Service) Disconnect(ctx context.Context, v store.Session) (bool, error) {
	cfg, e := s.Config(ctx, v.NAS)
	if e != nil || !cfg.Enabled {
		return false, e
	}
	var dictionary, mode string
	if e = s.Store.Row(ctx, "SELECT dictionary,access_mode FROM nas WHERE address=?", v.NAS).Scan(&dictionary, &mode); e != nil {
		return false, e
	}
	if dictionary != "mikrotik" || mode != "ssh" {
		return false, fmt.Errorf("RouterOS adapter requires an SSH MikroTik NAS")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, e := (&net.Dialer{}).DialContext(ctx, "tcp", cfg.Address)
	if e != nil {
		return false, fmt.Errorf("RouterOS management connection failed")
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	cc, ch, r, e := ssh.NewClientConn(conn, cfg.Address, &ssh.ClientConfig{User: cfg.Username, Auth: []ssh.AuthMethod{ssh.Password(cfg.Password)}, HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
		if ssh.FingerprintSHA256(k) != cfg.HostKey {
			return fmt.Errorf("SSH host key mismatch")
		}
		return nil
	}})
	if e != nil {
		return false, fmt.Errorf("RouterOS SSH authentication or pinned host key verification failed")
	}
	c := ssh.NewClient(cc, ch, r)
	defer c.Close()
	p, e := read(c)
	if e != nil {
		return false, e
	}
	u, e := match(v, p)
	if e != nil {
		return false, e
	}
	// Refuse overlapping accounting identities, including already closed ones:
	// a quick reconnect cannot silently replace the requested session.
	var count int
	e = s.Store.Row(ctx, "SELECT COUNT(*) FROM sessions WHERE nas=? AND username=? AND started_at BETWEEN ? AND ?", v.NAS, v.Username, v.StartedAt-4, v.StartedAt+4).Scan(&count)
	if e != nil {
		return false, e
	}
	if count != 1 {
		return false, fmt.Errorf("overlapping accounting sessions; refusing RouterOS disconnect")
	}
	var generation, token, status string
	if e = s.Store.Row(ctx, "SELECT generation,grant_token,status FROM sessions WHERE nas=? AND session_id=?", v.NAS, v.ID).Scan(&generation, &token, &status); e != nil {
		return false, e
	}
	if generation != v.Generation || token != v.GrantToken || (status != "active" && status != "stale") {
		return false, fmt.Errorf("accounting session changed before RouterOS disconnect")
	}
	b, e := run(c, removeCommand(u))
	if e != nil {
		return false, e
	}
	if strings.TrimSpace(string(b)) != "border-removed" {
		return false, fmt.Errorf("RouterOS did not confirm removal")
	}
	p, e = read(c)
	if e != nil {
		return false, e
	}
	for _, other := range p.Users {
		if other == u {
			return false, fmt.Errorf("RouterOS session remains active")
		}
	}
	return true, nil
}
