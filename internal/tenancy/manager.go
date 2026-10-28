// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package tenancy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"fmt"
	"github.com/rkislov/border/internal/aaa"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/eap"
	"github.com/rkislov/border/internal/guest"
	"github.com/rkislov/border/internal/identitysource"
	"github.com/rkislov/border/internal/notification"
	"github.com/rkislov/border/internal/pki"
	"github.com/rkislov/border/internal/selfservice"
	"github.com/rkislov/border/internal/store"
	"github.com/rkislov/border/internal/web"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Runtime struct {
	Store         *store.Store
	Admin, Portal http.Handler
	Options       aaa.Options
	engine        *eap.Engine
	guest         *guest.Service
	stop          func()
}
type Manager struct {
	Root                              *store.Store
	RootOptions                       aaa.Options
	Driver, DSN, Directory, PublicURL string
	Key                               []byte
	Pair                              tls.Certificate
	RequireMTLS                       bool
	mu                                sync.RWMutex
	runtimes                          map[string]*Runtime
}

func (m *Manager) Init(ctx context.Context) error {
	m.runtimes = make(map[string]*Runtime)
	list, err := m.List(ctx)
	if err != nil {
		return err
	}
	for _, t := range list {
		r, err := m.open(ctx, t.ID)
		if err != nil {
			m.Close()
			return fmt.Errorf("load tenant %s: %w", t.ID, err)
		}
		m.runtimes[t.ID] = r
	}
	return nil
}
func (m *Manager) List(ctx context.Context) ([]web.TenantInfo, error) {
	rows, err := m.Root.DB.QueryContext(ctx, "SELECT id,name FROM tenant_instances ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []web.TenantInfo{}
	for rows.Next() {
		var t web.TenantInfo
		if err = rows.Scan(&t.ID, &t.Name); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
func (m *Manager) Create(ctx context.Context, t web.TenantSpec) error {
	if !identitysource.IDPattern.MatchString(t.ID) || t.ID == "default" || len(t.Name) > 100 || t.Name == "" || len(t.Password) < 12 || len(t.Password) > 72 || t.Admin == "" {
		return fmt.Errorf("tenant ID, name, admin and password (12–72 bytes) required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.runtimes[t.ID]; ok {
		return fmt.Errorf("tenant exists")
	}
	if len(m.runtimes) >= 64 {
		return fmt.Errorf("tenant limit reached")
	}
	if m.Driver == "sqlite" {
		if _, e := os.Stat(filepath.Join(m.Directory, t.ID+".db")); e == nil {
			return fmt.Errorf("tenant database already exists; choose another ID")
		} else if !os.IsNotExist(e) {
			return e
		}
	}
	r, err := m.open(ctx, t.ID)
	if err != nil {
		return err
	}
	fail := func(err error) error { r.close(); return err }
	if err = r.Store.Admin(ctx, t.Admin, t.Password, false); err != nil {
		return fail(fmt.Errorf("tenant admin bootstrap failed"))
	}
	if err = m.copyRegistry(ctx, r.Store); err != nil {
		return fail(err)
	}
	if err = m.Root.Exec(ctx, "INSERT INTO tenant_instances(id,name,created_at) VALUES(?,?,?)", t.ID, t.Name, time.Now().Unix()); err != nil {
		return fail(err)
	}
	m.runtimes[t.ID] = r
	return nil
}
func (m *Manager) open(ctx context.Context, id string) (*Runtime, error) {
	if !identitysource.IDPattern.MatchString(id) || len(m.Key) != 32 {
		return nil, fmt.Errorf("valid tenant ID and master key required")
	}
	driver, dsn := m.Driver, ""
	if driver == "sqlite" {
		if err := os.MkdirAll(m.Directory, 0700); err != nil {
			return nil, err
		}
		dsn = filepath.Join(m.Directory, id+".db")
	} else {
		sum := sha256.Sum256([]byte(id))
		schema := "border_t_" + hex.EncodeToString(sum[:12])
		if _, err := m.Root.DB.ExecContext(ctx, "CREATE SCHEMA IF NOT EXISTS "+schema); err != nil {
			return nil, err
		}
		u, err := url.Parse(m.DSN)
		if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
			return nil, fmt.Errorf("multi-tenant PostgreSQL requires URL DSN")
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		dsn = u.String()
	}
	s, err := store.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	r := &Runtime{Store: s}
	fail := func(err error) (*Runtime, error) { r.close(); return nil, err }
	if err = s.Migrate(ctx); err != nil {
		return fail(err)
	}
	h := hmac.New(sha256.New, m.Key)
	h.Write([]byte("Border tenant master v1\x00" + id))
	key := h.Sum(nil)
	defer clear(key)
	codes, err := auth.New(s, key, nil, 0)
	if err != nil {
		return fail(err)
	}
	identities := &identitysource.Service{Store: s, Vault: codes.Vault}
	guests, err := guest.New(s, key)
	if err != nil {
		return fail(err)
	}
	r.guest = guests
	notifications := &notification.Service{Store: s, Vault: codes.Vault}
	codes.Mail = notifications
	guests.SenderForNAS = notifications.GuestSender
	portalURL := strings.TrimSuffix(m.PublicURL, "/") + "/portal/" + id
	guests.PublicURL = portalURL
	manager := &pki.Manager{Store: s, Vault: codes.Vault}
	engine, err := eap.New(eap.Config{
		TLSConfig: func(ctx context.Context) (*tls.Config, error) {
			enabled, _, err := s.EAPPolicy(ctx)
			if err != nil || !enabled {
				return nil, fmt.Errorf("EAP disabled")
			}
			return manager.EAPTLSConfig(ctx, m.Pair)
		},
		Authorize: func(ctx context.Context, state tls.ConnectionState) (eap.Authorization, error) {
			enabled, vlan, err := s.EAPPolicy(ctx)
			if err != nil || !enabled {
				return eap.Authorization{}, fmt.Errorf("EAP disabled")
			}
			user, err := manager.AuthorizeClient(ctx, state)
			return eap.Authorization{Identity: user, VLAN: vlan}, err
		},
	})
	if err != nil {
		return fail(err)
	}
	r.engine = engine
	r.Options = aaa.Options{Network: codes, EAP: engine, Directory: identities, Identities: identities, TOTP: codes}
	r.Admin = web.HandlerWithOptions(s, manager, nil, m.RequireMTLS, guests)
	r.Portal = selfservice.New(identities, codes, manager, portalURL, guests).Handler()
	// Manager.Close owns the cleanup lifecycle, independent of create request cancellation.
	stopGuests := guests.StartCleanup(context.Background())
	stopRevocations := aaa.StartRevocations(context.Background(), s, identities.SyncAccountStatus)
	r.stop = func() { stopRevocations(); stopGuests() }
	return r, nil
}
func (r *Runtime) close() {
	if r.stop != nil {
		r.stop()
	}
	if r.guest != nil {
		r.guest.Close()
	}
	if r.engine != nil {
		r.engine.Close()
	}
	if r.Store != nil {
		r.Store.DB.Close()
	}
}
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.runtimes {
		r.close()
	}
	clear(m.Key)
}
func (m *Manager) Resolve(ctx context.Context, host string) (*store.Store, aaa.Options, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var found *store.Store
	var options aaa.Options
	all := []*Runtime{{Store: m.Root, Options: m.RootOptions}}
	for _, r := range m.runtimes {
		all = append(all, r)
	}
	for _, r := range all {
		_, err := r.Store.Secret(ctx, host)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, aaa.Options{}, fmt.Errorf("tenant NAS lookup unavailable")
		}
		if found != nil {
			return nil, aaa.Options{}, fmt.Errorf("NAS IP is ambiguous across tenants")
		}
		found = r.Store
		options = r.Options
	}
	if found == nil {
		return nil, aaa.Options{}, fmt.Errorf("unknown NAS")
	}
	return found, options, nil
}
func (m *Manager) Handler(root, portal http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 3)
		if len(parts) < 2 || (parts[0] != "t" && parts[0] != "portal") {
			root.ServeHTTP(w, r)
			return
		}
		id := parts[1]
		var h http.Handler
		if id == "default" && parts[0] == "portal" {
			h = portal
		} else {
			m.mu.RLock()
			runtime := m.runtimes[id]
			m.mu.RUnlock()
			if runtime != nil {
				h = runtime.Admin
				if parts[0] == "portal" {
					h = runtime.Portal
				}
			}
		}
		if h == nil {
			http.NotFound(w, r)
			return
		}
		prefix := "/" + parts[0] + "/" + id + "/"
		if len(parts) < 3 {
			http.Redirect(w, r, prefix, http.StatusTemporaryRedirect)
			return
		}
		request := r.Clone(r.Context())
		u := *r.URL
		request.URL = &u
		request.URL.Path = "/" + parts[2]
		request.URL.RawPath = ""
		h.ServeHTTP(&cookieScope{ResponseWriter: w, path: prefix}, request)
	})
}

type cookieScope struct {
	http.ResponseWriter
	path    string
	written bool
}

func (w *cookieScope) WriteHeader(code int) {
	if !w.written {
		headers := w.Header().Values("Set-Cookie")
		w.Header().Del("Set-Cookie")
		for _, v := range headers {
			w.Header().Add("Set-Cookie", strings.Replace(v, "Path=/;", "Path="+w.path+";", 1))
		}
		w.written = true
	}
	w.ResponseWriter.WriteHeader(code)
}
func (w *cookieScope) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}

// The public OUI reference is copied; observations and API credentials stay tenant-private.
func (m *Manager) copyRegistry(ctx context.Context, target *store.Store) error {
	rows, err := m.Root.DB.QueryContext(ctx, "SELECT prefix,manufacturer FROM oui_prefixes")
	if err != nil {
		return err
	}
	defer rows.Close()
	tx, err := target.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for rows.Next() {
		var prefix, manufacturer string
		if err = rows.Scan(&prefix, &manufacturer); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, target.SQL("INSERT INTO oui_prefixes(prefix,manufacturer) VALUES(?,?) ON CONFLICT(prefix) DO NOTHING"), prefix, manufacturer); err != nil {
			return err
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	return tx.Commit()
}
