// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package pki

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"sync"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type ACMEConfig struct {
	Enabled                     bool
	Domain, Email, DirectoryURL string
	AcceptTerms                 bool
}
type ACME struct {
	pki     *Manager
	mu      sync.RWMutex
	manager *autocert.Manager
	config  ACMEConfig
}

func NewACME(ctx context.Context, pki *Manager) (*ACME, error) {
	a := &ACME{pki: pki}
	var raw string
	err := pki.Store.Row(ctx, "SELECT value FROM settings WHERE name='acme_config'").Scan(&raw)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if raw != "" {
		var c ACMEConfig
		if err = json.Unmarshal([]byte(raw), &c); err != nil {
			return nil, err
		}
		if err = a.configure(c); err != nil {
			return nil, err
		}
	}
	return a, nil
}
func (a *ACME) configure(c ACMEConfig) error {
	if !c.Enabled {
		a.manager = nil
		a.config = c
		return nil
	}
	if !c.AcceptTerms {
		return fmt.Errorf("ACME terms must be accepted")
	}
	if c.Domain == "" || !strings.Contains(c.Domain, ".") || strings.ContainsAny(c.Domain, "/:* \\@") {
		return fmt.Errorf("a public DNS hostname is required")
	}
	if _, err := mail.ParseAddress(c.Email); err != nil {
		return fmt.Errorf("valid ACME contact email required")
	}
	if c.DirectoryURL == "" {
		c.DirectoryURL = acme.LetsEncryptURL
	}
	if !strings.HasPrefix(c.DirectoryURL, "https://") {
		return fmt.Errorf("ACME directory requires HTTPS")
	}
	a.manager = &autocert.Manager{Prompt: autocert.AcceptTOS, Email: c.Email, HostPolicy: autocert.HostWhitelist(c.Domain), Cache: acmeCache{a.pki}, Client: &acme.Client{DirectoryURL: c.DirectoryURL}}
	_ = a.manager.HTTPHandler(http.NotFoundHandler())
	a.config = c
	return nil
}
func (a *ACME) Configure(ctx context.Context, c ACMEConfig) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	old, oldConfig := a.manager, a.config
	if err := a.configure(c); err != nil {
		return err
	}
	raw, err := json.Marshal(a.config)
	if err == nil {
		err = a.pki.Store.Exec(ctx, "INSERT INTO settings(name,value) VALUES ('acme_config',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", string(raw))
	}
	if err != nil {
		a.manager = old
		a.config = oldConfig
	}
	return err
}
func (a *ACME) Config() ACMEConfig { a.mu.RLock(); defer a.mu.RUnlock(); return a.config }
func (a *ACME) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	a.mu.RLock()
	manager := a.manager
	domain := a.config.Domain
	a.mu.RUnlock()
	if manager == nil || hello.ServerName != domain {
		return nil, nil
	}
	return manager.GetCertificate(hello)
}
func (a *ACME) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.RLock()
		manager := a.manager
		a.mu.RUnlock()
		if manager == nil {
			http.NotFound(w, r)
			return
		}
		manager.HTTPHandler(http.NotFoundHandler()).ServeHTTP(w, r)
	})
}

type acmeCache struct{ m *Manager }

func (c acmeCache) Get(ctx context.Context, key string) ([]byte, error) {
	var raw string
	if err := c.m.Store.Row(ctx, "SELECT value FROM settings WHERE name=?", "acme-cache:"+key).Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return nil, autocert.ErrCacheMiss
		}
		return nil, err
	}
	return c.m.Vault.Open(raw, "acme:"+key)
}
func (c acmeCache) Put(ctx context.Context, key string, b []byte) error {
	return c.m.Store.Exec(ctx, "INSERT INTO settings(name,value) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", "acme-cache:"+key, c.m.Vault.Seal(b, "acme:"+key))
}
func (c acmeCache) Delete(ctx context.Context, key string) error {
	return c.m.Store.Exec(ctx, "DELETE FROM settings WHERE name=?", "acme-cache:"+key)
}
