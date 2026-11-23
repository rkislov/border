// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package netcraze

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/store"
)

type Config struct {
	Enabled                                                    bool
	Address, HTTPHost, Username, Password, CertificateSHA256   string
	TunnelHTTP                                                 bool
	Chilli, Bridge, Subnet, SegmentID, DomainID, NASIdentifier string
	VLAN                                                       int
	RadiusServer                                               string
	AuthPort, AccountingPort                                   int
	UAMSecret                                                  string
}
type Service struct {
	Store     *store.Store
	Vault     *auth.Vault
	PublicURL string
}

var chilliName = regexp.MustCompile(`^Chilli[0-9]{1,4}$`)
var bridgeName = regexp.MustCompile(`^Bridge[0-9]{1,4}$`)
var sessionName = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func (s *Service) Config(ctx context.Context, nas string) (v Config, err error) {
	var raw string
	err = s.Store.Row(ctx, "SELECT config FROM nas_netcraze WHERE nas=?", nas).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return v, nil
	}
	if err != nil {
		return
	}
	if s.Vault == nil {
		return v, fmt.Errorf("BORDER_MASTER_KEY required")
	}
	b, e := s.Vault.Open(raw, "netcraze:"+nas)
	if e != nil {
		return v, fmt.Errorf("Netcraze configuration unavailable")
	}
	defer clear(b)
	err = json.Unmarshal(b, &v)
	return
}
func (c Config) validate() error {
	u, e := url.Parse(c.Address)
	if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("management URL must be https://IP:port")
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if e != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return fmt.Errorf("explicit unicast IPv4 management address required")
	}
	if u.Port() != "" {
		if port, err := strconv.Atoi(u.Port()); err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid management port")
		}
	}
	if u.Scheme == "http" && (!c.TunnelHTTP || !(ip.IsPrivate() || ip.IsLoopback())) {
		return fmt.Errorf("HTTP requires an explicitly protected private tunnel")
	}
	if u.Scheme == "https" {
		b, e := hex.DecodeString(c.CertificateSHA256)
		if e != nil || len(b) != 32 {
			return fmt.Errorf("verified SHA-256 certificate fingerprint required")
		}
	}
	if c.HTTPHost != "" {
		h, e := url.Parse("http://" + c.HTTPHost)
		if e != nil || h.Host != c.HTTPHost || h.Hostname() == "" || h.User != nil || h.Path != "" || h.RawQuery != "" || h.Fragment != "" || strings.ContainsAny(c.HTTPHost, " \r\n\t\\") {
			return fmt.Errorf("invalid management Host")
		}
	}
	if c.Username == "" || len(c.Username) > 128 || strings.ContainsAny(c.Username, "\r\n\x00") || len(c.Password) < 8 || len(c.Password) > 1024 {
		return fmt.Errorf("service username and password of at least 8 characters required")
	}
	prefix, e := netip.ParsePrefix(c.Subnet)
	if e != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() < 8 || prefix.Bits() > 30 {
		return fmt.Errorf("guest IPv4 subnet in CIDR form required")
	}
	if !chilliName.MatchString(c.Chilli) || !bridgeName.MatchString(c.Bridge) || c.VLAN < 1 || c.VLAN > 4094 || c.SegmentID == "" {
		return fmt.Errorf("Chilli, bridge and mapped guest segment required")
	}
	ip, e = netip.ParseAddr(c.RadiusServer)
	if e != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || c.AuthPort < 1 || c.AuthPort > 65535 || c.AccountingPort < 1 || c.AccountingPort > 65535 {
		return fmt.Errorf("RADIUS IPv4 address and ports required")
	}
	if c.NASIdentifier == "" || len(c.NASIdentifier) > 128 || strings.ContainsAny(c.NASIdentifier, "\r\n\x00") || len(c.UAMSecret) < 16 || len(c.UAMSecret) > 128 {
		return fmt.Errorf("NAS identifier and UAM secret of at least 16 characters required")
	}
	return nil
}
func (s *Service) Save(ctx context.Context, nas string, c Config) error {
	if s.Vault == nil {
		return fmt.Errorf("BORDER_MASTER_KEY required")
	}
	ip, e := netip.ParseAddr(nas)
	if e != nil || !ip.Is4() || ip.String() != nas {
		return fmt.Errorf("canonical NAS IPv4 address required")
	}
	var dict, mode string
	var portal bool
	if e = s.Store.Row(ctx, "SELECT dictionary,access_mode,portal_enabled FROM nas WHERE address=?", nas).Scan(&dict, &mode, &portal); e != nil || dict != "keenetic" {
		return fmt.Errorf("registered Netcraze/Keenetic NAS required")
	}
	old, e := s.Config(ctx, nas)
	if e != nil {
		return e
	}
	c.Address = strings.TrimRight(strings.TrimSpace(c.Address), "/")
	c.CertificateSHA256 = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(c.CertificateSHA256), ":", ""))
	if c.Password == "" && c.Address == old.Address && c.HTTPHost == old.HTTPHost && c.Username == old.Username && c.CertificateSHA256 == old.CertificateSHA256 && c.TunnelHTTP == old.TunnelHTTP {
		c.Password = old.Password
	}
	if c.UAMSecret == "" {
		c.UAMSecret = old.UAMSecret
	}
	if c.Enabled {
		if mode != "network" || !portal {
			return fmt.Errorf("NAS guest network must be enabled")
		}
		if e = c.validate(); e != nil {
			return e
		}
		var count int
		if e = s.Store.Row(ctx, "SELECT COUNT(*) FROM network_segments WHERE id=?", c.SegmentID).Scan(&count); e != nil || count != 1 {
			return fmt.Errorf("guest segment unavailable")
		}
		if c.DomainID != "" {
			if e = s.Store.ValidatePortalScope(ctx, "domain:"+c.DomainID); e != nil {
				return fmt.Errorf("domain unavailable")
			}
		}
	}
	if c == old {
		return nil
	}
	raw, e := json.Marshal(c)
	if e != nil {
		return e
	}
	defer clear(raw)
	tx, e := s.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	enabled := 0
	if c.Enabled {
		enabled = 1
	}
	if _, e = tx.ExecContext(ctx, s.Store.SQL("INSERT INTO nas_netcraze(nas,enabled,config) VALUES(?,?,?) ON CONFLICT(nas) DO UPDATE SET enabled=excluded.enabled,config=excluded.config"), nas, enabled, s.Vault.Seal(raw, "netcraze:"+nas)); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, s.Store.SQL("UPDATE access_grants SET reason='NAS captive adapter changed',next_attempt=0 WHERE nas=? AND reason='' AND guest_authorization_id<>''"), nas); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, s.Store.SQL("DELETE FROM guest_authorizations WHERE nas=?"), nas); e != nil {
		return e
	}
	return tx.Commit()
}
func RedirectURL(publicURL, nas string) (string, error) {
	u, e := url.Parse(publicURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("public HTTPS portal URL required")
	}
	if _, e = netip.ParseAddr(nas); e != nil {
		return "", fmt.Errorf("invalid NAS")
	}
	return strings.TrimRight(publicURL, "/") + "/uam/netcraze/" + url.PathEscape(nas), nil
}
