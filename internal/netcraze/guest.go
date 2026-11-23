// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package netcraze

import (
	"context"
	"crypto/md5"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rkislov/border/internal/guest"
	"github.com/rkislov/border/internal/identity"
	"github.com/rkislov/border/internal/store"
)

type interfaceConfig struct {
	Up       bool
	Security map[string]bool `json:"security-level"`
	IP       struct {
		Address struct{ Address, Mask string }
	}
	Chilli struct {
		Dhcpif, Uamserver, Uamsecret, Radiussecret, Radiusnasid string
		Radiusauthport, Radiusacctport, Coaport                 string
		Radius                                                  struct{ Server1, Server2 string }
		Nasip                                                   struct{ Address string }
	}
}
type host struct {
	SessionID     string `json:"session-id"`
	User, IP, MAC string
}

var errHostAbsent = errors.New("NAS guest not in authenticated host list")

func (s *Service) ready(ctx context.Context, nas string) (Config, string, int, error) {
	c, e := s.Config(ctx, nas)
	if e != nil {
		return c, "", 0, e
	}
	if !c.Enabled {
		return c, "", 0, fmt.Errorf("Netcraze adapter disabled")
	}
	if e = c.validate(); e != nil {
		return c, "", 0, e
	}
	var dict, mode, secret string
	var portal bool
	var coa int
	e = s.Store.Row(ctx, "SELECT dictionary,access_mode,portal_enabled,secret,coa_port FROM nas WHERE address=?", nas).Scan(&dict, &mode, &portal, &secret, &coa)
	if e != nil || dict != "keenetic" || mode != "network" || !portal {
		return c, "", 0, fmt.Errorf("Netcraze guest NAS unavailable")
	}
	if c.DomainID != "" {
		if e = s.Store.ValidatePortalScope(ctx, "domain:"+c.DomainID); e != nil {
			return c, "", 0, fmt.Errorf("domain unavailable")
		}
	}
	return c, secret, coa, nil
}
func (s *Service) inspect(ctx context.Context, x *client, nas, secret string, coa int) (interfaceConfig, error) {
	c := x.cfg
	var out struct{ Interface map[string]interfaceConfig }
	if e := x.command(ctx, "show rc interface "+c.Chilli, &out); e != nil {
		return interfaceConfig{}, e
	}
	v, ok := out.Interface[c.Chilli]
	if !ok || !v.Up || !v.Security["protected"] || v.Chilli.Dhcpif != c.Bridge {
		return v, fmt.Errorf("protected Chilli bridge unavailable")
	}
	prefix, _ := netip.ParsePrefix(c.Subnet)
	ip, e := netip.ParseAddr(v.IP.Address.Address)
	mask := net.ParseIP(v.IP.Address.Mask).To4()
	ones, bits := net.IPMask(mask).Size()
	if e != nil || bits != 32 || prefix.Bits() != ones || !prefix.Contains(ip) {
		return v, fmt.Errorf("guest subnet mismatch")
	}
	u, e := RedirectURL(s.PublicURL, nas)
	if e != nil {
		return v, e
	}
	equal := func(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
	if v.Chilli.Uamserver != u || !equal(v.Chilli.Uamsecret, c.UAMSecret) || !equal(v.Chilli.Radiussecret, secret) || v.Chilli.Radiusnasid != c.NASIdentifier || v.Chilli.Nasip.Address != nas {
		return v, fmt.Errorf("Chilli UAM or NAS configuration mismatch")
	}
	// CLI 5.1 specifies these defaults; running-config may omit unset ports.
	if v.Chilli.Radiusauthport == "" {
		v.Chilli.Radiusauthport = "1812"
	}
	if v.Chilli.Radiusacctport == "" {
		v.Chilli.Radiusacctport = "1813"
	}
	if v.Chilli.Radius.Server1 != c.RadiusServer || (v.Chilli.Radius.Server2 != "" && v.Chilli.Radius.Server2 != c.RadiusServer) || v.Chilli.Radiusauthport != strconv.Itoa(c.AuthPort) || v.Chilli.Radiusacctport != strconv.Itoa(c.AccountingPort) || v.Chilli.Coaport != strconv.Itoa(coa) {
		return v, fmt.Errorf("Chilli RADIUS configuration mismatch")
	}
	return v, nil
}
func liveHost(ctx context.Context, x *client, mac, sid string) (host, error) {
	var result struct{ Host []host }
	if e := x.command(ctx, "show interface "+x.cfg.Chilli+" chilli", &result); e != nil {
		return host{}, e
	}
	var match []host
	for _, h := range result.Host {
		m, e := identity.MAC(h.MAC)
		if e == nil && m == mac {
			match = append(match, h)
		}
	}
	if len(match) == 0 {
		return host{}, errHostAbsent
	}
	if len(match) != 1 || match[0].SessionID != sid {
		return host{}, fmt.Errorf("NAS guest session absent, changed or ambiguous")
	}
	prefix, _ := netip.ParsePrefix(x.cfg.Subnet)
	ip, e := netip.ParseAddr(match[0].IP)
	if e != nil || !prefix.Contains(ip) {
		return host{}, fmt.Errorf("guest IP outside configured subnet")
	}
	return match[0], nil
}
func (s *Service) Probe(ctx context.Context, nas string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, secret, coa, e := s.ready(ctx, nas)
	if e != nil {
		return e
	}
	x, e := connect(ctx, c)
	if e != nil {
		return e
	}
	defer x.close()
	_, e = s.inspect(ctx, x, nas, secret, coa)
	return e
}

// Verify the exact signed NAS URL before making any management connection. The
// signed session binding supports NAT/proxies without trusting browser IP headers.
func (s *Service) Redirect(ctx context.Context, nas, rawQuery, publicURL string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, secret, coa, e := s.ready(ctx, nas)
	if e != nil {
		return "", e
	}
	u, e := RedirectURL(publicURL, nas)
	if e != nil {
		return "", e
	}
	raw, sig, ok := strings.Cut(rawQuery, "&md=")
	if !ok || len(rawQuery) > 8192 || len(sig) != 32 {
		return "", fmt.Errorf("invalid NAS redirect")
	}
	digest, e := hex.DecodeString(sig)
	sum := md5.Sum([]byte(u + "?" + raw + c.UAMSecret))
	if e != nil || subtle.ConstantTimeCompare(digest, sum[:]) != 1 {
		return "", fmt.Errorf("invalid NAS redirect signature")
	}
	q, e := url.ParseQuery(raw)
	if e != nil {
		return "", fmt.Errorf("invalid NAS redirect")
	}
	for _, v := range q {
		if len(v) != 1 {
			return "", fmt.Errorf("ambiguous NAS redirect")
		}
	}
	mac, e := identity.MAC(q.Get("mac"))
	if e != nil || !sessionName.MatchString(q.Get("sessionid")) || q.Get("nasid") != c.NASIdentifier || q.Get("res") != "notyet" {
		return "", fmt.Errorf("invalid NAS guest session")
	}
	challenge, e := hex.DecodeString(q.Get("challenge"))
	if e != nil || len(challenge) != 16 {
		return "", fmt.Errorf("invalid NAS challenge")
	}
	x, e := connect(ctx, c)
	if e != nil {
		return "", e
	}
	defer x.close()
	scoped := *s
	scoped.PublicURL = publicURL
	rc, e := scoped.inspect(ctx, x, nas, secret, coa)
	if e != nil {
		return "", e
	}
	if q.Get("uamip") != rc.IP.Address.Address {
		return "", fmt.Errorf("UAM gateway mismatch")
	}
	h, e := liveHost(ctx, x, mac, q.Get("sessionid"))
	if e != nil && !errors.Is(e, errHostAbsent) {
		return "", e
	}
	if e == nil && (h.IP != q.Get("ip") || h.User != "") {
		return "", fmt.Errorf("NAS guest session changed")
	}
	ip, ipErr := netip.ParseAddr(q.Get("ip"))
	prefix, _ := netip.ParsePrefix(c.Subnet)
	if ipErr != nil || !prefix.Contains(ip) || ip.String() == rc.IP.Address.Address {
		return "", fmt.Errorf("guest IP outside configured subnet")
	}
	return guest.SignRedirect(guest.Redirect{NAS: nas, MAC: mac, SessionID: q.Get("sessionid"), Domain: c.DomainID}, secret)
}
func (s *Service) ActivateGuest(ctx context.Context, g store.GuestAuthorization, vlan int) (bool, error) {
	c, e := s.Config(ctx, g.NAS)
	if e != nil {
		return true, e
	}
	if !c.Enabled {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, secret, coa, e := s.ready(ctx, g.NAS)
	if e != nil {
		return true, e
	}
	mac, e := identity.MAC(g.MAC)
	if e != nil || mac != g.MAC || !sessionName.MatchString(g.NASSessionID) || vlan != c.VLAN || g.DomainID != c.DomainID {
		return true, fmt.Errorf("guest activation scope mismatch")
	}
	valid := func() error {
		actual, e := s.Store.GuestAuthorization(ctx, g.NAS, g.MAC)
		if e != nil || actual.ID != g.ID || actual.NASSessionID != g.NASSessionID {
			return fmt.Errorf("guest authorization changed")
		}
		bound, e := s.Store.GuestAccessPolicy(ctx, g.NAS, g.MAC, g.DomainID, g.Method)
		if e != nil || bound.Access.SegmentID != c.SegmentID || bound.VLAN != c.VLAN {
			return fmt.Errorf("guest segment mismatch")
		}
		now, e := s.Config(ctx, g.NAS)
		if e != nil || now != c {
			return fmt.Errorf("NAS configuration changed")
		}
		return nil
	}
	if e = valid(); e != nil {
		return true, e
	}
	x, e := connect(ctx, c)
	if e != nil {
		return true, e
	}
	defer x.close()
	if _, e = s.inspect(ctx, x, g.NAS, secret, coa); e != nil {
		return true, e
	}
	h, e := liveHost(ctx, x, mac, g.NASSessionID)
	if e != nil && !errors.Is(e, errHostAbsent) {
		return true, e
	}
	if h.User != "" {
		userMAC, err := identity.MAC(h.User)
		if err != nil || userMAC != mac {
			return true, fmt.Errorf("guest host already authenticated as another user")
		}
		return true, nil
	}
	if e = valid(); e != nil {
		return true, e
	}
	// Only canonical MAC and validated interface name enter the command. A new
	// NAS session racing this command cannot use the old grant: RADIUS checks SID.
	// Chilli may omit unauthenticated clients from its host list. Absence never
	// confirms access; the NAS must send this signed SID in Access-Request and
	// subsequently return the issued Class in Accounting to confirm activation.
	e = x.command(ctx, "interface "+c.Chilli+" chilli login "+mac+" username "+mac+" password "+mac, nil)
	return true, e
}
