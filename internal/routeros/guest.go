// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package routeros

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/rkislov/border/internal/identity"
	"github.com/rkislov/border/internal/store"
	"golang.org/x/crypto/ssh"
)

// HotSpot is a routed captive gateway: it cannot move a station to an arbitrary
// VLAN. Only a server on the policy's exact VLAN interface may be activated.
func hotspotLoginCommand(server, mac string, vlan int) string {
	return `:local hs [/ip hotspot find where name=` + quote(server) + ` and disabled=no]; :if ([:len $hs] != 1) do={:error "hotspot unavailable"}; ` +
		`:local iface [/ip hotspot get [:pick $hs 0] interface]; :local vl [/interface vlan find where name=$iface and vlan-id=` + strconv.Itoa(vlan) + ` and disabled=no]; :if ([:len $vl] != 1) do={:error "policy VLAN mismatch"}; ` +
		`:local profile [/ip hotspot get [:pick $hs 0] profile]; :if (([/ip hotspot profile get $profile use-radius] != true) or ([/ip hotspot profile get $profile radius-accounting] != true)) do={:error "RADIUS and accounting required"}; ` +
		`:if ([:len [/ip hotspot user find where name=` + quote(mac) + `]] != 0) do={:error "local user collision"}; ` +
		`:local host [/ip hotspot host find where mac-address=` + quote(strings.ToUpper(mac)) + ` and server=` + quote(server) + `]; :if ([:len $host] != 1) do={:error "host absent or ambiguous"}; :if ([/ip hotspot host get [:pick $host 0] bypassed] = true) do={:error "bypassed host"}; ` +
		`:if ([:len [/ip hotspot active find where mac-address=` + quote(strings.ToUpper(mac)) + `]] > 0) do={:put "border-awaiting-accounting"} else={:local ip [/ip hotspot host get [:pick $host 0] address]; /ip hotspot active login user=` + quote(mac) + ` password=` + quote(mac) + ` mac-address=` + quote(strings.ToUpper(mac)) + ` ip=$ip; :put "border-login-requested"}`
}

// Success means only that the request reached RouterOS. The caller must observe
// Accounting with the new grant's Class before announcing access to the guest.
func (s *Service) ActivateGuest(ctx context.Context, g store.GuestAuthorization, vlan int) (bool, error) {
	cfg, e := s.Config(ctx, g.NAS)
	if e != nil {
		return true, e
	}
	if !cfg.Enabled || cfg.GuestHotspot == "" {
		return false, nil
	}
	mac, e := identity.MAC(g.MAC)
	if e != nil || mac != g.MAC || vlan < 1 || vlan > 4094 {
		return true, fmt.Errorf("invalid guest activation")
	}
	var dictionary, mode string
	var portal bool
	if e = s.Store.Row(ctx, "SELECT dictionary,access_mode,portal_enabled FROM nas WHERE address=?", g.NAS).Scan(&dictionary, &mode, &portal); e != nil || dictionary != "mikrotik" || mode != "network" || !portal {
		return true, fmt.Errorf("MikroTik guest network required")
	}
	// Recheck the generation immediately before issuing any management command.
	current, e := s.Store.GuestAuthorization(ctx, g.NAS, g.MAC)
	if e != nil || current.ID != g.ID {
		return true, fmt.Errorf("guest authorization changed")
	}
	raw, e := guestCommand(ctx, cfg, hotspotLoginCommand(cfg.GuestHotspot, mac, vlan))
	if e != nil {
		return true, e
	}
	switch strings.TrimSpace(string(raw)) {
	case "border-login-requested", "border-awaiting-accounting":
		return true, nil
	}
	return true, fmt.Errorf("RouterOS activation response invalid")
}

func guestCommand(ctx context.Context, cfg Config, command string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, e := (&net.Dialer{}).DialContext(ctx, "tcp", cfg.Address)
	if e != nil {
		return nil, fmt.Errorf("RouterOS management unavailable")
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	cc, ch, r, e := ssh.NewClientConn(conn, cfg.Address, &ssh.ClientConfig{User: cfg.Username, Auth: []ssh.AuthMethod{ssh.Password(cfg.Password)}, HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
		if ssh.FingerprintSHA256(k) != cfg.HostKey {
			return fmt.Errorf("host key mismatch")
		}
		return nil
	}})
	if e != nil {
		return nil, fmt.Errorf("RouterOS SSH authentication or host key verification failed")
	}
	c := ssh.NewClient(cc, ch, r)
	defer c.Close()
	raw, e := run(c, command)
	if e != nil {
		return nil, e
	}

	return raw, e
}
