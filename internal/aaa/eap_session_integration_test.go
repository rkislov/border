// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/rkislov/border/internal/identitysource"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

// This NAS emulator acknowledges Disconnect requests; it cannot prove that a
// physical authenticator removed a station from its controlled port.
type tunnelSessions struct {
	t        *testing.T
	s        *store.Store
	ids      *identitysource.Service
	user     string
	received chan string
	errors   chan error
	active   map[string]string
	retired  map[string]string
}

func newTunnelSessions(t *testing.T, s *store.Store, ids *identitysource.Service, user string) *tunnelSessions {
	t.Helper()
	n := &tunnelSessions{t: t, s: s, ids: ids, user: user, received: make(chan string, 32), errors: make(chan error, 32), active: map[string]string{}, retired: map[string]string{}}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Exec(t.Context(), "UPDATE nas SET coa_port=? WHERE address='127.0.0.1'", conn.LocalAddr().(*net.UDPAddr).Port); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var buf [4096]byte
		for {
			size, remote, err := conn.ReadFrom(buf[:])
			if err != nil {
				return
			}
			p, err := radius.Parse(buf[:size], []byte(testSecret))
			if err != nil {
				n.errors <- err
				continue
			}
			id := rfc2866.AcctSessionID_GetString(p)
			if p.Code != radius.CodeDisconnectRequest || rfc2865.UserName_GetString(p) != user || id == "" {
				n.errors <- fmt.Errorf("unexpected disconnect target/code: %s", id)
			}
			n.received <- id
			wire, err := p.Response(radius.CodeDisconnectACK).Encode()
			if err == nil {
				_, err = conn.WriteTo(wire, remote)
			}
			if err != nil {
				n.errors <- err
			}
		}
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	token, err := s.NewAccessGrant(t.Context(), "127.0.0.1", "local/alice", "", time.Now().Unix()+3600)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Accounting(t.Context(), "127.0.0.1", "unrelated-session", "", "local/alice", "active", token); err != nil {
		t.Fatal(err)
	}
	return n
}

func (n *tunnelSessions) attach(ctx context.Context, phase string) {
	n.t.Helper()
	var token string
	// Each successful EAP exchange creates exactly one still-unattached grant.
	if err := n.s.Row(ctx, `SELECT token FROM access_grants WHERE username=? AND token NOT IN (SELECT grant_token FROM sessions WHERE grant_token IS NOT NULL)`, n.user).Scan(&token); err != nil {
		n.t.Fatal(err)
	}
	for _, suffix := range []string{"wifi", "wired"} {
		id := phase + "-" + suffix
		if err := n.s.Accounting(ctx, "127.0.0.1", id, "", n.user, "active", token); err != nil {
			n.t.Fatal(err)
		}
		n.active[id] = token
	}
}

func (n *tunnelSessions) check(ctx context.Context, phase string) {
	n.t.Helper()
	if err := n.s.Exec(ctx, "UPDATE identity_status SET checked_at=0"); err != nil {
		n.t.Fatal(err)
	}
	if err := n.ids.SyncAccountStatus(ctx); err != nil {
		n.t.Fatal(err)
	}
	if err := RevokeSessions(ctx, n.s); err != nil {
		n.t.Fatal(err)
	}
	expected := map[string]bool{}
	revoke := phase == "blocked" || phase == "expired"
	if revoke {
		for id, token := range n.active {
			expected[id] = true
			n.retired[id] = token
		}
		n.active = map[string]string{}
	}
	for len(n.received) > 0 {
		id := <-n.received
		if !expected[id] {
			n.t.Fatalf("%s: unexpected/duplicate Disconnect for %s", phase, id)
		}
		delete(expected, id)
	}
	if len(expected) != 0 {
		n.t.Fatalf("%s: missing Disconnects: %v", phase, expected)
	}
	select {
	case err := <-n.errors:
		n.t.Fatal(err)
	default:
	}
	for id := range n.active {
		n.status(ctx, id, "active")
	}
	for id, token := range n.retired {
		n.status(ctx, id, "disconnect-ack")
		var reason string
		if err := n.s.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", token).Scan(&reason); err != nil || reason == "" {
			n.t.Fatalf("old grant restored: %v", err)
		}
	}
	n.status(ctx, "unrelated-session", "active")
	enabled, err := n.s.IdentityEnabled(ctx, n.user)
	if err != nil || enabled == (phase == "blocked" || phase == "blocked-ldap-down") {
		n.t.Fatalf("%s: identity enabled=%v error=%v", phase, enabled, err)
	}
	n.t.Logf("%s: active=%d retired=%d; unrelated session preserved", phase, len(n.active), len(n.retired))
}
func (n *tunnelSessions) status(ctx context.Context, id, want string) {
	n.t.Helper()
	var got string
	if err := n.s.Row(ctx, "SELECT status FROM sessions WHERE session_id=?", id).Scan(&got); err != nil || got != want {
		n.t.Fatalf("session %s: status=%s want=%s error=%v", id, got, want, err)
	}
}
