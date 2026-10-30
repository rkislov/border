// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"testing"
	"time"
)

func TestVPNAccountingClaim(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	token, err := s.NewAccessGrant(ctx, "nas", "user", "p", now+600)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.EnableVPNAccounting(ctx, token, "tuple"); err != nil {
		t.Fatal(err)
	}
	e := AccountingEvent{NAS: "nas", ID: "vpn1", Username: "user", AccountingKey: "tuple", Kind: "start", Key: "start", At: now, Timed: true, HasSeconds: true}
	apply := func() {
		t.Helper()
		if err = s.ApplyAccounting(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	check := func(id, want, status string) {
		t.Helper()
		var got, st string
		if err = s.Row(ctx, "SELECT grant_token,status FROM sessions WHERE nas='nas' AND session_id=?", id).Scan(&got, &st); err != nil || got != want || st != status {
			t.Fatal(got, st, err)
		}
	}
	apply()
	apply()
	check("vpn1", token, "active")
	e.ID = "vpn2"
	e.Key = "other-session"
	apply()
	check("vpn2", "", "active")
	e.ID = "vpn1"
	e.Kind = "interim"
	e.Key = "interim"
	e.At = now + 1
	e.Seconds = 1
	apply()
	check("vpn1", token, "active")
	e.AccountingKey = "other-client"
	e.Kind = "stop"
	e.Key = "forged-stop"
	apply()
	check("vpn1", token, "active")
	e.AccountingKey = "tuple"
	e.Key = "stop"
	apply()
	check("vpn1", token, "stopped")
	e.Kind = "interim"
	e.Key = "late"
	e.At++
	e.Seconds++
	apply()
	check("vpn1", token, "stopped")
}

func TestVPNAccountingRefusesAmbiguity(t *testing.T) {
	for _, scenario := range []string{"ambiguous", "old-grant", "missing-tuple", "other-user", "other-nas", "untimed", "interim-first", "unknown-class", "delayed-start"} {
		t.Run(scenario, func(t *testing.T) {
			s := ruleStore(t)
			ctx := t.Context()
			now := time.Now().Unix()
			add := func() {
				t.Helper()
				token, e := s.NewAccessGrant(ctx, "nas", "user", "p", now+600)
				if e != nil {
					t.Fatal(e)
				}
				if e = s.EnableVPNAccounting(ctx, token, "tuple"); e != nil {
					t.Fatal(e)
				}
			}
			add()
			e := AccountingEvent{NAS: "nas", ID: "vpn", Username: "user", AccountingKey: "tuple", Kind: "start", Key: "event", At: now, Timed: true, HasSeconds: true}
			switch scenario {
			case "ambiguous":
				add()
			case "old-grant":
				if err := s.Exec(ctx, "UPDATE access_grants SET issued_at=?", now-100); err != nil {
					t.Fatal(err)
				}
			case "missing-tuple":
				e.AccountingKey = ""
			case "other-user":
				e.Username = "other"
			case "other-nas":
				e.NAS = "other"
			case "untimed":
				e.Timed = false
			case "interim-first":
				e.Kind = "interim"
			case "unknown-class":
				e.Classes = []string{"unknown"}
			case "delayed-start":
				e.Seconds = 20
			}
			if err := s.ApplyAccounting(ctx, e); err != nil {
				t.Fatal(err)
			}
			var token string
			if err := s.Row(ctx, "SELECT grant_token FROM sessions WHERE session_id='vpn'").Scan(&token); err != nil || token != "" {
				t.Fatal(token, err)
			}
		})
	}
}

func TestVPNRapidReconnectAndConcurrentClaims(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	add := func() string {
		t.Helper()
		v, e := s.NewAccessGrant(ctx, "nas", "user", "vpn", now+600)
		if e != nil {
			t.Fatal(e)
		}
		if e = s.EnableVPNAccounting(ctx, v, "tuple"); e != nil {
			t.Fatal(e)
		}
		return v
	}
	event := func(id, key, kind string, at, seconds int64) {
		t.Helper()
		if e := s.ApplyAccounting(ctx, AccountingEvent{NAS: "nas", ID: id, Username: "user", AccountingKey: "tuple", Key: key, Kind: kind, At: at, Seconds: seconds, Timed: true, HasSeconds: true}); e != nil {
			t.Fatal(e)
		}
	}
	check := func(id, token, status string) {
		t.Helper()
		var got, st string
		if e := s.Row(ctx, "SELECT grant_token,status FROM sessions WHERE nas='nas' AND session_id=?", id).Scan(&got, &st); e != nil || got != token || st != status {
			t.Fatal(got, st, e)
		}
	}
	first := add()
	event("one", "start1", "start", now, 0)
	second := add()
	event("two", "start2", "start", now, 0)
	check("one", first, "active")
	check("two", second, "active")
	event("one", "stop1", "stop", now+1, 1)
	third := add()
	event("three", "start3", "start", now+1, 0)
	check("three", third, "active")
	check("two", second, "active")
	event("one", "replay-start", "start", now, 0)
	check("one", first, "stopped")
	event("two", "stop2", "stop", now+2, 2)
	check("two", second, "stopped")
	check("three", third, "active")
}
