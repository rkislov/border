// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"path/filepath"
	"testing"
	"time"
)

// This is the vendor-independent Class path, not RouterOS tuple matching.
func TestAccountingWithoutStartSurvivesServerRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.db")
	s, err := Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.DB.Close() }()
	ctx := t.Context()
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	token, err := s.NewAccessGrant(ctx, "192.0.2.1", "local/user", "vpn", time.Now().Unix()+600)
	if err != nil {
		t.Fatal(err)
	}
	event := AccountingEvent{NAS: "192.0.2.1", ID: "vpn", Username: "local/user", Kind: "interim", Key: "first-interim", At: time.Now().Unix(), Seconds: 60, Timed: true, HasSeconds: true, Classes: []string{token}}
	if err = s.ApplyAccounting(ctx, event); err != nil {
		t.Fatal(err)
	}
	before, err := s.Sessions(ctx)
	if err != nil || len(before) != 1 || !before[0].AuthorizationLinked {
		t.Fatalf("lost Start: %+v %v", before, err)
	}
	if err = s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyAccounting(ctx, event); err != nil {
		t.Fatal(err)
	}
	after, err := s.Sessions(ctx)
	if err != nil || len(after) != 1 || after[0].Generation != before[0].Generation || after[0].LastSeen != before[0].LastSeen {
		t.Fatalf("replay after restart: %+v %v", after, err)
	}
	// Revocation remains associated with the recovered session after reopening DB.
	if err = s.Exec(ctx, "UPDATE access_grants SET reason='user blocked' WHERE token=?", token); err != nil {
		t.Fatal(err)
	}
	after, err = s.Sessions(ctx)
	if err != nil || after[0].RevocationReason != "user blocked" {
		t.Fatalf("lost revocation: %+v %v", after, err)
	}
}
