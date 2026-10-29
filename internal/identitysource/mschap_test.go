package identitysource

import (
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/mschap"
	"github.com/rkislov/border/internal/store"
	"path/filepath"
	"testing"
)

func TestMSCHAPLifecycle(t *testing.T) {
	ctx := t.Context()
	db, e := store.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.DB.Close()
	if e = db.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	vault, _ := auth.NewVault(make([]byte, 32))
	s := &Service{Store: db, Vault: vault}
	yes, no := true, false
	u := LocalUser{Username: "alice", Password: "test-password-123", Enabled: true, MSCHAPEnabled: &yes}
	if e = s.SaveLocal(ctx, u); e != nil {
		t.Fatal(e)
	}
	r := &mschap.Request{Challenge: make([]byte, 16), Peer: make([]byte, 16)}
	r.Response = mschap.NTResponse(mschap.PasswordHash(u.Password), r.Challenge, r.Peer, "alice")
	if _, e = s.VerifyLocalMSCHAP(ctx, "alice", "alice", r); e != nil {
		t.Fatal(e)
	}
	u.Password = ""
	u.Enabled = false
	if e = s.SaveLocal(ctx, u); e != nil {
		t.Fatal(e)
	}
	if _, e = s.VerifyLocalMSCHAP(ctx, "alice", "alice", r); e == nil {
		t.Fatal("disabled user accepted")
	}
	u.Enabled = true
	u.Password = "changed-password-123"
	u.MSCHAPEnabled = nil
	if e = s.SaveLocal(ctx, u); e != nil {
		t.Fatal(e)
	}
	if _, e = s.VerifyLocalMSCHAP(ctx, "alice", "alice", r); e == nil {
		t.Fatal("old password accepted")
	}
	u.Password = ""
	u.MSCHAPEnabled = &no
	if e = s.SaveLocal(ctx, u); e != nil {
		t.Fatal(e)
	}
	u.MSCHAPEnabled = &yes
	if e = s.SaveLocal(ctx, u); e == nil {
		t.Fatal("enabled without password")
	}
}
