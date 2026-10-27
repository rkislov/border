package identitysource

import (
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/store"
	"path/filepath"
	"strings"
	"testing"
)

func TestDomainIsolationAndLocalLifecycle(t *testing.T) {
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
	for _, id := range []string{"ad", "ipa"} {
		d := Domain{ID: id, Name: id, Enabled: true, Endpoints: []string{"ldaps://" + id + ".example.test:636"}, BaseDN: "dc=" + id, BindDN: "cn=reader", BindPassword: "password-" + id, UserAttribute: "uid"}
		if e = s.SaveDomain(ctx, d); e != nil {
			t.Fatal(e)
		}
	}
	list, e := s.Domains(ctx)
	if e != nil || len(list) != 2 {
		t.Fatal(list, e)
	}
	for _, d := range list {
		if d.BindPassword != "" || !d.HasPassword {
			t.Fatal("password leaked")
		}
	}
	ad, _ := s.Domain(ctx, "ad")
	ipa, _ := s.Domain(ctx, "ipa")
	if ad.BindPassword == ipa.BindPassword || ad.BaseDN == ipa.BaseDN {
		t.Fatal("domain mixup")
	}
	ad.BindPassword = ""
	ad.Endpoints = []string{"ldaps://new.example.test"}
	if e = s.SaveDomain(ctx, ad); e == nil {
		t.Fatal("secret forwarded to changed endpoint")
	}
	var raw string
	db.Row(ctx, "SELECT config FROM domains WHERE id='ad'").Scan(&raw)
	if strings.Contains(raw, "password-ad") {
		t.Fatal("unencrypted bind password")
	}
	if _, e = vault.Open(raw, "domain:ipa"); e == nil {
		t.Fatal("domain AAD mismatch accepted")
	}
	local := LocalUser{Username: "Alice", Email: "alice@example.test", Phone: "+79991234567", Password: "correct-password-123", Enabled: true}
	if e = s.SaveLocal(ctx, local); e != nil {
		t.Fatal(e)
	}
	i, e := s.Authenticate(ctx, "local/ALICE", local.Password)
	if e != nil || i.Username != "local/alice" || i.Phone != local.Phone {
		t.Fatal("local login", i, e)
	}
	if _, e = s.Authenticate(ctx, "missing/alice", local.Password); e == nil {
		t.Fatal("cross source fallback")
	}
	local.Password = ""
	local.Enabled = false
	if e = s.SaveLocal(ctx, local); e != nil {
		t.Fatal(e)
	}
	if s.Active(ctx, "local/alice") {
		t.Fatal("disabled local active")
	}
	if _, e = s.Authenticate(ctx, "local/alice", "correct-password-123"); e == nil {
		t.Fatal("disabled login")
	}
}
