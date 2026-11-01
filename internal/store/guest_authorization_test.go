package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/pressly/goose/v3"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestUnifiedGuestMigrationPreservesOIDCAndRetiresLegacyCodes(t *testing.T) {
	s, e := Open("sqlite", filepath.Join(t.TempDir(), "upgrade.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	ctx := t.Context()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	provider, e := goose.NewProvider(goose.DialectSQLite3, s.DB, migrationFS())
	must(e)
	_, e = provider.UpTo(ctx, 36)
	must(e)
	for _, q := range []string{
		"INSERT INTO vlan_catalog VALUES(100,'Guest')",
		"INSERT INTO network_segments VALUES('guests','Guests')",
		"INSERT INTO authentication_policies(id,name,source,steps) VALUES('auth','OIDC','oidc','[\"primary\"]')",
		"INSERT INTO access_policies(id,name,authentication_id,mode,segment_id,session_seconds) VALUES('access','Access','auth','network','guests',600)",
		"INSERT INTO nas(address,name,secret,access_policy_id,portal_enabled) VALUES('192.0.2.1','NAS','test-secret-123456','access',1)",
		"INSERT INTO nas_segments VALUES('192.0.2.1','guests',100)",
		"UPDATE guest_policy SET enabled=1,vlan=100",
	} {
		must(s.Exec(ctx, q))
	}
	user := "oidc:" + strings.Repeat("a", 64)
	must(s.Exec(ctx, "INSERT INTO policy_subjects VALUES('access',?)", user))
	d := DefaultPortalDesign()
	d.Custom = true
	d.SSOEnabled = true
	d.SSOProviders = []string{"oidc"}
	must(s.SavePortalDesign(ctx, "tenant", d))
	config, _ := json.Marshal(OIDCProvider{Scope: "tenant", ID: "oidc", Name: "OIDC", Issuer: "https://idp.example", ClientID: "border", Enabled: true, AccessPolicyID: "access"})
	must(s.Exec(ctx, "INSERT INTO guest_oidc_providers(scope,id,config,revision) VALUES('tenant','oidc',?,'rev1')", string(config)))
	// Original schema-36 hash, with the exact field order and no new JSON fields.
	type oldAuth struct {
		ID, Name, Source, DomainID, EAPMethod string
		RequireTOTP, Enabled                  bool
		Steps                                 []string
	}
	old := struct {
		BindingID      string
		BindingVersion int64
		Authentication oldAuth
		Access         AccessPolicy
		VLAN           int
		Rules          RuleSet
	}{Authentication: oldAuth{ID: "auth", Name: "OIDC", Source: "oidc", Enabled: true, Steps: []string{"primary"}}, Access: AccessPolicy{ID: "access", Name: "Access", AuthenticationID: "auth", Mode: "network", SegmentID: "guests", SessionSeconds: 600, Enabled: true}, VLAN: 100, Rules: RuleSet{PolicyID: "access", Rules: []AccessRule{}}}
	raw, _ := json.Marshal(old)
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	expires := time.Now().Unix() + 400
	must(s.Exec(ctx, "INSERT INTO guest_oidc_sessions(id,nas,mac,identity,provider_scope,provider_id,provider_revision,policy_id,policy_hash,expires_at) VALUES('oidc-existing','192.0.2.1','02:00:00:00:00:01',?,'tenant','oidc','rev1','access',?,?)", user, hash, expires))
	must(s.Exec(ctx, "INSERT INTO access_grants(token,nas,username,policy_id,expires_at,guest_oidc_id) VALUES('oidc-class','192.0.2.1',?,'access',?,'oidc-existing')", user, expires))
	must(s.Exec(ctx, "INSERT INTO guest_sessions VALUES('192.0.2.1','02:00:00:00:00:02','+7***67',100,?)", expires))
	must(s.Exec(ctx, "INSERT INTO access_grants(token,nas,username,policy_id,expires_at) VALUES('legacy-class','192.0.2.1','02:00:00:00:00:02','',?)", expires))
	must(s.Exec(ctx, "INSERT INTO guest_challenges(id,nas,mac,session_id,phone_hash,phone_cipher,code_digest,created_at,expires_at) VALUES('legacy-code','192.0.2.1','02:00:00:00:00:02','','hash','cipher','code',0,?)", expires))
	must(s.Migrate(ctx))
	g, e := s.GuestAuthorization(ctx, "192.0.2.1", "02:00:00:00:00:01")
	must(e)
	if g.ID != "oidc-existing" || g.Method != "oidc" || g.Expires != expires {
		t.Fatal(g)
	}
	if _, e = s.GuestAccessPolicy(ctx, g.NAS, g.MAC, "", "sms"); e == nil {
		t.Fatal("legacy OIDC policy widened")
	}
	var oldReason, newReason, digest string
	var count int
	must(s.Row(ctx, "SELECT reason FROM access_grants WHERE token='legacy-class'").Scan(&oldReason))
	must(s.Row(ctx, "SELECT reason FROM access_grants WHERE token='oidc-class'").Scan(&newReason))
	must(s.Row(ctx, "SELECT code_digest FROM guest_challenges WHERE id='legacy-code'").Scan(&digest))
	must(s.Row(ctx, "SELECT count(*) FROM guest_sessions").Scan(&count))
	if oldReason == "" || newReason != "" || digest != "" || count != 0 {
		t.Fatal("unsafe migration", oldReason, newReason, count)
	}
}

func TestGuestMethodsDraftPublicationRoundTrip(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	a := AuthenticationPolicy{ID: "portal", Name: "Guest portal", Source: "guest", Enabled: true, GuestMethods: []string{"sms", "email"}}
	raw, _ := json.Marshal(a)
	if e := s.SavePolicyDraft(ctx, PolicyDraft{Kind: "authentication", PolicyID: a.ID, Payload: raw}, "admin"); e != nil {
		t.Fatal(e)
	}
	if e := s.PublishPolicyDraft(ctx, "authentication", a.ID, 1, "admin"); e != nil {
		t.Fatal(e)
	}
	list, e := s.Authentications(ctx)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, p := range list {
		if p.ID == a.ID {
			found = true
			if !reflect.DeepEqual(p.GuestMethods, a.GuestMethods) {
				t.Fatal(p)
			}
		}
	}
	if !found {
		t.Fatal("published policy missing")
	}
	a.GuestMethods = []string{"sms", "sms"}
	if e = s.SaveAuthentication(ctx, a); e == nil {
		t.Fatal("duplicate method allowed")
	}
	a.GuestMethods = []string{"sms"}
	a.Steps = []string{"primary", "totp"}
	if e = s.SaveAuthentication(ctx, a); e == nil {
		t.Fatal("unimplemented guest factor allowed")
	}
}
