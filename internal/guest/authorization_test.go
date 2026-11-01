package guest

import (
	"context"
	"encoding/json"
	"github.com/rkislov/border/internal/store"
	"strings"
	"sync"
	"testing"
	"time"
)

func confirmContact(t *testing.T, s *Service, token, method, contact string) (Grant, error) {
	t.Helper()
	code := ""
	if method == "email" {
		s.SendEmail = func(_ context.Context, _, _, _, body string) error {
			code = strings.TrimSuffix(strings.Fields(body)[3], ".")
			return nil
		}
	}
	challenge, e := s.RequestContact(t.Context(), token, method, contact)
	if e != nil {
		return Grant{}, e
	}
	if method == "sms" {
		code = s.SMS.(*fakeSMS).code
	}
	return s.Confirm(t.Context(), challenge.ID, code)
}

func TestUnifiedGuestMethodsPolicyVLANExpiryAndRevocation(t *testing.T) {
	for _, method := range []string{"sms", "email", "oidc"} {
		t.Run(method, func(t *testing.T) {
			s, idp, token := oidcFixture(t)
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			must(s.Store.SaveAuthentication(ctx, store.AuthenticationPolicy{ID: "oidc", Name: "All guest methods", Source: "guest", GuestMethods: []string{"sms", "email", "oidc"}, Enabled: true}))
			d, _ := s.Store.PortalDesign(ctx, "tenant")
			d.LoginMethod = "both"
			must(s.Store.SavePortalDesign(ctx, "tenant", d))
			must(s.Store.Exec(ctx, "INSERT INTO locations VALUES('branch','Branch')"))
			must(s.Store.Exec(ctx, "UPDATE nas SET location_id='branch'"))
			must(s.Store.Exec(ctx, "DELETE FROM nas_segments WHERE segment_id='guest'"))
			must(s.Store.SaveMapping(ctx, store.SegmentMapping{LocationID: "branch", SegmentID: "guest", VLAN: 222}))
			end := time.Now().Unix() + 90
			must(s.Store.Exec(ctx, "UPDATE access_policies SET valid_until=? WHERE id='guest'", end))
			// Legacy settings cannot broaden the selected policy.
			must(s.Store.Exec(ctx, "UPDATE guest_policy SET session_seconds=86400,vlan=100"))
			var grant Grant
			var e error
			if method == "oidc" {
				start, state := startOIDCTest(t, s, idp, token)
				grant, e = s.FinishOIDC(ctx, state, start.BrowserBinding, "good-code", "")
			} else {
				contact := "+79991234567"
				if method == "email" {
					contact = "alice@example.org"
				}
				grant, e = confirmContact(t, s, token, method, contact)
			}
			must(e)
			if grant.VLAN != 222 || grant.Expires > end || !grant.ReconnectRequired {
				t.Fatal(grant)
			}
			g, e := s.Store.GuestAuthorization(ctx, "192.0.2.1", "00:11:22:33:44:55")
			must(e)
			if g.Method != method || g.PolicyID != "guest" || g.Identity == "" || strings.Contains(g.Identity, "alice@example.org") {
				t.Fatal(g)
			}
			b, e := s.Store.GuestAccessPolicy(ctx, g.NAS, g.MAC, "", method)
			must(e)
			class, e := s.Store.NewGuestGrant(ctx, g, b, g.Expires)
			must(e)
			must(s.Store.ApplyAccounting(ctx, store.AccountingEvent{NAS: g.NAS, MAC: g.MAC, ID: "guest-session", Username: g.MAC, Kind: "start", At: time.Now().Unix(), Classes: []string{class}}))
			must(s.Store.Exec(ctx, "UPDATE access_policies SET valid_until=? WHERE id='guest'", time.Now().Unix()-1))
			must(s.Store.RefreshRevocations(ctx))
			var reason string
			must(s.Store.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", class).Scan(&reason))
			if reason == "" {
				t.Fatal("expiry did not trigger revocation")
			}
			if _, e = s.Store.GuestAuthorization(ctx, g.NAS, g.MAC); e == nil {
				t.Fatal("expired grant survived")
			}
		})
	}
}

func TestGuestCodesRecheckPolicyDomainAndAllowedMethod(t *testing.T) {
	for _, change := range []string{"methods", "expiry", "rules", "domain", "binding", "global-toggle", "publication"} {
		t.Run(change, func(t *testing.T) {
			s, sender, token := fixture(t)
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			if change == "domain" {
				must(s.Store.Exec(ctx, "INSERT INTO domains(id,name,config) VALUES('corp','Corp','')"))
				token, _ = SignRedirect(Redirect{NAS: "192.0.2.1", MAC: "00:11:22:33:44:55", Domain: "corp"}, "long-test-secret-123")
			}
			c, e := s.Request(ctx, token, "+79991234567")
			must(e)
			switch change {
			case "methods":
				must(s.Store.Exec(ctx, "UPDATE authentication_policies SET guest_methods='[\"email\"]' WHERE id='contact-auth'"))
			case "expiry":
				must(s.Store.Exec(ctx, "UPDATE access_policies SET valid_until=? WHERE id='contact-access'", time.Now().Unix()-1))
			case "rules":
				must(s.Store.Exec(ctx, "DELETE FROM access_rule_sets"))
			case "domain":
				must(s.Store.Exec(ctx, "UPDATE domains SET enabled=0"))
			case "binding":
				must(s.Store.Exec(ctx, "UPDATE nas SET access_policy_id=NULL"))
			case "global-toggle":
				must(s.Store.SetGuestPolicy(ctx, store.GuestPolicy{MaxPerHour: 1000}))
				must(s.Store.SetGuestPolicy(ctx, store.GuestPolicy{Enabled: true, MaxPerHour: 1000}))
			case "publication":
				policies, _ := s.Store.Accesses(ctx)
				p := policies[0]
				p.SessionSeconds = 600
				raw, _ := json.Marshal(p)
				must(s.Store.SavePolicyDraft(ctx, store.PolicyDraft{Kind: "access", PolicyID: p.ID, Payload: raw}, "admin"))
				must(s.Store.PublishPolicyDraft(ctx, "access", p.ID, 1, "admin"))
			}
			if _, e = s.Confirm(ctx, c.ID, sender.code); e == nil {
				t.Fatal("stale challenge accepted")
			}
			var count int
			must(s.Store.Row(ctx, "SELECT count(*) FROM guest_authorizations").Scan(&count))
			if count != 0 {
				t.Fatal("unauthorized guest record")
			}
		})
	}
}

func TestGuestMethodSwitchReplacesOnlySameDeviceAndStaleRevokeIsSafe(t *testing.T) {
	s, _, token := fixture(t)
	ctx := t.Context()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	d := store.DefaultPortalDesign()
	d.Custom = true
	d.LoginMethod = "both"
	must(s.Store.SavePortalDesign(ctx, "tenant", d))
	_, e := confirmContact(t, s, token, "sms", "+79991234567")
	must(e)
	first, e := s.Store.GuestAuthorization(ctx, "192.0.2.1", "00:11:22:33:44:55")
	must(e)
	b, e := s.Store.GuestAccessPolicy(ctx, first.NAS, first.MAC, "", "sms")
	must(e)
	class, e := s.Store.NewGuestGrant(ctx, first, b, first.Expires)
	must(e)
	other := first
	other.ID = randomID()
	other.MAC = "02:00:00:00:00:02"
	must(s.Store.SaveGuestAuthorization(ctx, other))
	otherClass, e := s.Store.NewGuestGrant(ctx, other, b, other.Expires)
	must(e)
	must(s.Store.Exec(ctx, "UPDATE guest_challenges SET created_at=created_at-901"))
	_, e = confirmContact(t, s, token, "email", "alice@example.org")
	must(e)
	current, e := s.Store.GuestAuthorization(ctx, first.NAS, first.MAC)
	must(e)
	if current.ID == first.ID || current.Method != "email" {
		t.Fatal(current)
	}
	must(s.Store.RevokeGuest(ctx, first.NAS, first.MAC, first.ID))
	if got, e := s.Store.GuestAuthorization(ctx, first.NAS, first.MAC); e != nil || got.ID != current.ID {
		t.Fatal("stale revoke removed new login", e)
	}
	var reason, unrelated string
	must(s.Store.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", class).Scan(&reason))
	must(s.Store.Row(ctx, "SELECT reason FROM access_grants WHERE token=?", otherClass).Scan(&unrelated))
	if reason == "" || unrelated != "" {
		t.Fatal("wrong session revoked", reason, unrelated)
	}
	must(s.Store.SetGuestPolicy(ctx, store.GuestPolicy{MaxPerHour: 1000}))
	must(s.Store.SetGuestPolicy(ctx, store.GuestPolicy{Enabled: true, MaxPerHour: 1000}))
	if _, e = s.Store.GuestAuthorization(ctx, current.NAS, current.MAC); e == nil {
		t.Fatal("global re-enable restored permission")
	}
}

func TestGuestCodeConcurrentConfirmation(t *testing.T) {
	s, sender, token := fixture(t)
	c, e := s.Request(t.Context(), token, "+79991234567")
	if e != nil {
		t.Fatal(e)
	}
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := s.Confirm(t.Context(), c.ID, sender.code); results <- e }()
	}
	wg.Wait()
	close(results)
	accepted := 0
	for e := range results {
		if e == nil {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d times", accepted)
	}
}

func TestGuestPublicationAndRollbackDoNotResurrectAuthorization(t *testing.T) {
	s, _, token := fixture(t)
	ctx := t.Context()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	_, e := confirmContact(t, s, token, "sms", "+79991234567")
	must(e)
	first, e := s.Store.GuestAuthorization(ctx, "192.0.2.1", "00:11:22:33:44:55")
	must(e)
	policies, e := s.Store.Accesses(ctx)
	must(e)
	p := policies[0]
	otherPolicy := p
	otherPolicy.ID = "other-policy"
	must(s.Store.SaveAccess(ctx, otherPolicy))
	must(s.Store.SaveRules(ctx, store.RuleSet{PolicyID: otherPolicy.ID, Enabled: true, Rules: []store.AccessRule{{ID: "allow", Name: "Guests", Effect: "allow", Enabled: true, AllAuthenticated: true}}}))
	must(s.Store.Exec(ctx, "INSERT INTO nas(address,name,secret,portal_enabled,access_policy_id) VALUES('192.0.2.2','Other','long-test-secret-123',1,'other-policy')"))
	must(s.Store.SaveMapping(ctx, store.SegmentMapping{NAS: "192.0.2.2", SegmentID: p.SegmentID, VLAN: 100}))
	other := first
	other.ID, other.NAS, other.PolicyID = randomID(), "192.0.2.2", otherPolicy.ID
	b, e := s.Store.GuestAccessPolicy(ctx, other.NAS, other.MAC, "", "sms")
	must(e)
	other.PolicyHash = store.GuestPolicyHash(b)
	must(s.Store.SaveGuestAuthorization(ctx, other))
	// Neither authorization has reached RADIUS/Accounting yet.
	p.SessionSeconds = 900
	raw, _ := json.Marshal(p)
	must(s.Store.SavePolicyDraft(ctx, store.PolicyDraft{Kind: "access", PolicyID: p.ID, Payload: raw}, "admin"))
	must(s.Store.PublishPolicyDraft(ctx, "access", p.ID, 1, "admin"))
	var release string
	must(s.Store.Row(ctx, "SELECT id FROM policy_releases WHERE kind='access' AND policy_id=?", p.ID).Scan(&release))
	must(s.Store.RollbackPolicyDraft(ctx, release, "admin"))
	drafts, e := s.Store.PolicyDrafts(ctx)
	must(e)
	if len(drafts) != 1 {
		t.Fatal("missing rollback draft")
	}
	must(s.Store.PublishPolicyDraft(ctx, "access", p.ID, drafts[0].Revision, "admin"))
	if _, e = s.Store.GuestAuthorization(ctx, first.NAS, first.MAC); e == nil {
		t.Fatal("rollback resurrected guest authorization")
	}
	if g, e := s.Store.GuestAuthorization(ctx, other.NAS, other.MAC); e != nil || g.ID != other.ID {
		t.Fatal("unrelated policy lost authorization", e)
	}
}
