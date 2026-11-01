package guest

import (
	"context"
	"errors"
	"github.com/rkislov/border/internal/store"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeSMS struct {
	code  string
	fail  bool
	calls int
}

func (f *fakeSMS) Send(_ context.Context, _, text string) error {
	f.calls++
	f.code = strings.TrimSuffix(strings.Fields(text)[3], ".")
	if f.fail {
		return errors.New("delivery failure")
	}
	return nil
}
func fixture(t *testing.T) (*Service, *fakeSMS, string) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "guest.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.DB.Close() })
	if err = db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"INSERT INTO vlan_catalog VALUES(100,'guest')", "INSERT INTO nas(address,name,secret,portal_enabled) VALUES('192.0.2.1','test','long-test-secret-123',1)", "UPDATE guest_policy SET enabled=1,vlan=100 WHERE id=1"} {
		if err = db.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.Exec(ctx, "INSERT INTO network_segments VALUES('contact-network','Guest contacts')"); err != nil {
		t.Fatal(err)
	}
	if err = db.SaveAuthentication(ctx, store.AuthenticationPolicy{ID: "contact-auth", Name: "Guest contacts", Source: "guest", GuestMethods: []string{"sms", "email", "oidc"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err = db.SaveAccess(ctx, store.AccessPolicy{ID: "contact-access", Name: "Guest access", AuthenticationID: "contact-auth", Mode: "network", SegmentID: "contact-network", SessionSeconds: 3600, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err = db.SaveMapping(ctx, store.SegmentMapping{NAS: "192.0.2.1", SegmentID: "contact-network", VLAN: 100}); err != nil {
		t.Fatal(err)
	}
	if err = db.SaveRules(ctx, store.RuleSet{PolicyID: "contact-access", Enabled: true, Rules: []store.AccessRule{{ID: "guests", Name: "Guests", Effect: "allow", Enabled: true, AllAuthenticated: true}}}); err != nil {
		t.Fatal(err)
	}
	if err = db.Exec(ctx, "UPDATE nas SET access_policy_id='contact-access' WHERE address='192.0.2.1'"); err != nil {
		t.Fatal(err)
	}
	s, err := New(db, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMS{}
	s.SMS = f
	token, err := SignRedirect(Redirect{NAS: "192.0.2.1", MAC: "00:11:22:33:44:55"}, "long-test-secret-123")
	if err != nil {
		t.Fatal(err)
	}
	return s, f, token
}
func TestGuestGrantBindingReplayAndPrivacy(t *testing.T) {
	s, f, token := fixture(t)
	ctx := context.Background()
	c, err := s.Request(ctx, token, "+79991234567")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c.MaskedPhone, "999123") {
		t.Fatal("unmasked phone")
	}
	var cipher, digest string
	if err = s.Store.Row(ctx, "SELECT phone_cipher,code_digest FROM guest_challenges WHERE id=?", c.ID).Scan(&cipher, &digest); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cipher, "79991234567") || digest == f.code {
		t.Fatal("plaintext secret")
	}
	if _, err = s.Request(ctx, token, "+79991234567"); err == nil {
		t.Fatal("resend not limited")
	}
	g, err := s.Confirm(ctx, c.ID, f.code)
	if err != nil || g.VLAN != 100 {
		t.Fatalf("grant: %+v %v", g, err)
	}
	if _, err = s.Confirm(ctx, c.ID, f.code); err == nil {
		t.Fatal("replay")
	}
	if _, err = s.Store.GuestAuthorization(ctx, "192.0.2.1", "00:11:22:33:44:55"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Store.GuestAuthorization(ctx, "192.0.2.2", "00:11:22:33:44:55"); err == nil {
		t.Fatal("cross-NAS grant")
	}
}
func TestGuestFailures(t *testing.T) {
	for _, mode := range []string{"attempts", "expiry", "blocked", "disabled", "delivery", "signature"} {
		t.Run(mode, func(t *testing.T) {
			s, f, token := fixture(t)
			ctx := context.Background()
			if mode == "signature" {
				token += "x"
			}
			if mode == "delivery" {
				f.fail = true
			}
			c, err := s.Request(ctx, token, "+79991234567")
			if mode == "signature" || mode == "delivery" {
				if err == nil {
					t.Fatal("accepted invalid request")
				}
				var n int
				s.Store.Row(ctx, "SELECT COUNT(*) FROM guest_authorizations").Scan(&n)
				if n != 0 {
					t.Fatal("unexpected grant")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "attempts":
				wrong := "000000"
				if f.code == wrong {
					wrong = "111111"
				}
				for i := 0; i < 5; i++ {
					if _, err = s.Confirm(ctx, c.ID, wrong); err == nil {
						t.Fatal("bad code accepted")
					}
				}
				err = nil
			case "expiry":
				err = s.Store.Exec(ctx, "UPDATE guest_challenges SET expires_at=?", time.Now().Unix()-1)
			case "blocked":
				err = s.Store.Exec(ctx, "INSERT INTO mac_auth(mac,active) VALUES('00:11:22:33:44:55',0)")
			case "disabled":
				err = s.Store.Exec(ctx, "UPDATE nas SET portal_enabled=0")
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Confirm(ctx, c.ID, f.code); err == nil {
				t.Fatal("invalid grant")
			}
		})
	}
}
