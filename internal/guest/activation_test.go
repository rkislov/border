package guest

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rkislov/border/internal/store"
)

func TestActivationWorkerLeaseAndReplacement(t *testing.T) {
	s, _, token := fixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s.Activate = func(context.Context, store.GuestAuthorization, int) (bool, error) {
		calls.Add(1)
		close(entered)
		<-release
		return true, nil
	}
	grant, e := confirmContact(t, s, token, "sms", "+79991234567")
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- s.ProcessActivations(t.Context()) }()
	<-entered
	// A second worker must not send while the first owns the persisted lease.
	e = s.ProcessActivations(t.Context())
	// Revocation while the external command runs must not be undone by its result.
	revokeErr := s.Store.RevokeGuest(t.Context(), "192.0.2.1", "00:11:22:33:44:55")
	close(release)
	workerErr := <-done
	if e != nil || revokeErr != nil || workerErr != nil || calls.Load() != 1 {
		t.Fatal(e, revokeErr, workerErr, calls.Load())
	}
	if _, e = s.ActivationStatus(t.Context(), grant.StatusToken); e == nil {
		t.Fatal("revocation undone by worker")
	}
}

func TestActivationAllGuestMethodsRequireAccounting(t *testing.T) {
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
			must(s.Store.SaveAuthentication(ctx, store.AuthenticationPolicy{ID: "oidc", Name: "Guests", Source: "guest", GuestMethods: []string{"sms", "email", "oidc"}, Enabled: true}))
			d, _ := s.Store.PortalDesign(ctx, "tenant")
			d.LoginMethod = "both"
			must(s.Store.SavePortalDesign(ctx, "tenant", d))
			calls := 0
			s.Activate = func(_ context.Context, g store.GuestAuthorization, vlan int) (bool, error) {
				calls++
				if g.Method != method || vlan != 100 {
					t.Fatal("wrong activation target")
				}
				return true, nil
			}
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
			if grant.ReconnectRequired || grant.ActivationState != "pending" {
				t.Fatal(grant)
			}
			must(s.ProcessActivations(ctx))
			status, e := s.ActivationStatus(ctx, grant.StatusToken)
			must(e)
			if status.State != "awaiting_accounting" || calls != 1 {
				t.Fatal(status, calls)
			}
			// An old or unrelated session must not count as proof of the new login.
			must(s.Store.Accounting(ctx, "192.0.2.1", "unrelated", "00:11:22:33:44:55", "00:11:22:33:44:55", "active"))
			status, e = s.ActivationStatus(ctx, grant.StatusToken)
			must(e)
			if status.State == "active" {
				t.Fatal("unlinked session confirmed access")
			}
			g, e := s.Store.GuestAuthorization(ctx, "192.0.2.1", "00:11:22:33:44:55")
			must(e)
			b, e := s.Store.GuestAccessPolicy(ctx, g.NAS, g.MAC, g.DomainID, method)
			must(e)
			class, e := s.Store.NewGuestGrant(ctx, g, b, g.Expires)
			must(e)
			must(s.Store.ApplyAccounting(ctx, store.AccountingEvent{NAS: g.NAS, MAC: g.MAC, Username: g.MAC, ID: "new-session", Kind: "start", At: time.Now().Unix(), Classes: []string{class}}))
			status, e = s.ActivationStatus(ctx, grant.StatusToken)
			must(e)
			if status.State != "active" {
				t.Fatal(status)
			}
			must(s.Store.Exec(ctx, "UPDATE guest_authorizations SET activation_next=0"))
			must(s.ProcessActivations(ctx))
			if calls != 1 {
				t.Fatal("duplicate NAS command after Accounting")
			}
			must(s.Store.RevokeGuest(ctx, g.NAS, g.MAC, g.ID))
			if _, e = s.ActivationStatus(ctx, grant.StatusToken); e == nil {
				t.Fatal("revoked receipt accepted")
			}
		})
	}
}
func TestActivationRetriesRestartAndReceipts(t *testing.T) {
	s, _, token := fixture(t)
	ctx := t.Context()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	calls := 0
	adapter := func(context.Context, store.GuestAuthorization, int) (bool, error) {
		calls++
		return true, errors.New("private management failure")
	}
	s.Activate = adapter
	grant, e := confirmContact(t, s, token, "sms", "+79991234567")
	must(e)
	must(s.ProcessActivations(ctx))
	if calls != 1 {
		t.Fatal(calls)
	}
	must(s.ProcessActivations(ctx))
	if calls != 1 {
		t.Fatal("lease ignored")
	}
	restarted, e := New(s.Store, make([]byte, 32))
	must(e)
	restarted.Activate = adapter
	for i := 0; i < 5; i++ {
		must(s.Store.Exec(ctx, "UPDATE guest_authorizations SET activation_next=0"))
		must(restarted.ProcessActivations(ctx))
	}
	status, e := restarted.ActivationStatus(ctx, grant.StatusToken)
	must(e)
	if status.State != "failed" || status.Attempts != 5 || calls != 5 {
		t.Fatal(status, calls)
	}
	if _, e = restarted.ActivationStatus(ctx, grant.StatusToken+"x"); e == nil {
		t.Fatal("forged receipt")
	}
	other, e := New(s.Store, []byte(strings.Repeat("z", 32)))
	must(e)
	if _, e = other.ActivationStatus(ctx, grant.StatusToken); e == nil {
		t.Fatal("cross tenant receipt")
	}
	var logs string
	must(s.Store.Row(ctx, "SELECT reason FROM auth_log WHERE source='guest-activation' LIMIT 1").Scan(&logs))
	if strings.Contains(logs, "private") {
		t.Fatal("raw adapter error leaked")
	}
}
func TestActivationDoesNotSendAfterPolicyChange(t *testing.T) {
	s, _, token := fixture(t)
	ctx := t.Context()
	called := false
	s.Activate = func(context.Context, store.GuestAuthorization, int) (bool, error) { called = true; return true, nil }
	grant, e := confirmContact(t, s, token, "sms", "+79991234567")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Store.Exec(ctx, "UPDATE access_policies SET enabled=0"); e != nil {
		t.Fatal(e)
	}
	if e = s.ProcessActivations(ctx); e != nil {
		t.Fatal(e)
	}
	if called {
		t.Fatal("NAS called for disabled policy")
	}
	if _, e = s.ActivationStatus(ctx, grant.StatusToken); e == nil {
		t.Fatal("stale permission survived")
	}
}
