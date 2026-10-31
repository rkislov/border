package guest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rkislov/border/internal/store"
)

type testOIDC struct {
	server           *httptest.Server
	key              *rsa.PrivateKey
	claims           jwt.MapClaims
	nonce, challenge string
	mu               sync.Mutex
	exchanges        int
	wrongKey         bool
}

func oidcFixture(t *testing.T) (*Service, *testOIDC, string) {
	t.Helper()
	s, _, token := fixture(t)
	s.PublicURL = "https://border.example/portal/default"
	for _, q := range []string{
		"INSERT INTO network_segments(id,name) VALUES('guest','Guest')",
		"INSERT INTO authentication_policies(id,name,source,steps) VALUES('oidc','OIDC','oidc','[\"primary\"]')",
		"INSERT INTO access_policies(id,name,authentication_id,mode,segment_id,session_seconds) VALUES('guest','Guest','oidc','network','guest',600)",
		"INSERT INTO nas_segments(nas,segment_id,vlan) VALUES('192.0.2.1','guest',100)",
		"UPDATE nas SET access_policy_id='guest' WHERE address='192.0.2.1'",
	} {
		if err := s.Store.Exec(t.Context(), q); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Store.SaveRules(t.Context(), store.RuleSet{PolicyID: "guest", Enabled: true, Rules: []store.AccessRule{{ID: "guests", Name: "Guests", Effect: "allow", Enabled: true, AllAuthenticated: true}}}); err != nil {
		t.Fatal(err)
	}
	d := store.DefaultPortalDesign()
	d.Custom = true
	d.SSOEnabled = true
	d.SSOProviders = []string{"oidc"}
	if err := s.Store.SavePortalDesign(t.Context(), "tenant", d); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &testOIDC{key: key, claims: jwt.MapClaims{}}
	idp.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": idp.server.URL, "authorization_endpoint": idp.server.URL + "/authorize", "token_endpoint": idp.server.URL + "/token", "jwks_uri": idp.server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "key1", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
		case "/token":
			idp.mu.Lock()
			defer idp.mu.Unlock()
			idp.exchanges++
			if r.ParseForm() != nil {
				http.Error(w, "bad form", 400)
				return
			}
			client, secret, _ := r.BasicAuth()
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if client != "border" || secret != "private-secret" || r.Form.Get("code") != "good-code" || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != "https://border.example/portal/default/api/guest/oidc/callback" || base64.RawURLEncoding.EncodeToString(sum[:]) != idp.challenge {
				http.Error(w, "invalid grant", 400)
				return
			}
			claims := jwt.MapClaims{"iss": idp.server.URL, "sub": "user-123", "aud": "border", "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(), "nonce": idp.nonce, "email": "guest@example.org", "email_verified": true}
			for k, v := range idp.claims {
				claims[k] = v
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "key1"
			signer := idp.key
			if idp.wrongKey {
				signer, _ = rsa.GenerateKey(rand.Reader, 2048)
			}
			signed, e := token.SignedString(signer)
			if e != nil {
				t.Error(e)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-token", "token_type": "Bearer", "expires_in": 300, "id_token": signed})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.server.Close)
	s.oidcTestClient = idp.server.Client()
	c := OIDCConfiguration{OIDCProvider: store.OIDCProvider{Scope: "tenant", ID: "oidc", Name: "Test SSO", Issuer: idp.server.URL, ClientID: "border", AccessPolicyID: "guest", AuthStyle: "basic", Enabled: true, AllowPrivateNetwork: true}, ClientSecret: "private-secret"}
	if err = s.SaveOIDCProvider(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	return s, idp, token
}
func startOIDCTest(t *testing.T, s *Service, idp *testOIDC, token string) (OIDCStart, string) {
	t.Helper()
	start, e := s.StartOIDC(t.Context(), token, "oidc")
	if e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(start.URL)
	if e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" || q.Get("nonce") == "" {
		t.Fatal("PKCE/nonce missing")
	}
	idp.mu.Lock()
	idp.challenge = q.Get("code_challenge")
	idp.nonce = q.Get("nonce")
	idp.mu.Unlock()
	return start, q.Get("state")
}
func TestOIDCCodeFlowPolicyAndReplay(t *testing.T) {
	s, idp, token := oidcFixture(t)
	design, e := s.Design(t.Context(), token)
	if e != nil || len(design.OIDC) != 1 {
		t.Fatalf("design %+v %v", design, e)
	}
	start, state := startOIDCTest(t, s, idp, token)
	if _, e = s.FinishOIDC(t.Context(), state, strings.Repeat("f", 64), "good-code", ""); e == nil {
		t.Fatal("foreign browser accepted")
	}
	grant, e := s.FinishOIDC(t.Context(), state, start.BrowserBinding, "good-code", "")
	if e != nil {
		t.Fatal(e)
	}
	if grant.VLAN != 100 || grant.Expires > time.Now().Unix()+301 || !grant.ReconnectRequired {
		t.Fatal(grant)
	}
	g, e := s.Store.GuestOIDCSession(t.Context(), "192.0.2.1", "00:11:22:33:44:55")
	if e != nil {
		t.Fatal(e)
	}
	if g.Identity != OIDCIdentity(idp.server.URL, "user-123") || strings.Contains(g.Identity, "guest@example.org") {
		t.Fatal(g)
	}
	if _, e = s.FinishOIDC(t.Context(), state, start.BrowserBinding, "good-code", ""); e == nil {
		t.Fatal("replay accepted")
	}
	if idp.exchanges != 1 {
		t.Fatal("extra token exchange")
	}
	b, _, _ := s.Store.GuestOIDCPolicy(t.Context(), g.NAS, g.MAC, "", "oidc")
	access, e := s.Store.NewGuestOIDCGrant(t.Context(), g, b, g.Expires)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Store.Exec(t.Context(), "UPDATE access_policies SET enabled=0 WHERE id='guest'"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Store.GuestOIDCSession(t.Context(), g.NAS, g.MAC); e == nil {
		t.Fatal("disabled policy accepted")
	}
	if e = s.Store.RefreshRevocations(t.Context()); e != nil {
		t.Fatal(e)
	}
	var reason string
	if e = s.Store.Row(t.Context(), "SELECT reason FROM access_grants WHERE token=?", access).Scan(&reason); e != nil || reason == "" {
		t.Fatalf("revocation %q %v", reason, e)
	}
}
func TestOIDCRejectsInvalidIdentityTokens(t *testing.T) {
	cases := map[string]jwt.MapClaims{
		"issuer": {"iss": "https://wrong.example"}, "audience": {"aud": "another-client"}, "nonce": {"nonce": "wrong"}, "expired": {"exp": time.Now().Unix() - 1}, "future-issued": {"iat": time.Now().Unix() + 1000}, "no-issued": {"iat": 0}, "empty-sub": {"sub": ""}, "azp": {"azp": "another"}, "multi-audience": {"aud": []string{"border", "other"}}, "signature": {}, "email-unverified": {"email_verified": false}, "email-domain": {"email": "guest@evil.example"}, "hash": {"at_hash": "bad"},
	}
	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			s, idp, token := oidcFixture(t)
			idp.claims = claims
			idp.wrongKey = name == "signature"
			if strings.HasPrefix(name, "email-") {
				providers, _ := s.Store.OIDCProviders(t.Context(), "tenant")
				c := OIDCConfiguration{OIDCProvider: providers[0]}
				c.EmailDomains = []string{"example.org"}
				if e := s.SaveOIDCProvider(t.Context(), c); e != nil {
					t.Fatal(e)
				}
			}
			start, state := startOIDCTest(t, s, idp, token)
			if _, e := s.FinishOIDC(t.Context(), state, start.BrowserBinding, "good-code", ""); e == nil {
				t.Fatal("invalid token accepted")
			}
			var n int
			_ = s.Store.Row(t.Context(), "SELECT count(*) FROM guest_oidc_sessions").Scan(&n)
			if n != 0 {
				t.Fatal("grant after rejected token")
			}
		})
	}
}
func TestOIDCFlowInvalidatedAndScopes(t *testing.T) {
	for _, change := range []string{"provider", "policy", "binding", "domain", "design", "blocked", "expired-flow", "restart", "registered-device", "deny-rule"} {
		t.Run(change, func(t *testing.T) {
			s, idp, token := oidcFixture(t)
			if change == "domain" {
				if e := s.Store.Exec(t.Context(), "INSERT INTO domains(id,name,config) VALUES('corp','Corp','')"); e != nil {
					t.Fatal(e)
				}
				token, _ = SignRedirect(Redirect{NAS: "192.0.2.1", MAC: "00:11:22:33:44:55", Domain: "corp"}, "long-test-secret-123")
			}
			start, state := startOIDCTest(t, s, idp, token)
			var e error
			switch change {
			case "provider":
				list, _ := s.Store.OIDCProviders(t.Context(), "tenant")
				c := OIDCConfiguration{OIDCProvider: list[0]}
				c.Enabled = false
				e = s.SaveOIDCProvider(t.Context(), c)
			case "policy":
				e = s.Store.Exec(t.Context(), "UPDATE access_policies SET session_seconds=120 WHERE id='guest'")
			case "binding":
				e = s.Store.Exec(t.Context(), "UPDATE nas SET access_policy_id=NULL")
			case "domain":
				e = s.Store.Exec(t.Context(), "UPDATE domains SET enabled=0")
			case "design":
				d := store.DefaultPortalDesign()
				d.Custom = true
				e = s.Store.SavePortalDesign(t.Context(), "nas:192.0.2.1", d)
			case "blocked":
				e = s.Store.Exec(t.Context(), "INSERT INTO identity_status(username,blocked,checked_at) VALUES(?,1,0)", OIDCIdentity(idp.server.URL, "user-123"))
			case "expired-flow":
				f := s.oidcFlows[state]
				f.expires = time.Now().Add(-time.Minute)
				s.oidcFlows[state] = f
			case "restart":
				s.oidcFlows = nil
			case "registered-device":
				e = s.Store.Exec(t.Context(), "INSERT INTO mac_auth(mac,vlan,active) VALUES('00:11:22:33:44:55',100,0)")
			case "deny-rule":
				e = s.Store.Exec(t.Context(), "DELETE FROM access_rule_sets")
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.FinishOIDC(t.Context(), state, start.BrowserBinding, "good-code", ""); e == nil {
				t.Fatal("changed authorization accepted")
			}
		})
	}
}
func TestOIDCProviderSecretsAndInheritance(t *testing.T) {
	s, idp, token := oidcFixture(t)
	list, e := s.Store.OIDCProviders(t.Context(), "tenant")
	if e != nil || len(list) != 1 || !list[0].HasSecret {
		t.Fatalf("list %v %v", list, e)
	}
	var encrypted, config string
	_ = s.Store.Row(t.Context(), "SELECT secret,config FROM guest_oidc_providers").Scan(&encrypted, &config)
	if strings.Contains(encrypted+config, "private-secret") {
		t.Fatal("plaintext credential")
	}
	c := OIDCConfiguration{OIDCProvider: list[0]}
	c.Scope = "nas:192.0.2.1"
	c.Revision = ""
	c.Enabled = false
	c.ClientSecret = ""
	if e = s.SaveOIDCProvider(t.Context(), c); e != nil {
		t.Fatal(e)
	}
	d, e := s.Design(t.Context(), token)
	if e != nil || len(d.OIDC) != 0 {
		t.Fatalf("disabled override %v %v", d, e)
	}
	if _, e = s.StartOIDC(t.Context(), token, "oidc"); e == nil {
		t.Fatal("override bypass")
	}
	c = listToConfig(list[0])
	c.ClientID = "new-client"
	if e = s.SaveOIDCProvider(t.Context(), c); e == nil {
		t.Fatal("secret reused for changed client")
	}
	c = listToConfig(list[0])
	c.Revision = "stale"
	if e = s.SaveOIDCProvider(t.Context(), c); e == nil {
		t.Fatal("lost update")
	}
	c = listToConfig(list[0])
	c.Issuer = "http://example.org"
	if e = s.SaveOIDCProvider(t.Context(), c); e == nil {
		t.Fatal("HTTP issuer")
	}
	_ = idp
}
func listToConfig(c store.OIDCProvider) OIDCConfiguration { return OIDCConfiguration{OIDCProvider: c} }
func TestOIDCHTTPBlocksPrivateNetwork(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "secret") }))
	defer server.Close()
	if _, e := newOIDCClient(false).Get(server.URL); e == nil || !strings.Contains(e.Error(), "private") {
		t.Fatalf("private endpoint allowed: %v", e)
	}
	if _, e := newOIDCClient(true).Get("http://example.org"); e == nil {
		t.Fatal("HTTP endpoint allowed")
	}
}

func TestOIDCCallbackConcurrentConsumption(t *testing.T) {
	s, idp, token := oidcFixture(t)
	start, state := startOIDCTest(t, s, idp, token)
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := s.FinishOIDC(t.Context(), state, start.BrowserBinding, "good-code", "")
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		}
	}
	if success != 1 || idp.exchanges != 1 {
		t.Fatalf("success %d exchanges %d", success, idp.exchanges)
	}
}

func TestOIDCRejectsCrossTenantAndDoesNotReplacePasswordPolicy(t *testing.T) {
	s, idp, token := oidcFixture(t)
	start, state := startOIDCTest(t, s, idp, token)
	other, _, _ := oidcFixture(t)
	if _, e := other.FinishOIDC(t.Context(), state, start.BrowserBinding, "good-code", ""); e == nil {
		t.Fatal("cross-tenant flow accepted")
	}
	if e := s.Store.Exec(t.Context(), "UPDATE authentication_policies SET source='local' WHERE id='oidc'"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.FinishOIDC(t.Context(), state, start.BrowserBinding, "good-code", ""); e == nil {
		t.Fatal("OIDC replaced password authentication")
	}
}
