// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package guest

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rkislov/border/internal/store"
	"golang.org/x/oauth2"
)

type oidcFlow struct {
	redirect                             Redirect
	config                               store.OIDCProvider
	policyHash, browser, nonce, verifier string
	expires                              time.Time
	provider                             *oidc.Provider
	oauth                                oauth2.Config
	client                               *http.Client
}
type OIDCStart struct {
	URL            string
	BrowserBinding string `json:"-"`
}

func (s *Service) StartOIDC(ctx context.Context, token, id string) (OIDCStart, error) {
	r, err := s.redirect(ctx, token)
	if err != nil {
		return OIDCStart{}, err
	}
	b, c, err := s.Store.GuestOIDCPolicy(ctx, r.NAS, r.MAC, r.Domain, id)
	if err != nil {
		return OIDCStart{}, err
	}
	callback, err := s.OIDCCallbackURL()
	if err != nil {
		return OIDCStart{}, err
	}
	state, browser := randomID(), randomID()
	f := oidcFlow{redirect: r, config: c, policyHash: store.GuestPolicyHash(b), browser: s.digest("oidc-browser", browser), nonce: randomID(), verifier: oauth2.GenerateVerifier(), expires: time.Now().Add(5 * time.Minute)}
	s.mu.Lock()
	if s.oidcFlows == nil {
		s.oidcFlows = map[string]oidcFlow{}
		s.oidcStarts = map[string]time.Time{}
	}
	for k, v := range s.oidcFlows {
		if time.Now().After(v.expires) {
			if v.client != nil {
				v.client.CloseIdleConnections()
			}
			delete(s.oidcFlows, k)
		}
	}
	for k, v := range s.oidcStarts {
		if time.Now().After(v) {
			delete(s.oidcStarts, k)
		}
	}
	key := r.NAS + "/" + r.MAC
	if len(s.oidcFlows) >= 1000 || len(s.oidcStarts) >= 10000 || !s.oidcStarts[key].IsZero() {
		s.mu.Unlock()
		return OIDCStart{}, fmt.Errorf("wait one minute before another login")
	}
	s.oidcStarts[key] = time.Now().Add(time.Minute)
	s.oidcFlows[state] = f
	s.mu.Unlock()
	succeeded := false
	defer func() {
		if !succeeded {
			s.mu.Lock()
			delete(s.oidcFlows, state)
			s.mu.Unlock()
		}
	}()
	client := newOIDCClient(c.AllowPrivateNetwork)
	defer func() {
		if !succeeded {
			client.CloseIdleConnections()
		}
	}()
	if s.oidcTestClient != nil {
		client = s.oidcTestClient
	} // package-private TLS fixture, never configurable through API
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return OIDCStart{}, fmt.Errorf("OIDC discovery unavailable")
	}
	endpoint := provider.Endpoint()
	var metadata struct {
		JWKS string `json:"jwks_uri"`
	}
	if provider.Claims(&metadata) != nil || oidcURL(metadata.JWKS) != nil || oidcURL(endpoint.AuthURL) != nil || oidcURL(endpoint.TokenURL) != nil {
		return OIDCStart{}, fmt.Errorf("invalid OIDC HTTPS endpoints")
	}
	secret, err := s.oidcSecret(ctx, c)
	if err != nil {
		return OIDCStart{}, fmt.Errorf("provider credentials unavailable")
	}
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	if c.AuthStyle == "post" || c.AuthStyle == "none" {
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}
	f.provider, f.client = provider, client
	f.oauth = oauth2.Config{ClientID: c.ClientID, ClientSecret: secret, Endpoint: endpoint, RedirectURL: callback, Scopes: []string{oidc.ScopeOpenID, "email", "profile"}}
	s.mu.Lock()
	s.oidcFlows[state] = f
	s.mu.Unlock()
	succeeded = true
	return OIDCStart{URL: f.oauth.AuthCodeURL(state, oidc.Nonce(f.nonce), oauth2.S256ChallengeOption(f.verifier), oauth2.SetAuthURLParam("response_mode", "query")), BrowserBinding: browser}, nil
}

func OIDCIdentity(issuer, subject string) string {
	h := sha256.Sum256([]byte(issuer + "\x00" + subject))
	return "oidc:" + hex.EncodeToString(h[:])
}

func (s *Service) FinishOIDC(ctx context.Context, state, browser, code, providerError string) (Grant, error) {
	denied := fmt.Errorf("OIDC login rejected; reopen the portal from the guest network")
	if len(state) != 64 || len(browser) != 64 || len(code) > 8192 {
		return Grant{}, denied
	}
	s.mu.Lock()
	f, ok := s.oidcFlows[state]
	matches := ok && subtle.ConstantTimeCompare([]byte(f.browser), []byte(s.digest("oidc-browser", browser))) == 1
	if matches {
		delete(s.oidcFlows, state)
	}
	s.mu.Unlock()
	if matches && f.client != nil {
		defer f.client.CloseIdleConnections()
	}
	if !matches || f.provider == nil || time.Now().After(f.expires) || providerError != "" || code == "" {
		return Grant{}, denied
	}
	ctx = oidc.ClientContext(ctx, f.client)
	b, c, err := s.Store.GuestOIDCPolicy(ctx, f.redirect.NAS, f.redirect.MAC, f.redirect.Domain, f.config.ID)
	if err != nil || c.Scope != f.config.Scope || c.Revision != f.config.Revision || store.GuestPolicyHash(b) != f.policyHash {
		return Grant{}, denied
	}
	tokens, err := f.oauth.Exchange(ctx, code, oauth2.VerifierOption(f.verifier))
	if err != nil {
		return Grant{}, denied
	}
	raw, ok := tokens.Extra("id_token").(string)
	if !ok || len(raw) > 65536 {
		return Grant{}, denied
	}
	verified, err := f.provider.Verifier(&oidc.Config{ClientID: c.ClientID, SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256}}).Verify(ctx, raw)
	if err != nil || verified.Subject == "" || len(verified.Subject) > 255 || verified.Nonce != f.nonce || verified.IssuedAt.After(time.Now().Add(time.Minute)) || verified.IssuedAt.Before(time.Now().Add(-10*time.Minute)) {
		return Grant{}, denied
	}
	var claims struct {
		Email           string `json:"email"`
		EmailVerified   bool   `json:"email_verified"`
		AuthorizedParty string `json:"azp"`
	}
	if verified.Claims(&claims) != nil || (len(verified.Audience) > 1 && claims.AuthorizedParty != c.ClientID) || (claims.AuthorizedParty != "" && claims.AuthorizedParty != c.ClientID) {
		return Grant{}, denied
	}
	if len(c.EmailDomains) > 0 {
		_, domain, found := strings.Cut(strings.ToLower(claims.Email), "@")
		if !found || !claims.EmailVerified || !slices.Contains(c.EmailDomains, domain) {
			return Grant{}, denied
		}
	}
	if verified.AccessTokenHash != "" && verified.VerifyAccessToken(tokens.AccessToken) != nil {
		return Grant{}, denied
	}
	// Recheck after remote calls. No email-based account linking or local MFA bypass.
	b, c, err = s.Store.GuestOIDCPolicy(ctx, f.redirect.NAS, f.redirect.MAC, f.redirect.Domain, f.config.ID)
	if err != nil || c.Scope != f.config.Scope || c.Revision != f.config.Revision || store.GuestPolicyHash(b) != f.policyHash {
		return Grant{}, denied
	}
	user := OIDCIdentity(verified.Issuer, verified.Subject)
	return s.authorizeGuest(ctx, store.GuestAuthorization{NAS: f.redirect.NAS, MAC: f.redirect.MAC, DomainID: f.redirect.Domain, Method: "oidc", Identity: user, ProviderScope: c.Scope, ProviderID: c.ID, ProviderRevision: c.Revision, PolicyID: b.Access.ID, PolicyHash: f.policyHash, Expires: verified.Expiry.Unix()})
}
