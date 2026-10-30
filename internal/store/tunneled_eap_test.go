// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import "testing"

func TestTunneledEAPPolicyValidation(t *testing.T) {
	for _, a := range []AuthenticationPolicy{{Source: "codes", EAPMethod: "peap"}, {Source: "local", EAPMethod: "invented"}, {Source: "local", EAPMethod: "peap", RequireTOTP: true}, {Source: "directory", EAPMethod: "ttls", Steps: []string{"primary", "totp"}}} {
		if a.ValidateChain() == nil {
			t.Fatalf("invalid tunnel policy accepted: %+v", a)
		}
	}
	s := ruleStore(t)
	for _, method := range []string{"peap", "ttls"} {
		a := AuthenticationPolicy{ID: method, Name: method, Source: "local", EAPMethod: method, Enabled: true, Steps: []string{"primary", "device"}}
		if err := s.SaveAuthentication(t.Context(), a); err != nil {
			t.Fatal(err)
		}
		all, err := s.Authentications(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, v := range all {
			if v.ID == method {
				found = v.EAPMethod == method
			}
		}
		if !found {
			t.Fatal("tunnel selection lost")
		}
		if s.SaveAccess(t.Context(), AccessPolicy{ID: method, Name: method, AuthenticationID: method, Mode: "vpn", SessionSeconds: 600, Enabled: true}) == nil {
			t.Fatal("network tunnel allowed for VPN")
		}
	}
}
