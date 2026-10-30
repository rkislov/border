// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"testing"
)

func TestTunnelPolicyNoPAPFallback(t *testing.T) {
	for _, method := range []string{"peap", "ttls"} {
		t.Run(method, func(t *testing.T) {
			s, o := vpnFixture(t)
			if err := s.SaveAuthentication(t.Context(), store.AuthenticationPolicy{ID: "local", Name: "Local", Source: "local", Enabled: true, EAPMethod: method}); err != nil {
				t.Fatal(err)
			}
			p := request(t, "aa:bb:cc:dd:ee:ff")
			rfc2865.UserName_SetString(p, "local/alice")
			rfc2865.UserPassword_SetString(p, "test-password-123")
			raw, err := ProcessWithOptions(t.Context(), s, wire(t, p), source(), false, o)
			if err != nil {
				t.Fatal(err)
			}
			reply, err := radius.Parse(raw, []byte(testSecret))
			if err != nil || reply.Code != radius.CodeAccessReject {
				t.Fatal("PAP fallback", reply, err)
			}
		})
	}
}
