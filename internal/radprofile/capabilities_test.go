// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package radprofile

import "testing"

func TestCapabilityCatalog(t *testing.T) {
	for _, p := range Catalog {
		c, ok := Describe(p.ID)
		if !ok || len(c.Features) == 0 {
			t.Fatal(p.ID)
		}
		for _, mode := range []string{"network", "ssh", "vpn"} {
			advertised := false
			for _, m := range c.Modes {
				advertised = advertised || m == mode
			}
			valid := (Config{Dictionary: p.ID, Mode: mode, Credential: "codes"}).Validate() == nil
			if advertised != valid {
				t.Fatal("UI/server mismatch", p.ID, mode)
			}
		}
		seen := map[string]bool{}
		for _, f := range c.Features {
			if seen[f.ID] || f.Requirements == "" || f.Verification == "" {
				t.Fatal(p.ID, f)
			}
			seen[f.ID] = true
			if (f.ID == "peap" || f.ID == "radsec") && f.Available {
				t.Fatal("unsupported feature advertised")
			}
		}
	}
	if _, ok := Describe("unknown"); ok {
		t.Fatal("unknown profile accepted")
	}
	if !SupportsMode("strongswan", "vpn") || SupportsMode("strongswan", "ssh") || SupportsMode("keenetic", "vpn") {
		t.Fatal("invalid mode constraints")
	}
}
