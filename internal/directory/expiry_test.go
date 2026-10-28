package directory

import (
	"github.com/go-ldap/ldap/v3"
	"strconv"
	"testing"
	"time"
)

func TestAccountExpiry(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	ticks := (now.Unix() + 11644473600) * 10000000
	for _, tc := range []struct {
		attr, value      string
		expired, invalid bool
	}{
		{"accountExpires", "0", false, false},
		{"accountExpires", "9223372036854775807", false, false},
		{"accountExpires", strconv.FormatInt(ticks, 10), true, false},
		{"accountExpires", strconv.FormatInt(ticks+1, 10), false, false},
		{"accountExpires", strconv.FormatInt(ticks-1, 10), true, false},
		{"accountExpires", "-1", false, true},
		{"accountExpires", "9223372036854775808", false, true},
		{"accountExpires", "broken", false, true},
		{"krbPrincipalExpiration", "20261028120000Z", true, false},
		{"krbPrincipalExpiration", "20261028120001Z", false, false},
		{"krbPrincipalExpiration", "20261028150000+0300", true, false},
		{"krbPrincipalExpiration", "20261028120000.5Z", false, false},
		{"krbPrincipalExpiration", "broken", false, true},
	} {
		expired, err := accountExpired(ldap.NewEntry("uid=user", map[string][]string{tc.attr: {tc.value}}), now)
		if expired != tc.expired || (err != nil) != tc.invalid {
			t.Fatal(tc, expired, err)
		}
	}
	if expired, err := accountExpired(ldap.NewEntry("uid=user", nil), now); err != nil || expired {
		t.Fatal(expired, err)
	}
	// Expiration must override an otherwise enabled disable flag.
	for _, attr := range []string{"accountExpires", "krbPrincipalExpiration"} {
		value := "1"
		if attr == "krbPrincipalExpiration" {
			value = "20000101000000Z"
		}
		enabled, err := accountEnabled(ldap.NewEntry("uid=user", map[string][]string{"userAccountControl": {"512"}, attr: {value}}))
		if err != nil || enabled {
			t.Fatal(attr, enabled, err)
		}
	}
}
