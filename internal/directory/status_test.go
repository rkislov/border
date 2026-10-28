package directory

import (
	"github.com/go-ldap/ldap/v3"
	"testing"
)

func TestAccountDisableFlags(t *testing.T) {
	for _, tc := range []struct {
		attrs            map[string][]string
		enabled, unknown bool
	}{
		{map[string][]string{"userAccountControl": {"512"}}, true, false},
		{map[string][]string{"userAccountControl": {"514"}}, false, false},
		{map[string][]string{"nsAccountLock": {"TRUE"}}, false, false},
		{map[string][]string{"nsAccountLock": {"FALSE"}}, true, false},
		{map[string][]string{}, false, true},
		{map[string][]string{"userAccountControl": {"broken"}}, false, true},
	} {
		enabled, e := accountEnabled(ldap.NewEntry("uid=user", tc.attrs))
		if (e != nil) != tc.unknown || (e == nil && enabled != tc.enabled) {
			t.Fatal(tc, enabled, e)
		}
	}
}
