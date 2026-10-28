// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package directory

import (
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"strconv"
	"time"
)

// ErrAccountNotFound means a successful search returned no entries, not proof
// of deletion: callers must opt in with authoritative search permissions.
var ErrAccountNotFound = errors.New("account not found in directory search")

func accountExpired(entry *ldap.Entry, now time.Time) (bool, error) {
	if value := entry.GetAttributeValue("accountExpires"); value != "" {
		ticks, err := strconv.ParseInt(value, 10, 64)
		if err != nil || ticks < 0 {
			return false, fmt.Errorf("invalid accountExpires")
		}
		if ticks != 0 && ticks != 9223372036854775807 {
			// FILETIME uses 100ns ticks since 1601. Divide before converting to avoid overflow.
			expiry := time.Unix(ticks/10000000-11644473600, (ticks%10000000)*100)
			if !now.Before(expiry) {
				return true, nil
			}
		}
	}
	if value := entry.GetAttributeValue("krbPrincipalExpiration"); value != "" {
		expiry, err := time.Parse("20060102150405Z0700", value)
		if err != nil {
			return false, fmt.Errorf("invalid krbPrincipalExpiration")
		}
		if !now.Before(expiry) {
			return true, nil
		}
	}
	return false, nil
}
