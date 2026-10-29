package radprofile

import (
	"encoding/binary"
	"layeh.com/radius"
	"strings"
	"testing"
)

func TestVendorAuthorizationEncoding(t *testing.T) {
	for _, tc := range []struct {
		id     string
		vendor uint32
		code   byte
		value  string
	}{{"cisco", 9, 1, "shell:priv-lvl=3"}, {"mikrotik", 14988, 3, "readonly"}, {"huawei", 2011, 29, ""}, {"fortinet", 12356, 1, "readonly"}} {
		t.Run(tc.id, func(t *testing.T) {
			p := radius.New(radius.CodeAccessAccept, []byte("secret"))
			c := Config{Dictionary: tc.id, Mode: "ssh", Credential: "codes"}
			if err := Apply(p, c, Grant{Privilege: 3, Group: "readonly", Role: "read_only"}); err != nil {
				t.Fatal(err)
			}
			a := p.Attributes.Get(26)
			vendor, b, err := radius.VendorSpecific(a)
			if err != nil || vendor != tc.vendor || len(b) < 2 || b[0] != tc.code || int(b[1]) != len(b) {
				t.Fatalf("%v %x %v", vendor, b, err)
			}
			if tc.id == "huawei" {
				if binary.BigEndian.Uint32(b[2:]) != 3 {
					t.Fatal("wrong integer")
				}
			} else if string(b[2:]) != tc.value {
				t.Fatal("wrong string")
			}
		})
	}
}
func TestProfilesValidate(t *testing.T) {
	if (Config{Dictionary: "strongswan", Mode: "vpn", Credential: "directory"}).Validate() != nil {
		t.Fatal("VPN profile rejected")
	}
	if (Config{Dictionary: "strongswan", Mode: "ssh", Credential: "directory"}).Validate() == nil {
		t.Fatal("SSH profile accepted")
	}
	for _, id := range []string{"keenetic"} {
		if (Config{Dictionary: id, Mode: "vpn", Credential: "codes"}).Validate() == nil {
			t.Fatal("unsupported VPN accepted")
		}
	}
	if (Config{Dictionary: "invented", Mode: "network", Credential: "codes"}).Validate() == nil {
		t.Fatal("unknown dictionary")
	}
	if (Grant{Username: "user", Mode: "ssh", Role: strings.Repeat("x", 101)}).Validate() == nil {
		t.Fatal("oversized VSA")
	}
}
