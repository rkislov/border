// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"layeh.com/radius"
	"testing"
)

func TestVPNAccountingTuple(t *testing.T) {
	p := radius.New(radius.CodeAccessRequest, []byte("secret"))
	for k, v := range map[radius.Type][]byte{4: {192, 0, 2, 1}, 6: {0, 0, 0, 2}, 30: []byte("server"), 31: []byte("client"), 32: []byte("nas"), 61: {0, 0, 0, 5}, 87: {0, 0, 0, 10}} {
		p.Attributes.Add(k, v)
	}
	key := vpnAccountingKey(p)
	if key == "" {
		t.Fatal("valid tuple rejected")
	}
	p.Attributes.Set(1, []byte("canonical/user"))
	if vpnAccountingKey(p) != key {
		t.Fatal("username must be matched separately")
	}
	p.Attributes.Set(87, []byte{0, 0, 0, 11})
	if vpnAccountingKey(p) == key {
		t.Fatal("binary port ignored")
	}
	p.Attributes.Add(31, []byte("duplicate"))
	if vpnAccountingKey(p) != "" {
		t.Fatal("duplicate accepted")
	}
}
