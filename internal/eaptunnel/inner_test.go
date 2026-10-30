package eaptunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/rkislov/border/internal/eap"
	"testing"
)

func TestTTLSAVPs(t *testing.T) {
	avp := func(code uint32, v string) []byte {
		n := 8 + len(v)
		b := make([]byte, (n+3)&^3)
		binary.BigEndian.PutUint32(b, code)
		b[4] = 64
		b[5] = byte(n >> 16)
		b[6] = byte(n >> 8)
		b[7] = byte(n)
		copy(b[8:], v)
		return b
	}
	good := append(avp(1, "alice"), avp(2, "password")...)
	for _, tc := range []struct {
		b  []byte
		ok bool
	}{{good, true}, {append(bytes.Clone(good), avp(1, "other")...), false}, {append(bytes.Clone(good), avp(999, "x")...), false}, {good[:len(good)-1], false}, {append(avp(1, "alice"), avp(2, "a\x00b")...), false}} {
		called := false
		_, err := TTLS(context.Background(), bytes.NewReader(tc.b), func(_ context.Context, u, p string) (eap.Authorization, error) {
			called = true
			if u != "alice" || p != "password" {
				t.Fatal(u)
			}
			return eap.Authorization{Identity: u}, nil
		})
		if (err == nil) != tc.ok || called != tc.ok {
			t.Fatalf("accepted=%v callback=%v want=%v", err == nil, called, tc.ok)
		}
	}
}
