package aaa

import (
	"encoding/binary"
	"layeh.com/radius"
	"testing"
)

func TestNASAccountingIntervalInAccept(t *testing.T) {
	s := database(t)
	ctx := t.Context()
	if err := s.Exec(ctx, "UPDATE nas SET interim_seconds=600,stale_seconds=1800 WHERE address='127.0.0.1'"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mac    string
		accept bool
	}{{"aa:bb:cc:dd:ee:ff", true}, {"11:22:33:44:55:66", false}} {
		raw, err := Process(ctx, s, wire(t, request(t, tc.mac)), source(), false)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := radius.Parse(raw, []byte(testSecret))
		if err != nil {
			t.Fatal(err)
		}
		attr := packet.Attributes.Get(85)
		if tc.accept {
			if packet.Code != radius.CodeAccessAccept || len(attr) != 4 || binary.BigEndian.Uint32(attr) != 600 {
				t.Fatal(packet.Code, attr)
			}
		} else if len(attr) != 0 {
			t.Fatal("interval in reject")
		}
	}
}
