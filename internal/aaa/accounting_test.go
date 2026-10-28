package aaa

import (
	"encoding/binary"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2866"
	"testing"
	"time"
)

func TestAccountingRestartWithoutSessionID(t *testing.T) {
	for _, code := range []uint32{7, 8} {
		t.Run(string(rune('0'+code)), func(t *testing.T) {
			s := database(t)
			ctx := t.Context()
			base := time.Now().Unix() - 100
			if e := s.ApplyAccounting(ctx, store.AccountingEvent{NAS: "127.0.0.1", ID: "s", Kind: "start", At: base, Timed: true}); e != nil {
				t.Fatal(e)
			}
			p := radius.New(radius.CodeAccountingRequest, []byte(testSecret))
			p.Attributes.Add(40, binary.BigEndian.AppendUint32(nil, code))
			p.Attributes.Add(55, binary.BigEndian.AppendUint32(nil, uint32(base+10)))
			raw, e := p.Encode()
			if e != nil {
				t.Fatal(e)
			}
			out, e := Process(ctx, s, raw, source(), true)
			if e != nil || !radius.IsAuthenticResponse(out, raw, []byte(testSecret)) {
				t.Fatal(e)
			}
			sessions, e := s.Sessions(ctx)
			if e != nil || len(sessions) != 1 || sessions[0].Status == "active" {
				t.Fatal(sessions, e)
			}
		})
	}
}
func TestAccountingRetryFingerprintAndValidation(t *testing.T) {
	p := radius.New(radius.CodeAccountingRequest, []byte(testSecret))
	rfc2866.AcctSessionID_SetString(p, "s")
	p.Attributes.Add(40, binary.BigEndian.AppendUint32(nil, 3))
	p.Attributes.Add(46, binary.BigEndian.AppendUint32(nil, 120))
	p.Attributes.Add(41, binary.BigEndian.AppendUint32(nil, 1))
	first, e := accountingEvent(p, "nas")
	if e != nil {
		t.Fatal(e)
	}
	p.Identifier++
	p.Attributes.Set(41, binary.BigEndian.AppendUint32(nil, 10))
	second, e := accountingEvent(p, "nas")
	if e != nil || first.Key != second.Key || first.At-second.At != 9 {
		t.Fatal(first, second, e)
	}
	p.Attributes.Add(46, []byte{0, 0, 0, 1})
	if _, e = accountingEvent(p, "nas"); e == nil {
		t.Fatal("duplicate counter accepted")
	}
}
