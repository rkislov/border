package aaa

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"sort"
	"time"
)

func accountingEvent(p *radius.Packet, host string) (store.AccountingEvent, error) {
	e := store.AccountingEvent{NAS: host, ID: rfc2866.AcctSessionID_GetString(p), Username: rfc2865.UserName_GetString(p), At: time.Now().Unix()}
	e.AccountingKey = vpnAccountingKey(p)
	e.MAC, _ = NormalizeMAC(rfc2865.CallingStationID_GetString(p))
	fields := map[radius.Type]bool{}
	parts := []string{}
	var delay int64
	counters := map[radius.Type]uint32{}
	for _, a := range p.Attributes {
		if a.Type == 25 {
			e.Classes = append(e.Classes, string(a.Attribute))
		}
		switch a.Type {
		case 1, 31, 40, 41, 42, 43, 44, 46, 52, 53, 55:
			if fields[a.Type] {
				return e, fmt.Errorf("duplicate accounting field")
			}
			fields[a.Type] = true
		}
		if a.Type == 41 || a.Type == 46 || a.Type == 55 || a.Type == 40 || a.Type == 42 || a.Type == 43 || a.Type == 52 || a.Type == 53 {
			if len(a.Attribute) != 4 {
				return e, fmt.Errorf("invalid accounting integer")
			}
			value := int64(binary.BigEndian.Uint32(a.Attribute))
			switch a.Type {
			case 42, 43, 52, 53:
				counters[a.Type] = uint32(value)
			case 41:
				delay = value
			case 46:
				e.Seconds = value
				e.HasSeconds = true
			case 55:
				e.At = value
				e.Timed = true
			}
		}
		// Retries may change Identifier, Authenticator and Acct-Delay-Time.
		if a.Type != 41 && a.Type != 80 {
			parts = append(parts, string(append([]byte{byte(a.Type)}, a.Attribute...)))
		}
	}
	if !e.Timed {
		e.At -= delay
	}
	switch rfc2866.AcctStatusType_Get(p) {
	case 1:
		e.Kind = "start"
	case 2:
		e.Kind = "stop"
	case 3:
		e.Kind = "interim"
	case 7:
		e.Kind = "on"
	case 8:
		e.Kind = "off"
	default:
		return e, fmt.Errorf("unsupported accounting status")
	}
	if e.Kind == "interim" || e.Kind == "stop" {
		for _, pair := range []struct {
			low, high radius.Type
			target    **store.TrafficCounter
		}{{42, 52, &e.Input}, {43, 53, &e.Output}} {
			low, hasLow := counters[pair.low]
			high, hasHigh := counters[pair.high]
			if hasHigh && !hasLow {
				return e, fmt.Errorf("gigawords without octets")
			}
			if hasLow {
				*pair.target = &store.TrafficCounter{Bytes: uint64(high)<<32 | uint64(low), Gigawords: hasHigh}
			}
		}
	}
	sort.Strings(parts)
	h := sha256.New()
	for _, part := range parts {
		h.Write([]byte{byte(len(part))})
		h.Write([]byte(part))
	}
	e.Key = hex.EncodeToString(h.Sum(nil))
	return e, nil
}
