package aaa

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/rkislov/border/internal/mschap"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func selectPolicy(ctx context.Context, s *store.Store, p *radius.Packet, host string) (*store.BoundPolicy, bool, error) {
	request := store.PolicyRequest{Protocol: "pap", Username: rfc2865.UserName_GetString(p)}
	ms, err := mschap.Parse(p)
	if err != nil {
		return nil, true, err
	}
	if ms != nil {
		request.Protocol = "mschapv2"
	} else if len(p.Attributes.Get(79)) > 0 {
		request.Protocol = "eap"
	} else if _, e := NormalizeMAC(request.Username); e == nil {
		request.Protocol = "mab"
	}
	called := rfc2865.CalledStationID_GetString(p)
	if len(called) > 18 && called[17] == ':' {
		if _, e := NormalizeMAC(called[:17]); e == nil && len(called[18:]) <= 32 {
			request.SSID = called[18:]
		}
	}
	seen := map[radius.Type]bool{}
	for _, a := range p.Attributes {
		switch a.Type {
		case 1, 6, 30, 61:
			if seen[a.Type] {
				return nil, true, fmt.Errorf("duplicate policy selector")
			}
			seen[a.Type] = true
			if a.Type == 6 || a.Type == 61 {
				if len(a.Attribute) != 4 {
					return nil, true, fmt.Errorf("invalid policy selector")
				}
				v := int(binary.BigEndian.Uint32(a.Attribute))
				if a.Type == 6 {
					request.ServiceType = v
				} else {
					request.NASPortType = &v
				}
			}
		}
	}
	return s.SelectPolicy(ctx, host, request)
}
func registeredDevice(ctx context.Context, s *store.Store, p *radius.Packet) bool {
	mac, err := NormalizeMAC(rfc2865.CallingStationID_GetString(p))
	if err != nil {
		return false
	}
	d, err := s.Device(ctx, mac)
	return err == nil && d.Active
}
