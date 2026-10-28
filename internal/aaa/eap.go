// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"time"

	"github.com/rkislov/border/internal/eap"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2868"
)

func processEAP(ctx context.Context, s *store.Store, p *radius.Packet, host string, engine *eap.Engine, selected ...*store.BoundPolicy) ([]byte, error) {
	var message, state []byte
	var states int
	for _, a := range p.Attributes {
		switch a.Type {
		case 79:
			message = append(message, a.Attribute...)
		case 24:
			states++
			state = a.Attribute
		}
	}
	if states > 1 || len(message) > 65535 {
		return nil, errors.New("invalid EAP attributes")
	}
	// Bind State to NAS, station and port, never to the unauthenticated identity.
	// Length prefixes prevent ambiguous concatenation of attribute values.
	peer := []byte(host)
	for _, kind := range []radius.Type{31, 5, 87} {
		value := p.Attributes.Get(kind)
		peer = binary.BigEndian.AppendUint16(peer, uint16(len(value)))
		peer = append(peer, value...)
	}
	var bound *store.BoundPolicy
	var policyErr error
	if len(selected) > 0 {
		bound = selected[0]
	} else {
		bound, policyErr = s.BoundPolicy(ctx, host)
	}
	if bound != nil {
		encoded, _ := json.Marshal(bound)
		digest := sha256.Sum256(encoded)
		peer = append(peer, digest[:]...)
	}
	reply := engine.Handle(ctx, string(peer), state, message)
	if reply.Accept {
		current, configured, e := selectPolicy(ctx, s, p, host)
		if e != nil || configured && current == nil || !reflect.DeepEqual(current, bound) {
			policyErr = errors.New("policy changed during EAP")
		}
	}
	timeout := uint32(3600)
	if reply.Accept && bound != nil {
		if policyErr == nil {
			timeout, policyErr = bound.Timeout(time.Now())
		}
		if policyErr == nil && (bound.Authentication.Source != "eap_tls" || bound.Access.Mode != "network") {
			policyErr = errors.New("identity not permitted by access policy")
		}
		if policyErr == nil {
			allowed, _, e := evaluatePolicy(ctx, s, p, host, reply.Authorization.Identity, nil, bound)
			if e != nil || !allowed {
				policyErr = errors.New("access rule rejected")
			}
		}
		if policyErr == nil {
			for _, step := range bound.Authentication.Chain() {
				if step == "device" && !registeredDevice(ctx, s, p) {
					policyErr = errors.New("device step rejected")
				}
			}
		}
		if policyErr == nil {
			reply.Authorization.VLAN = bound.VLAN
		}
	}
	if reply.Accept {
		if enabled, e := s.IdentityEnabled(ctx, reply.Authorization.Identity); e != nil || !enabled {
			policyErr = errors.New("identity disabled")
		}
	}
	if reply.Accept && policyErr != nil {
		clear(reply.Key)
		reply.Accept = false
		reply.Reject = true
		reply.Reason = "access policy rejected"
		id := byte(0)
		if len(reply.Message) > 1 {
			id = reply.Message[1]
		}
		reply.Message = []byte{4, id, 0, 4}
	}

	code := radius.CodeAccessChallenge
	if reply.Accept {
		code = radius.CodeAccessAccept
	} else if reply.Reject {
		code = radius.CodeAccessReject
	}
	out := p.Response(code)
	for _, a := range p.Attributes {
		if a.Type == 33 {
			out.Attributes.Add(33, a.Attribute)
		}
	}
	for remaining := reply.Message; len(remaining) > 0; {
		n := len(remaining)
		if n > 253 {
			n = 253
		}
		out.Attributes.Add(79, remaining[:n])
		remaining = remaining[n:]
	}
	if len(reply.State) > 0 {
		out.Attributes.Add(24, reply.State)
	}
	if reply.Accept {
		if bound != nil && bound.Access.IdleSeconds > 0 {
			if err := rfc2865.IdleTimeout_Set(out, rfc2865.IdleTimeout(bound.Access.IdleSeconds)); err != nil {
				return nil, err
			}
		}
		defer clear(reply.Key)
		if len(reply.Key) != 128 {
			return nil, errors.New("invalid EAP key material")
		}
		if err := setMPPEKeys(out, reply.Key); err != nil {
			return nil, err
		}
		if err := rfc2865.UserName_SetString(out, reply.Authorization.Identity); err != nil {
			return nil, err
		}
		if vlan := reply.Authorization.VLAN; vlan > 0 {
			if err := rfc2868.TunnelType_Set(out, 0, 13); err != nil {
				return nil, err
			}
			if err := rfc2868.TunnelMediumType_Set(out, 0, 6); err != nil {
				return nil, err
			}
			if err := rfc2868.TunnelPrivateGroupID_SetString(out, 0, strconv.Itoa(vlan)); err != nil {
				return nil, err
			}
		}
		if err := rfc2865.SessionTimeout_Set(out, rfc2865.SessionTimeout(timeout)); err != nil {
			return nil, err
		}
	}
	if reply.Accept {

		token, e := s.NewPolicyGrant(ctx, host, reply.Authorization.Identity, bound, time.Now().Unix()+int64(timeout))
		if e != nil {
			return nil, e
		}
		out.Attributes.Add(25, []byte(token))
		out.Attributes.Add(85, []byte{0, 0, 1, 44})
	}
	if reply.Accept || reply.Reject {
		if err := s.Audit(ctx, host, reply.Authorization.Identity, code.String(), reply.Reason); err != nil {
			return nil, errors.New("EAP audit failed")
		}
	}
	if err := SignMessageAuthenticator(out); err != nil {
		return nil, err
	}
	return out.Encode()
}

// Each encrypted MPPE attribute must have a distinct salt within the response.
func setMPPEKeys(packet *radius.Packet, key []byte) error {
	if len(key) != 128 {
		return errors.New("invalid EAP key material")
	}
	var salts [4]byte
	if _, err := rand.Read(salts[:]); err != nil {
		return err
	}
	salts[0] |= 0x80
	salts[2] |= 0x80
	if salts[0] == salts[2] && salts[1] == salts[3] {
		salts[3] ^= 1
	}
	for i, kind := range []byte{17, 16} {
		encrypted, err := radius.NewTunnelPassword(key[i*32:(i+1)*32], salts[i*2:(i+1)*2], packet.Secret, packet.Authenticator[:])
		if err != nil {
			return err
		}
		value := append([]byte{kind, byte(len(encrypted) + 2)}, encrypted...)
		attribute, err := radius.NewVendorSpecific(311, value)
		if err != nil {
			return err
		}
		packet.Attributes.Add(26, attribute)
	}
	return nil
}
