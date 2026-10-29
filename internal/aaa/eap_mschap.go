// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/rkislov/border/internal/eapmschap"
	"github.com/rkislov/border/internal/mschap"
	"github.com/rkislov/border/internal/radprofile"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"reflect"
	"strings"
	"time"
)

func processVPN_EAP(ctx context.Context, s *store.Store, p *radius.Packet, host string, c radprofile.Config, b *store.BoundPolicy, o Options) ([]byte, error) {
	var msg, state []byte
	states := 0
	for _, a := range p.Attributes {
		switch a.Type {
		case 79:
			msg = append(msg, a.Attribute...)
		case 24:
			states++
			state = a.Attribute
		case 2, 3:
			return nil, fmt.Errorf("mixed EAP and password credentials")
		}
	}
	if states > 1 || len(msg) > 512 {
		return nil, fmt.Errorf("invalid EAP attributes")
	}
	user := rfc2865.UserName_GetString(p)
	encoded, _ := json.Marshal(b)
	digest := sha256.Sum256(encoded)
	peer := append([]byte(host), digest[:]...)
	for _, v := range []string{user, string(p.Attributes.Get(31)), string(p.Attributes.Get(5)), string(p.Attributes.Get(87)), string(p.Attributes.Get(30))} {
		peer = binary.BigEndian.AppendUint16(peer, uint16(len(v)))
		peer = append(peer, v...)
	}
	permitted := o.Identities != nil && b.Authentication.ValidateChain() == nil
	for _, step := range b.Authentication.Chain() {
		if step != "primary" && step != "device" {
			permitted = false
		}
		if step == "device" && !registeredDevice(ctx, s, p) {
			permitted = false
		}
	}
	verify := func(ctx context.Context, wire string, r *mschap.Request) (eapmschap.Result, error) {
		result := eapmschap.Result{}
		source := "local"
		if b.Authentication.Source == "directory" {
			source = b.Authentication.DomainID
		}
		login := strings.ToLower(wire)
		if strings.HasPrefix(login, source+"/") {
			login = strings.TrimPrefix(login, source+"/")
		}
		if login == "" || strings.ContainsAny(login, "/\\") {
			return result, eapmschap.ErrRejected
		}
		result.Identity = source + "/" + login
		var err error
		if source == "local" {
			result.Success, result.Key, err = o.Identities.VerifyLocalMSCHAPKeys(ctx, login, wire, r)
		} else {
			result.Success, result.Key, err = o.Identities.VerifyDomainMSCHAPKeys(ctx, source, login, wire, r)
		}
		if err == nil && source != "local" {
			result.Groups, err = o.Identities.DomainGroups(ctx, result.Identity)
		}
		if err != nil {
			clear(result.Key)
			return eapmschap.Result{}, eapmschap.ErrRejected
		}
		return result, nil
	}
	reply := eapmschap.Reply{Reject: true, Message: []byte{4, 0, 0, 4}}
	if len(msg) > 1 {
		reply.Message[1] = msg[1]
	}
	if permitted {
		reply = o.EAPMSCHAP.Handle(ctx, string(peer), user, state, msg, verify)
	}
	defer clear(reply.Key)
	ttl, err := b.Timeout(time.Now())
	reason := "EAP-MSCHAPv2"
	if reply.Accept {
		current, _, e := selectPolicy(ctx, s, p, host)
		valid := e == nil && reflect.DeepEqual(current, b) && err == nil
		if valid {
			enabled, e := s.IdentityEnabled(ctx, reply.Identity)
			valid = enabled && e == nil
		}
		if valid {
			enabled, e := o.Identities.AccountEnabled(ctx, reply.Identity)
			valid = enabled && e == nil
		}
		if valid && b.Authentication.Source == "directory" {
			reply.Groups, e = o.Identities.DomainGroups(ctx, reply.Identity)
			valid = e == nil
		}
		if valid {
			valid, reason, e = evaluatePolicy(ctx, s, p, host, reply.Identity, reply.Groups, b)
			valid = valid && e == nil
		}
		if !valid {
			reply.Accept = false
			reply.Reject = true
			reply.Message = []byte{4, msg[1], 0, 4}
			reason = "VPN access policy rejected"
		}
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
		n := min(len(remaining), 253)
		out.Attributes.Add(79, remaining[:n])
		remaining = remaining[n:]
	}
	if len(reply.State) > 0 {
		out.Attributes.Add(24, reply.State)
	}
	if reply.Accept {
		if len(reply.Key) != 32 {
			return nil, fmt.Errorf("invalid EAP-MSCHAPv2 key")
		}
		if err = setMPPEPair(out, reply.Key[:16], reply.Key[16:]); err != nil {
			return nil, err
		}
		if err = radprofile.Apply(out, c, b.Grant()); err != nil {
			return nil, err
		}
		if err = rfc2865.UserName_SetString(out, reply.Identity); err != nil {
			return nil, err
		}
		if err = rfc2865.SessionTimeout_Set(out, rfc2865.SessionTimeout(ttl)); err != nil {
			return nil, err
		}
		if b.Access.IdleSeconds > 0 {
			if err = rfc2865.IdleTimeout_Set(out, rfc2865.IdleTimeout(b.Access.IdleSeconds)); err != nil {
				return nil, err
			}
		}
		token, e := s.NewPolicyGrant(ctx, host, reply.Identity, b, time.Now().Unix()+int64(ttl))
		if e != nil {
			return nil, e
		}
		out.Attributes.Add(25, []byte(token))
		if err = setAccountingInterval(ctx, s, host, out); err != nil {
			return nil, err
		}
	}
	if reply.Accept || reply.Reject {
		if err = s.Audit(ctx, host, user, code.String(), reason); err != nil {
			return nil, err
		}
	}
	if err = SignMessageAuthenticator(out); err != nil {
		return nil, err
	}
	return out.Encode()
}
