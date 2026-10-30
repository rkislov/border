// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/rkislov/border/internal/eap"
	"github.com/rkislov/border/internal/eapmschap"
	"github.com/rkislov/border/internal/eaptunnel"
	"github.com/rkislov/border/internal/mschap"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"strings"
)

func processTunneledEAP(ctx context.Context, s *store.Store, p *radius.Packet, host string, b *store.BoundPolicy, o Options) ([]byte, error) {
	source := "local"
	if b.Authentication.Source == "directory" {
		source = b.Authentication.DomainID
	}
	canonical := func(wire string) (string, error) {
		login := strings.TrimPrefix(strings.ToLower(wire), source+"/")
		if login == "" || len(login) > 253 || strings.ContainsAny(login, "/\\\x00\r\n") {
			return "", fmt.Errorf("invalid inner identity")
		}
		return login, nil
	}
	t := eap.Tunnel{Method: eap.TTLS}
	t.Authenticate = func(ctx context.Context, c *tls.Conn) (eap.Authorization, error) {
		if err := b.Authentication.ValidateChain(); err != nil {
			return eap.Authorization{}, err
		}
		if b.Authentication.EAPMethod == "ttls" {
			return eaptunnel.TTLS(ctx, c, func(ctx context.Context, wire, password string) (eap.Authorization, error) {
				login, err := canonical(wire)
				if err != nil {
					return eap.Authorization{}, err
				}
				identity, err := o.Identities.Authenticate(ctx, source+"/"+login, password)
				if err != nil || identity.Username != source+"/"+login {
					return eap.Authorization{}, fmt.Errorf("inner password rejected")
				}
				return eap.Authorization{Identity: identity.Username, Groups: identity.Groups}, nil
			})
		}
		return eaptunnel.PEAP(ctx, c, func(ctx context.Context, wire string, r *mschap.Request) (eapmschap.Result, error) {
			login, err := canonical(wire)
			if err != nil {
				return eapmschap.Result{}, err
			}
			result := eapmschap.Result{Identity: source + "/" + login}
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
				return eapmschap.Result{}, err
			}
			return result, nil
		})
	}
	if b.Authentication.EAPMethod == "peap" {
		t.Method = eap.PEAP
	}
	return processEAPTunnel(ctx, s, p, host, o.EAP, []*store.BoundPolicy{b}, &t, o)
}
