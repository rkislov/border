// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"context"
	"errors"
	"github.com/rkislov/border/internal/radprofile"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"time"
)

// Service profiles never fall back to MAC authorization or isolation VLANs.
// PAP is the only supported credential exchange here; the NAS must protect
// its RADIUS transport and explicitly opt into the intended service.
func processService(ctx context.Context, s *store.Store, p *radius.Packet, host string, c radprofile.Config, o Options) ([]byte, error) {
	user := rfc2865.UserName_GetString(p)
	valid := false
	reason := "service authorization denied"
	grant, err := s.NASGrant(ctx, host, user, c.Mode)
	pap := len(p.Attributes.Get(2)) > 0 && len(p.Attributes.Get(3)) == 0 && len(p.Attributes.Get(79)) == 0
	if err == nil && pap && user != "" {
		password := rfc2865.UserPassword_GetString(p)
		switch c.Credential {
		case "codes":
			if o.Network != nil {
				valid, err = o.Network.Verify(ctx, user, password)
			}
		case "directory":
			if o.Directory != nil {
				identity, authErr := o.Directory.Authenticate(ctx, user, password)
				err = authErr
				valid = err == nil
				if valid {
					user = identity.Username
				}
			}
		}
		valid = valid && err == nil
		if valid {
			reason = c.Mode + " authorized"
		}
	}
	if valid {
		enabled, e := s.IdentityEnabled(ctx, user)
		valid = enabled && e == nil
	}
	out := p.Response(radius.CodeAccessReject)
	if valid {
		out = p.Response(radius.CodeAccessAccept)
		if err = radprofile.Apply(out, c, grant); err != nil {
			return nil, err
		}
		if err = rfc2865.SessionTimeout_Set(out, 3600); err != nil {
			return nil, err
		}
	}
	if valid {
		token, e := s.NewAccessGrant(ctx, host, user, "", time.Now().Unix()+3600)
		if e != nil {
			return nil, e
		}
		out.Attributes.Add(25, []byte(token))
		out.Attributes.Add(85, []byte{0, 0, 1, 44})
	}
	for _, a := range p.Attributes {
		if a.Type == 33 {
			out.Attributes.Add(33, a.Attribute)
		}
	}
	if err = s.Audit(ctx, host, user, out.Code.String(), reason); err != nil {
		return nil, errors.New("service audit failed")
	}
	if err = SignMessageAuthenticator(out); err != nil {
		return nil, err
	}
	return out.Encode()
}
