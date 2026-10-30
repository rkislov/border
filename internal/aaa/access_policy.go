package aaa

import (
	"context"
	"fmt"
	"github.com/rkislov/border/internal/mschap"
	"github.com/rkislov/border/internal/radprofile"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2868"
	"reflect"
	"strconv"
	"time"
)

type TOTPVerifier interface {
	VerifyTOTP(context.Context, string, string) (bool, error)
}

func processPolicy(ctx context.Context, s *store.Store, p *radius.Packet, host string, c radprofile.Config, b *store.BoundPolicy, o Options) ([]byte, error) {
	if b.BindingID != "" {
		c.Mode = b.Access.Mode
	}
	ttl, err := b.Timeout(time.Now())
	valid := err == nil && c.Mode == b.Access.Mode
	effective := c
	effective.Mode = b.Access.Mode
	valid = valid && effective.Validate() == nil
	if b.Access.Mode != "network" && (b.Authentication.Source == "mab" || b.Authentication.Source == "eap_tls") {
		valid = false
	}
	a := b.Authentication
	if a.EAPMethod != "" {
		if valid && b.Access.Mode == "network" && o.EAP != nil && o.Identities != nil && len(p.Attributes.Get(79)) > 0 {
			return processTunneledEAP(ctx, s, p, host, b, o)
		}
		valid = false
	}
	if a.Source == "eap_tls" && valid && b.Access.Mode == "network" && o.EAP != nil && len(p.Attributes.Get(79)) > 0 {
		return processEAP(ctx, s, p, host, o.EAP, b)
	}
	if valid && b.Access.Mode == "vpn" && (a.Source == "local" || a.Source == "directory") && o.EAPMSCHAP != nil && len(p.Attributes.Get(79)) > 0 {
		return processVPN_EAP(ctx, s, p, host, effective, b, o)
	}
	user := rfc2865.UserName_GetString(p)
	var groups []string
	reason := "policy unavailable"
	ms, parseErr := mschap.Parse(p)
	if parseErr != nil {
		return nil, parseErr
	}
	msSuccess := ""
	if valid {
		if ms != nil {
			user, msSuccess, valid, reason = authenticateMSCHAP(ctx, s, p, b, o, ms)
			if valid && b.Authentication.Source == "directory" {
				groups, err = o.Identities.DomainGroups(ctx, user)
				if err != nil {
					valid = false
					reason = "directory groups unavailable"
				}
			}
		} else {
			user, groups, valid, reason = authenticateChain(ctx, s, p, b, o)
		}
	}

	if valid {
		enabled, e := s.IdentityEnabled(ctx, user)
		valid = enabled && e == nil
	}
	if valid {
		current, _, e := selectPolicy(ctx, s, p, host)
		valid = e == nil && current != nil && reflect.DeepEqual(current, b)
		if valid {
			ttl, err = current.Timeout(time.Now())
			valid = err == nil
		}
	}
	if valid {
		valid, reason, err = evaluatePolicy(ctx, s, p, host, user, groups, b)
		if err != nil {
			return nil, err
		}
	}
	out := p.Response(radius.CodeAccessReject)
	if !valid && len(p.Attributes.Get(79)) > 1 {
		message := p.Attributes.Get(79)
		out.Attributes.Add(79, []byte{4, message[1], 0, 4})
	}
	if valid {
		out = p.Response(radius.CodeAccessAccept)
		if ms != nil {
			if err = ms.AddSuccess(out, msSuccess); err != nil {
				return nil, err
			}
		}
		c.Mode = b.Access.Mode
		if c.Mode == "network" {
			if err = setPolicyVLAN(out, b.VLAN); err != nil {
				return nil, err
			}
		} else {
			if err = radprofile.Apply(out, c, b.Grant()); err != nil {
				return nil, err
			}
		}
		if err = rfc2865.SessionTimeout_Set(out, rfc2865.SessionTimeout(ttl)); err != nil {
			return nil, err
		}
		if b.Access.IdleSeconds > 0 {
			if err = rfc2865.IdleTimeout_Set(out, rfc2865.IdleTimeout(b.Access.IdleSeconds)); err != nil {
				return nil, err
			}
		}
	}
	if valid {
		token, e := s.NewPolicyGrant(ctx, host, user, b, time.Now().Unix()+int64(ttl))
		if e != nil {
			return nil, e
		}
		out.Attributes.Add(25, []byte(token))
		if err := setAccountingInterval(ctx, s, host, out); err != nil {
			return nil, err
		}
	}
	for _, v := range p.Attributes {
		if v.Type == 33 {
			out.Attributes.Add(33, v.Attribute)
		}
	}
	if err = s.Audit(ctx, host, user, out.Code.String(), "access policy "+b.Access.ID+" binding "+b.BindingID+": "+reason); err != nil {
		return nil, fmt.Errorf("policy audit failed")
	}
	if err = SignMessageAuthenticator(out); err != nil {
		return nil, err
	}
	return out.Encode()
}
func setPolicyVLAN(p *radius.Packet, v int) error {
	if v < 1 || v > 4094 {
		return fmt.Errorf("unmapped VLAN")
	}
	if err := rfc2868.TunnelType_Set(p, 0, 13); err != nil {
		return err
	}
	if err := rfc2868.TunnelMediumType_Set(p, 0, 6); err != nil {
		return err
	}
	return rfc2868.TunnelPrivateGroupID_SetString(p, 0, strconv.Itoa(v))
}
