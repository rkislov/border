package aaa

import (
	"context"
	"fmt"
	"github.com/rkislov/border/internal/radprofile"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2868"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type TOTPVerifier interface {
	VerifyTOTP(context.Context, string, string) (bool, error)
}

func processPolicy(ctx context.Context, s *store.Store, p *radius.Packet, host string, c radprofile.Config, b *store.BoundPolicy, o Options) ([]byte, error) {
	ttl, err := b.Timeout(time.Now())
	valid := err == nil && c.Mode == b.Access.Mode
	effective := c
	effective.Mode = b.Access.Mode
	valid = valid && effective.Validate() == nil
	if b.Access.Mode != "network" && (b.Authentication.Source == "mab" || b.Authentication.Source == "eap_tls") {
		valid = false
	}
	a := b.Authentication
	if a.Source == "eap_tls" && valid && b.Access.Mode == "network" && o.EAP != nil && len(p.Attributes.Get(79)) > 0 {
		return processEAP(ctx, s, p, host, o.EAP)
	}
	var groups []string
	reason := "authentication failed"
	user := rfc2865.UserName_GetString(p)
	if a.Source == "mab" {
		mac, e := NormalizeMAC(rfc2865.CallingStationID_GetString(p))
		if e != nil {
			mac, e = NormalizeMAC(user)
		}
		valid = valid && e == nil && len(p.Attributes.Get(79)) == 0 && len(p.Attributes.Get(3)) == 0
		user = mac
		if d, e := s.Device(ctx, mac); e == nil && !d.Active {
			valid = false
		}
	} else {
		valid = valid && len(p.Attributes.Get(2)) > 0 && len(p.Attributes.Get(79)) == 0 && len(p.Attributes.Get(3)) == 0
		source := "local"
		if a.Source == "directory" {
			source = a.DomainID
		}
		if a.Source == "local" || a.Source == "directory" {
			if _, _, qualified := strings.Cut(user, "/"); !qualified {
				user = source + "/" + user
			}
			if !strings.HasPrefix(user, source+"/") {
				valid = false
			}
			user = strings.ToLower(user)
		}
		if !b.Rules.Enabled && !s.PolicySubject(ctx, b.Access.ID, user) {
			valid = false
		}
		password := rfc2865.UserPassword_GetString(p)
		factor := ""
		if a.RequireTOTP {
			index := strings.LastIndex(password, ";otp=")
			if index < 0 || len(password[index+5:]) != 6 {
				valid = false
			} else {
				factor = password[index+5:]
				password = password[:index]
			}
		}
		if valid {
			switch a.Source {
			case "local", "directory":
				if o.Identities == nil {
					valid = false
				} else {
					i, e := o.Identities.Authenticate(ctx, user, password)
					valid = e == nil && i.Username == user
					if valid {
						groups = i.Groups
					}
				}
			case "codes":
				if o.Network == nil {
					valid = false
				} else {
					if strings.Contains(user, "/") && (o.Identities == nil || !o.Identities.Active(ctx, user)) {
						valid = false
					} else {
						valid, err = o.Network.Verify(ctx, user, password)
					}
					valid = valid && err == nil
				}
			default:
				valid = false
			}
		}
		if valid && a.RequireTOTP {
			if o.TOTP == nil {
				valid = false
			} else {
				valid, err = o.TOTP.VerifyTOTP(ctx, user, factor)
				valid = valid && err == nil
			}
		}
	}
	if valid {
		enabled, e := s.IdentityEnabled(ctx, user)
		valid = enabled && e == nil
	}
	if valid {
		current, e := s.BoundPolicy(ctx, host)
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
		token, e := s.NewAccessGrant(ctx, host, user, b.Access.ID, time.Now().Unix()+int64(ttl))
		if e != nil {
			return nil, e
		}
		out.Attributes.Add(25, []byte(token))
	}
	for _, v := range p.Attributes {
		if v.Type == 33 {
			out.Attributes.Add(33, v.Attribute)
		}
	}
	if err = s.Audit(ctx, host, user, out.Code.String(), "access policy "+b.Access.ID+": "+reason); err != nil {
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
