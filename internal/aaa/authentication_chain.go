package aaa

import (
	"context"
	"github.com/rkislov/border/internal/mschap"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"strings"
)

func authenticateChain(ctx context.Context, s *store.Store, p *radius.Packet, b *store.BoundPolicy, o Options) (string, []string, bool, string) {
	a := b.Authentication
	user := rfc2865.UserName_GetString(p)
	groups := []string{}
	if err := a.ValidateChain(); err != nil {
		return user, nil, false, "invalid chain"
	}
	if a.Source == "local" || a.Source == "directory" {
		source := "local"
		if a.Source == "directory" {
			source = a.DomainID
		}
		user = strings.ToLower(user)
		if !strings.Contains(user, "/") {
			user = source + "/" + user
		}
		if !strings.HasPrefix(user, source+"/") {
			return user, nil, false, "identity source mismatch"
		}
	}
	password := rfc2865.UserPassword_GetString(p)
	factor := ""
	for _, step := range a.Chain() {
		if step == "totp" {
			index := strings.LastIndex(password, ";otp=")
			if index >= 0 {
				factor = password[index+5:]
				password = password[:index]
			}
		}
	}
	for _, step := range a.Chain() {
		valid := false
		switch step {
		case "device":
			valid = registeredDevice(ctx, s, p)
		case "totp":
			formatOK := len(factor) == 6
			for _, digit := range factor {
				if digit < '0' || digit > '9' {
					formatOK = false
				}
			}
			if o.TOTP != nil && formatOK {
				ok, err := o.TOTP.VerifyTOTP(ctx, user, factor)
				valid = ok && err == nil
			}
		case "primary":
			if a.Source == "mab" {
				mac, err := NormalizeMAC(rfc2865.CallingStationID_GetString(p))
				if err != nil {
					mac, err = NormalizeMAC(user)
				}
				user = mac
				valid = err == nil && len(p.Attributes.Get(79)) == 0 && len(p.Attributes.Get(3)) == 0
				if d, err := s.Device(ctx, mac); err == nil && !d.Active {
					valid = false
				}
			} else if len(p.Attributes.Get(2)) > 0 && len(p.Attributes.Get(79)) == 0 && len(p.Attributes.Get(3)) == 0 {
				switch a.Source {
				case "local", "directory":
					if o.Identities != nil {
						identity, err := o.Identities.Authenticate(ctx, user, password)
						valid = err == nil && identity.Username == user
						if valid {
							groups = identity.Groups
						}
					}
				case "codes":
					if o.Network != nil {
						ok, err := o.Network.Verify(ctx, user, password)
						valid = ok && err == nil
					}
				}
			}
			if valid {
				enabled, err := s.IdentityEnabled(ctx, user)
				valid = enabled && err == nil
			}
		}
		if !valid {
			return user, groups, false, "step " + step + " rejected"
		}
	}
	return user, groups, true, "chain completed"
}

// MS-CHAPv2 support is deliberately restricted to SSH accounts. TOTP,
// VPN/MPPE and EAP are not silently downgraded.
func authenticateMSCHAP(ctx context.Context, s *store.Store, p *radius.Packet, b *store.BoundPolicy, o Options, r *mschap.Request) (string, string, bool, string) {
	wireUser := rfc2865.UserName_GetString(p)
	login := strings.ToLower(wireUser)
	if b.Authentication.Source == "local" && strings.HasPrefix(login, "local/") {
		login = strings.TrimPrefix(login, "local/")
	}
	source := "local"
	if b.Authentication.Source == "directory" {
		source = b.Authentication.DomainID
	}
	user := source + "/" + login
	if (b.Authentication.Source != "local" && b.Authentication.Source != "directory") || b.Access.Mode != "ssh" || o.Identities == nil || b.Authentication.ValidateChain() != nil || strings.ContainsAny(login, "/\\") || login == "" {
		return user, "", false, "MS-CHAPv2 requires local or directory SSH policy"
	}
	// Reject unsupported factors before validating any credentials.
	for _, step := range b.Authentication.Chain() {
		if step != "primary" && step != "device" {
			return user, "", false, "MS-CHAPv2 cannot satisfy required factor"
		}
	}
	success := ""
	for _, step := range b.Authentication.Chain() {
		if step == "device" && !registeredDevice(ctx, s, p) {
			return user, "", false, "step device rejected"
		}
		if step == "primary" {
			var err error
			if source == "local" {
				success, err = o.Identities.VerifyLocalMSCHAP(ctx, login, wireUser, r)
			} else {
				success, err = o.Identities.VerifyDomainMSCHAP(ctx, source, login, wireUser, r)
			}
			if err != nil {
				return user, "", false, "step primary rejected"
			}
		}
	}
	return user, success, true, "MS-CHAPv2 chain completed"
}
