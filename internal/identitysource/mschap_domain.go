package identitysource

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/rkislov/border/internal/directory"
	"github.com/rkislov/border/internal/mschap"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The helper path is host configuration, never tenant-controlled. Input travels
// over stdin, not a shell or process arguments. No domain password is stored.
func (s *Service) VerifyDomainMSCHAP(ctx context.Context, domain, login, wireUser string, r *mschap.Request) (string, error) {
	fail := fmt.Errorf("domain MS-CHAPv2 authentication failed")
	d, err := s.Domain(ctx, domain)
	if err != nil || !d.Enabled || d.MSCHAPDomain == "" {
		return "", fail
	}
	helper := os.Getenv("BORDER_NTLM_AUTH")
	if !filepath.IsAbs(helper) {
		return "", fail
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	input := fmt.Sprintf("Username:: %s\nNT-Domain:: %s\nLANMAN-Challenge: %X\nNT-Response: %X\nRequest-User-Session-Key: Yes\n.\n", base64.StdEncoding.EncodeToString([]byte(login)), base64.StdEncoding.EncodeToString([]byte(d.MSCHAPDomain)), r.ChallengeHash(wireUser), r.Response)
	cmd := exec.CommandContext(ctx, helper, "--helper-protocol=ntlm-server-1")
	cmd.Stdin = strings.NewReader(input)
	cmd.WaitDelay = time.Second
	var output boundedNTLMOutput
	cmd.Stdout = &output
	if err = cmd.Run(); err != nil {
		return "", fail
	}
	authenticated := false
	var key []byte
	for _, line := range strings.Split(output.String(), "\n") {
		if line == "Authenticated: Yes" {
			authenticated = true
		}
		if strings.HasPrefix(line, "User-Session-Key: ") {
			if key != nil {
				return "", fail
			}
			key, err = hex.DecodeString(strings.TrimPrefix(line, "User-Session-Key: "))
			if err != nil {
				return "", fail
			}
		}
	}
	defer clear(key)
	if !authenticated || len(key) != 16 {
		return "", fail
	}
	enabled, err := s.AccountEnabled(ctx, domain+"/"+login)
	if err != nil || !enabled {
		return "", fail
	}
	return r.AuthenticatorResponse(key, wireUser), nil
}

type boundedNTLMOutput struct{ bytes.Buffer }

func (b *boundedNTLMOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 4096 {
		return 0, fmt.Errorf("helper output too large")
	}
	return b.Buffer.Write(p)
}

func (s *Service) DomainGroups(ctx context.Context, qualified string) ([]string, error) {
	id, user, ok := strings.Cut(qualified, "/")
	if !ok {
		return nil, fmt.Errorf("domain required")
	}
	d, err := s.Domain(ctx, id)
	if err != nil || !d.Enabled {
		return nil, fmt.Errorf("domain unavailable")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if d.CAPEM != "" && !roots.AppendCertsFromPEM([]byte(d.CAPEM)) {
		return nil, fmt.Errorf("invalid domain CA")
	}
	for _, endpoint := range d.Endpoints {
		u, e := url.Parse(endpoint)
		if e != nil {
			return nil, e
		}
		l := directory.LDAP{URL: endpoint, BaseDN: d.BaseDN, BindDN: d.BindDN, BindPassword: d.BindPassword, UserAttribute: d.UserAttribute, TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: u.Hostname()}}
		groups, e := l.AccountGroups(ctx, user)
		if e == nil {
			return groups, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("domain groups unavailable")
}
