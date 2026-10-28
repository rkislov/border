// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type Identity struct {
	Username string
	Email    string
	Phone    string
	Groups   []string
}
type Authenticator interface {
	Authenticate(context.Context, string, string) (Identity, error)
}
type LDAP struct {
	URL, BaseDN, BindDN, BindPassword, UserAttribute string
	TLS                                              *tls.Config
}

// FromEnv supports AD (sAMAccountName) and FreeIPA (uid), using the same LDAP
// search/bind flow. Cleartext binds and anonymous directory searches are forbidden.
func FromEnv() (*LDAP, error) {
	endpoint := os.Getenv("BORDER_LDAP_URL")
	if endpoint == "" {
		return nil, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "ldaps" && u.Scheme != "ldap") || u.Hostname() == "" {
		return nil, fmt.Errorf("LDAP URL must use ldaps:// or ldap:// with StartTLS")
	}
	attr := os.Getenv("BORDER_LDAP_USER_ATTRIBUTE")
	if attr == "" {
		attr = "sAMAccountName"
	}
	if attr != "uid" && attr != "sAMAccountName" && attr != "userPrincipalName" {
		return nil, fmt.Errorf("LDAP user attribute must be uid, sAMAccountName or userPrincipalName")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if path := os.Getenv("BORDER_LDAP_CA"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("invalid LDAP CA")
		}
		config.RootCAs = roots
	}
	l := &LDAP{URL: endpoint, BaseDN: os.Getenv("BORDER_LDAP_BASE_DN"), BindDN: os.Getenv("BORDER_LDAP_BIND_DN"), BindPassword: os.Getenv("BORDER_LDAP_BIND_PASSWORD"), UserAttribute: attr, TLS: config}
	if l.BaseDN == "" || l.BindDN == "" || l.BindPassword == "" {
		return nil, fmt.Errorf("LDAP base DN and service credentials required")
	}
	return l, nil
}
func (l *LDAP) Authenticate(ctx context.Context, user, password string) (Identity, error) {
	fail := errors.New("domain authentication failed")
	if user == "" || len(user) > 200 || password == "" || len(password) > 1024 {
		return Identity{}, fail
	}
	conn, err := ldap.DialURL(l.URL, ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}), ldap.DialWithTLSConfig(l.TLS))
	if err != nil {
		return Identity{}, fail
	}
	defer conn.Close()
	conn.SetTimeout(5 * time.Second)
	if strings.HasPrefix(l.URL, "ldap://") {
		if err = conn.StartTLS(l.TLS); err != nil {
			return Identity{}, fail
		}
	}
	select {
	case <-ctx.Done():
		return Identity{}, ctx.Err()
	default:
	}
	if err = conn.Bind(l.BindDN, l.BindPassword); err != nil {
		return Identity{}, fail
	}
	filter := "(" + l.UserAttribute + "=" + ldap.EscapeFilter(user) + ")"
	result, err := conn.Search(ldap.NewSearchRequest(l.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false, filter, []string{l.UserAttribute, "mail", "mobile", "memberOf"}, nil))
	if err != nil || len(result.Entries) != 1 {
		return Identity{}, fail
	}
	entry := result.Entries[0]
	for _, attribute := range entry.Attributes {
		if strings.HasPrefix(strings.ToLower(attribute.Name), "memberof;range=") {
			return Identity{}, fail
		}
	}
	canonical := strings.ToLower(entry.GetAttributeValue(l.UserAttribute))
	email := entry.GetAttributeValue("mail")
	if canonical == "" || email == "" {
		return Identity{}, fail
	}
	if err = conn.Bind(entry.DN, password); err != nil {
		return Identity{}, fail
	}
	return Identity{Username: canonical, Email: email, Phone: entry.GetAttributeValue("mobile"), Groups: entry.GetAttributeValues("memberOf")}, nil
}

// AccountEnabled reads authoritative disable flags using the service account.
// Missing/inaccessible attributes are unknown, never evidence of a block.
func (l *LDAP) AccountEnabled(ctx context.Context, user string) (bool, error) {
	conn, err := ldap.DialURL(l.URL, ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}), ldap.DialWithTLSConfig(l.TLS))
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetTimeout(5 * time.Second)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if strings.HasPrefix(l.URL, "ldap://") {
		if err = conn.StartTLS(l.TLS); err != nil {
			return false, err
		}
	}
	if err = conn.Bind(l.BindDN, l.BindPassword); err != nil {
		return false, err
	}
	result, err := conn.Search(ldap.NewSearchRequest(l.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false, "("+l.UserAttribute+"="+ldap.EscapeFilter(user)+")", []string{"userAccountControl", "nsAccountLock"}, nil))
	if err != nil {
		return false, err
	}
	if len(result.Entries) != 1 {
		return false, fmt.Errorf("account status unknown")
	}
	return accountEnabled(result.Entries[0])
}
func accountEnabled(entry *ldap.Entry) (bool, error) {
	if value := entry.GetAttributeValue("userAccountControl"); value != "" {
		flags, err := strconv.ParseUint(value, 10, 32)
		return flags&2 == 0, err
	}
	switch strings.ToLower(entry.GetAttributeValue("nsAccountLock")) {
	case "true":
		return false, nil
	case "false":
		return true, nil
	}
	return false, fmt.Errorf("disable flag unavailable")
}
