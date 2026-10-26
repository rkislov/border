// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package pki

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// EAPTLSConfig trusts managed CAs and additionally requires the exact, active
// client certificate recorded by Border. Possession of a CA-signed leaf alone
// cannot bypass revocation or registration in the managed certificate ledger.
func (m *Manager) EAPTLSConfig(ctx context.Context, pair tls.Certificate) (*tls.Config, error) {
	roots := x509.NewCertPool()
	authorities, err := m.Authorities(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range authorities {
		if !roots.AppendCertsFromPEM([]byte(a.Certificate)) {
			return nil, fmt.Errorf("invalid managed CA")
		}
	}
	if len(authorities) == 0 {
		return nil, fmt.Errorf("create a managed CA before enabling EAP")
	}
	config := &tls.Config{Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, SessionTicketsDisabled: true}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		verifyCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := m.AuthorizeClient(verifyCtx, state)
		return err
	}
	return config, nil
}
func (m *Manager) AuthorizeClient(ctx context.Context, state tls.ConnectionState) (string, error) {
	if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("verified client certificate required")
	}
	leaf := state.PeerCertificates[0]
	var owner, raw, caPEM string
	var revoked int64
	if err := m.Store.Row(ctx, "SELECT c.owner,c.certificate,c.revoked_at,ca.certificate FROM certificates c JOIN certificate_authorities ca ON ca.id=c.ca_id WHERE c.serial=?", leaf.SerialNumber.Text(16)).Scan(&owner, &raw, &revoked, &caPEM); err != nil {
		return "", fmt.Errorf("unregistered client certificate")
	}
	block, _ := pem.Decode([]byte(raw))
	if block == nil || !bytes.Equal(block.Bytes, leaf.Raw) || revoked != 0 || owner == "" || leaf.Subject.CommonName != owner {
		return "", fmt.Errorf("client certificate is revoked or identity does not match")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return "", fmt.Errorf("client certificate expired")
	}
	caBlock, _ := pem.Decode([]byte(caPEM))
	if caBlock == nil {
		return "", fmt.Errorf("invalid issuing CA")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil || leaf.CheckSignatureFrom(ca) != nil || now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return "", fmt.Errorf("invalid issuing CA")
	}
	return owner, nil
}
