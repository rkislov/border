// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/store"
)

type Manager struct {
	Store *store.Store
	Vault *auth.Vault
}
type Authority struct {
	ID, Name, Certificate string
	Created               int64
}
type Certificate struct {
	Serial, CA, Owner, Certificate string
	Expires, Revoked               int64
}
type Bundle struct{ Serial, Certificate, PrivateKey, CA string }

func serial() *big.Int {
	v, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		panic(err)
	}
	return v.Add(v, big.NewInt(1))
}
func encodeCert(b []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}))
}
func (m *Manager) CreateCA(ctx context.Context, name string) (Authority, error) {
	if name == "" || len(name) > 100 {
		return Authority{}, fmt.Errorf("CA name required, up to 100 characters")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Authority{}, err
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return Authority{}, err
	}
	k, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Authority{}, err
	}
	defer clear(k)
	return m.ImportCA(ctx, name, encodeCert(der), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})))
}
func (m *Manager) ImportCA(ctx context.Context, name, certPEM, keyPEM string) (Authority, error) {
	if name == "" || len(name) > 100 {
		return Authority{}, fmt.Errorf("invalid CA name")
	}
	cb, _ := pem.Decode([]byte(certPEM))
	kb, _ := pem.Decode([]byte(keyPEM))
	if cb == nil || kb == nil {
		return Authority{}, fmt.Errorf("certificate and PKCS8 private key PEM required")
	}
	defer clear(kb.Bytes)
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 || cert.KeyUsage&x509.KeyUsageCRLSign == 0 || time.Now().After(cert.NotAfter) {
		return Authority{}, fmt.Errorf("CA must be valid and permit certificate and CRL signing")
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return Authority{}, fmt.Errorf("PKCS8 key required")
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return Authority{}, fmt.Errorf("unsupported CA key")
	}
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return Authority{}, err
	}
	expected, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil || hex.EncodeToString(pub) != hex.EncodeToString(expected) {
		return Authority{}, fmt.Errorf("certificate and key do not match")
	}
	id := uuid.NewString()
	a := Authority{ID: id, Name: name, Certificate: certPEM, Created: time.Now().Unix()}
	encrypted := m.Vault.Seal(kb.Bytes, "ca:"+id)
	err = m.Store.Exec(ctx, "INSERT INTO certificate_authorities(id,name,certificate,private_key,created_at) VALUES (?,?,?,?,?)", id, name, certPEM, encrypted, a.Created)
	return a, err
}
func (m *Manager) Authorities(ctx context.Context) ([]Authority, error) {
	rows, err := m.Store.DB.QueryContext(ctx, "SELECT id,name,certificate,created_at FROM certificate_authorities ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Authority{}
	for rows.Next() {
		var a Authority
		if err = rows.Scan(&a.ID, &a.Name, &a.Certificate, &a.Created); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (m *Manager) authority(ctx context.Context, id string) (*x509.Certificate, crypto.Signer, string, error) {
	var certPEM, encrypted string
	if err := m.Store.Row(ctx, "SELECT certificate,private_key FROM certificate_authorities WHERE id=?", id).Scan(&certPEM, &encrypted); err != nil {
		return nil, nil, "", err
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, nil, "", fmt.Errorf("invalid CA")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, "", err
	}
	plain, err := m.Vault.Open(encrypted, "ca:"+id)
	if err != nil {
		return nil, nil, "", err
	}
	defer clear(plain)
	key, err := x509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		return nil, nil, "", err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, "", fmt.Errorf("unsupported key")
	}
	return cert, signer, certPEM, nil
}
func (m *Manager) Certificates(ctx context.Context, owner string) ([]Certificate, error) {
	q := "SELECT serial,ca_id,owner,certificate,expires_at,revoked_at FROM certificates"
	args := []any{}
	if owner != "" {
		q += " WHERE owner=?"
		args = append(args, owner)
	}
	q += " ORDER BY expires_at DESC LIMIT 200"
	rows, err := m.Store.DB.QueryContext(ctx, m.Store.SQL(q), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Certificate{}
	for rows.Next() {
		var c Certificate
		if err = rows.Scan(&c.Serial, &c.CA, &c.Owner, &c.Certificate, &c.Expires, &c.Revoked); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Issue generates a new client key, returns it once and never stores it.
// renewal, when supplied, atomically revokes the old certificate owned by user.
func (m *Manager) Issue(ctx context.Context, caID, user, email, renewal, crlURL string, days int) (Bundle, error) {
	if user == "" || len(user) > 200 || days < 1 || days > 365 {
		return Bundle{}, fmt.Errorf("invalid owner or lifetime (1–365 days)")
	}
	ca, key, caPEM, err := m.authority(ctx, caID)
	if err != nil {
		return Bundle{}, err
	}
	now := time.Now()
	expires := now.Add(time.Duration(days) * 24 * time.Hour)
	if expires.After(ca.NotAfter) || now.Before(ca.NotBefore) {
		return Bundle{}, fmt.Errorf("CA validity does not cover requested certificate")
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Bundle{}, err
	}
	template := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: user}, NotBefore: now.Add(-time.Minute), NotAfter: expires, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	if email != "" {
		template.EmailAddresses = []string{email}
	}
	if crlURL != "" {
		template.CRLDistributionPoints = []string{crlURL}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &clientKey.PublicKey, key)
	if err != nil {
		return Bundle{}, err
	}
	priv, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		return Bundle{}, err
	}
	defer clear(priv)
	b := Bundle{Serial: template.SerialNumber.Text(16), Certificate: encodeCert(der), PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})), CA: caPEM}
	tx, err := m.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return Bundle{}, err
	}
	defer tx.Rollback()
	if renewal != "" {
		r, err := tx.ExecContext(ctx, m.Store.SQL("UPDATE certificates SET revoked_at=? WHERE serial=? AND owner=? AND ca_id=? AND revoked_at=0"), now.Unix(), renewal, user, caID)
		if err != nil {
			return Bundle{}, err
		}
		n, err := r.RowsAffected()
		if err != nil || n != 1 {
			return Bundle{}, fmt.Errorf("active certificate owned by this user required for reissue")
		}
	}
	if _, err = tx.ExecContext(ctx, m.Store.SQL("INSERT INTO certificates(serial,ca_id,owner,certificate,expires_at) VALUES (?,?,?,?,?)"), b.Serial, caID, user, b.Certificate, expires.Unix()); err != nil {
		return Bundle{}, err
	}
	if err = tx.Commit(); err != nil {
		return Bundle{}, err
	}
	return b, nil
}
func (m *Manager) Revoke(ctx context.Context, serial, owner string) error {
	q := "UPDATE certificates SET revoked_at=? WHERE serial=? AND revoked_at=0"
	args := []any{time.Now().Unix(), serial}
	if owner != "" {
		q += " AND owner=?"
		args = append(args, owner)
	}
	r, err := m.Store.DB.ExecContext(ctx, m.Store.SQL(q), args...)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("active certificate not found")
	}
	return nil
}
func (m *Manager) CRL(ctx context.Context, id string) ([]byte, error) {
	ca, key, _, err := m.authority(ctx, id)
	if err != nil {
		return nil, err
	}
	rows, err := m.Store.DB.QueryContext(ctx, m.Store.SQL("SELECT serial,revoked_at FROM certificates WHERE ca_id=? AND revoked_at>0"), id)
	if err != nil {
		return nil, err
	}
	var entries []x509.RevocationListEntry
	for rows.Next() {
		var raw string
		var at int64
		if err = rows.Scan(&raw, &at); err != nil {
			rows.Close()
			return nil, err
		}
		n, ok := new(big.Int).SetString(raw, 16)
		if !ok {
			rows.Close()
			return nil, fmt.Errorf("invalid serial")
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: n, RevocationTime: time.Unix(at, 0), ReasonCode: 1})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(now.UnixNano()), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(24 * time.Hour), RevokedCertificateEntries: entries}, ca, key)
}
