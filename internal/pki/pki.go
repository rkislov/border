// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Generate creates a dedicated CA, HTTPS server certificate and admin client
// certificate. It refuses to overwrite any existing output file.
func Generate(dir, host string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	serial := func() *big.Int {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			panic(err)
		}
		return n
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Border local CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	cert, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return err
	}
	// Parse the actual CA so generated SubjectKeyId is available when signing
	// leaves; OpenSSL strict validation requires their AuthorityKeyIdentifier.
	ca, err = x509.ParseCertificate(cert)
	if err != nil {
		return err
	}
	write := func(name, typ string, b []byte) error {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		if err = pem.Encode(f, &pem.Block{Type: typ, Bytes: b}); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}
	writeKey := func(name string, k *ecdsa.PrivateKey) error {
		b, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return err
		}
		return write(name, "PRIVATE KEY", b)
	}
	for _, name := range []string{"ca.pem", "ca.key", "server.pem", "server.key", "admin.pem", "admin.key"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			return fmt.Errorf("refusing to overwrite %s", name)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if err = write("ca.pem", "CERTIFICATE", cert); err != nil {
		return err
	}
	if err = writeKey("ca.key", key); err != nil {
		return err
	}
	for _, name := range []string{"server", "admin"} {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		c := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Border " + name}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature}
		if name == "server" {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			if ip := net.ParseIP(host); ip != nil {
				c.IPAddresses = []net.IP{ip}
			} else {
				c.DNSNames = []string{host}
			}
		} else {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		b, err := x509.CreateCertificate(rand.Reader, c, ca, &k.PublicKey, key)
		if err != nil {
			return err
		}
		if err = write(name+".pem", "CERTIFICATE", b); err != nil {
			return err
		}
		if err = writeKey(name+".key", k); err != nil {
			return err
		}
	}
	return nil
}
