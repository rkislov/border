// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rkislov/border/internal/auth"
)

func masterKey(path string) ([]byte, error) {
	f, err := regularFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	var key []byte
	count := 0
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		line = strings.TrimPrefix(line, "export ")
		name, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(name) != "BORDER_MASTER_KEY" {
			continue
		}
		count++
		value = strings.TrimSpace(value)
		if len(value) > 1 && ((value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"')) {
			value = value[1 : len(value)-1]
		}
		key, err = base64.StdEncoding.DecodeString(value)
		if err != nil || len(key) != 32 {
			return nil, errors.New("archived BORDER_MASTER_KEY must be a literal base64 32-byte key")
		}
	}
	if err = s.Err(); err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, errors.New("archived environment must contain one BORDER_MASTER_KEY")
	}
	return key, nil
}

// Refuse stale SQLite backup configuration after an environment-driven database move.
// Never include a DSN in the error: PostgreSQL URLs can contain credentials.
func checkSourceEnvironment(c Config) error {
	f, e := regularFile(c.EnvFile)
	if e != nil {
		return e
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := strings.TrimPrefix(strings.TrimSpace(scan.Text()), "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if len(v) > 1 && ((v[0] == '\'' && v[len(v)-1] == '\'') || (v[0] == '"' && v[len(v)-1] == '"')) {
			v = v[1 : len(v)-1]
		}
		switch k {
		case "BORDER_DB_DRIVER":
			if v != "" && v != "sqlite" {
				return errors.New("backup supports SQLite only; configured database driver differs")
			}
		case "BORDER_DB":
			if v != "" && v != c.RootDB {
				return errors.New("backup RootDB differs from BORDER_DB; use the same absolute path")
			}
		case "BORDER_TENANT_DIR":
			if v != "" && v != c.TenantDir {
				return errors.New("backup TenantDir differs from BORDER_TENANT_DIR; use the same absolute path")
			}
		}
	}
	return scan.Err()
}

func checkRecovery(ctx context.Context, dir string, m Manifest) (Report, error) {
	r := Report{Files: len(m.Files)}
	sources := map[string]string{}
	databases := map[string]File{}
	for _, v := range m.Files {
		if sources[v.Source] != "" {
			return r, errors.New("duplicate recovery source")
		}
		sources[v.Source] = filepath.Join(dir, filepath.FromSlash(v.Path))
		if v.Kind == "database" {
			if _, ok := databases[v.Tenant]; ok {
				return r, errors.New("duplicate database")
			}
			databases[v.Tenant] = v
		}
	}
	envPath, ok := sources[m.EnvFile]
	if !ok {
		return r, errors.New("environment missing from archive")
	}
	if m.Binary == "" || sources[m.Binary] == "" {
		return r, errors.New("Border executable missing from archive")
	}
	key, err := masterKey(envPath)
	if err != nil {
		return r, err
	}
	defer clear(key)
	root, ok := databases[""]
	if !ok || root.Path != "databases/root.db" {
		return r, errors.New("root database missing")
	}
	ids, err := tenants(ctx, filepath.Join(dir, root.Path))
	if err != nil {
		return r, err
	}
	if len(databases) != len(ids)+1 {
		return r, errors.New("tenant database set does not match catalog")
	}
	for _, id := range ids {
		v, ok := databases[id]
		if !ok || v.Path != "databases/tenants/"+id+".db" {
			return r, errors.New("tenant database missing")
		}
	}
	for id, v := range databases {
		k := key
		if id != "" {
			h := hmac.New(sha256.New, key)
			h.Write([]byte("Border tenant master v1\x00" + id))
			k = h.Sum(nil)
		}
		n, e := checkDatabase(ctx, filepath.Join(dir, v.Path), k)
		if id != "" {
			clear(k)
		}
		if e != nil {
			return r, fmt.Errorf("database recovery validation (%s): %w", v.Path, e)
		}
		r.Secrets += n
		r.Databases++
	}
	cert, keyPath := sources[filepath.Join(m.CertDir, "server.pem")], sources[filepath.Join(m.CertDir, "server.key")]
	if cert == "" || keyPath == "" {
		return r, errors.New("TLS certificate/key missing")
	}
	if _, err = tls.LoadX509KeyPair(cert, keyPath); err != nil {
		return r, errors.New("restored TLS certificate/key do not match")
	}
	ca := sources[filepath.Join(m.CertDir, "ca.pem")]
	if ca == "" {
		return r, errors.New("TLS trust CA missing")
	}
	b, err := os.ReadFile(ca)
	if err != nil {
		return r, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return r, errors.New("invalid restored TLS trust CA")
	}
	// Bootstrap CA/admin keys are optional on hardened servers; validate pairs when present.
	for _, name := range []string{"ca", "admin"} {
		k := sources[filepath.Join(m.CertDir, name+".key")]
		if k != "" {
			c := sources[filepath.Join(m.CertDir, name+".pem")]
			if c == "" {
				return r, errors.New("orphan TLS key")
			}
			if _, err = tls.LoadX509KeyPair(c, k); err != nil {
				return r, errors.New("restored bootstrap certificate/key do not match")
			}
		}
	}
	r.Tenants = len(ids)
	return r, nil
}

func checkDatabase(ctx context.Context, path string, key []byte) (int, error) {
	db, err := openDB(path)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var integrity string
	if err = db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		return 0, err
	}
	if integrity != "ok" {
		return 0, errors.New("SQLite integrity check failed")
	}
	rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return 0, err
	}
	bad := rows.Next()
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return 0, err
	}
	if bad {
		return 0, errors.New("SQLite foreign key check failed")
	}
	var version int
	if err = db.QueryRowContext(ctx, "SELECT MAX(version_id) FROM goose_db_version WHERE is_applied=1").Scan(&version); err != nil || version < 32 {
		return 0, errors.New("unsupported database schema")
	}
	vault, err := auth.NewVault(key)
	if err != nil {
		return 0, err
	}
	count := 0
	queries := []string{
		"SELECT 'totp:' || username,totp_secret FROM identities WHERE totp_secret<>''",
		"SELECT 'totp:' || username,pending_secret FROM identities WHERE pending_secret<>''",
		"SELECT 'domain:' || id,config FROM domains WHERE config<>''",
		"SELECT 'local-mschap/' || username,encrypted_hash FROM local_mschap_credentials",
		"SELECT 'routeros:' || nas,config FROM nas_routeros",
		"SELECT 'guest:' || id,phone_cipher FROM guest_challenges",
		"SELECT 'push:' || username || ':' || endpoint_hash,subscription FROM push_subscriptions",
		"SELECT 'policy-push:' || username,destination FROM policy_notification_targets WHERE channel='push' AND (enabled=1 OR destination<>'')",
		"SELECT CASE WHEN name='fingerbank_config' THEN 'fingerbank:config' WHEN name='sms_config' THEN 'sms:config' WHEN name LIKE 'acme-cache:%' THEN 'acme:' || substr(name,12) ELSE name END,value FROM settings WHERE value<>'' AND (name IN ('fingerbank_config','sms_config') OR name LIKE 'notifications:%' OR name LIKE 'acme-cache:%')",
	}
	if version >= 36 {
		queries = append(queries, "SELECT 'guest-oidc:' || scope || ':' || id,secret FROM guest_oidc_providers WHERE secret<>''")
	}
	if version >= 35 {
		queries = append(queries, "SELECT 'admin-totp:' || username,mfa_secret FROM admins WHERE mfa_secret<>''", "SELECT 'admin-totp:' || username,mfa_pending FROM admins WHERE mfa_pending<>''")
	}
	for _, q := range queries {
		n, e := checkSecrets(ctx, db, vault, q)
		if e != nil {
			return count, e
		}
		count += n
	}
	rows, err = db.QueryContext(ctx, "SELECT id,certificate,private_key FROM certificate_authorities")
	if err != nil {
		return count, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, cert, encrypted string
		if err = rows.Scan(&id, &cert, &encrypted); err != nil {
			return count, err
		}
		plain, e := vault.Open(encrypted, "ca:"+id)
		if e != nil {
			return count, errors.New("CA decryption failed")
		}
		err = checkCA(cert, plain)
		clear(plain)
		if err != nil {
			return count, err
		}
		count++
	}
	return count, rows.Err()
}
func checkSecrets(ctx context.Context, db *sql.DB, v *auth.Vault, q string) (int, error) {
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var aad, cipher string
		if err = rows.Scan(&aad, &cipher); err != nil {
			return n, err
		}
		plain, e := v.Open(cipher, aad)
		if e != nil {
			return n, errors.New("stored secret cannot be decrypted with archived master key")
		}
		clear(plain)
		n++
	}
	return n, rows.Err()
}
func checkCA(cert string, key []byte) error {
	b, _ := pem.Decode([]byte(cert))
	if b == nil {
		return errors.New("invalid CA certificate")
	}
	c, e := x509.ParseCertificate(b.Bytes)
	if e != nil {
		return e
	}
	k, e := x509.ParsePKCS8PrivateKey(key)
	if e != nil {
		return e
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return errors.New("unsupported CA key")
	}
	pub, e := x509.MarshalPKIXPublicKey(signer.Public())
	if e != nil {
		return e
	}
	expected, e := x509.MarshalPKIXPublicKey(c.PublicKey)
	if e != nil {
		return e
	}
	if !bytes.Equal(pub, expected) {
		return errors.New("CA certificate/key mismatch")
	}
	return nil
}
