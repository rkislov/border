package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/store"
)

func manager(t *testing.T) *Manager {
	t.Helper()
	s, err := store.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	vault, err := auth.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return &Manager{Store: s, Vault: vault}
}
func TestManagedCertificates(t *testing.T) {
	m := manager(t)
	ca, err := m.CreateCA(t.Context(), "Test root")
	if err != nil {
		t.Fatal(err)
	}
	var encrypted string
	if err = m.Store.Row(t.Context(), "SELECT private_key FROM certificate_authorities WHERE id=?", ca.ID).Scan(&encrypted); err != nil || strings.Contains(encrypted, "PRIVATE KEY") {
		t.Fatal("CA key not encrypted")
	}
	b, err := m.Issue(t.Context(), ca.ID, "user", "user@example.test", "", "https://portal.example.test/crl/"+ca.ID, 90)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair([]byte(b.Certificate), []byte(b.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(ca.Certificate))
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	if len(cert.EmailAddresses) != 1 || cert.Subject.CommonName != "user" || len(cert.CRLDistributionPoints) != 1 {
		t.Fatal("certificate identity or CRL missing")
	}
	if _, err = m.Issue(t.Context(), ca.ID, "other", "", b.Serial, "", 90); err == nil {
		t.Fatal("cross-user renewal")
	}
	if err = m.Revoke(t.Context(), b.Serial, "other"); err == nil {
		t.Fatal("cross-user revocation")
	}
	newCert, err := m.Issue(t.Context(), ca.ID, "user", "user@example.test", b.Serial, "", 90)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Revoke(t.Context(), newCert.Serial, "user"); err != nil {
		t.Fatal(err)
	}
	crl, err := m.CRL(t.Context(), ca.ID)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseRevocationList(crl)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(ca.Certificate))
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err = parsed.CheckSignatureFrom(root); err != nil {
		t.Fatal(err)
	}
	if len(parsed.RevokedCertificateEntries) != 2 {
		t.Fatal("missing revocations")
	}
	list, err := m.Certificates(t.Context(), "other")
	if err != nil || len(list) != 0 {
		t.Fatal("owner filtering")
	}
	if _, err = m.Issue(t.Context(), ca.ID, "user", "", "", "", 366); err == nil {
		t.Fatal("invalid lifetime")
	}
	if _, err = m.ImportCA(t.Context(), "bad", b.Certificate, b.PrivateKey); err == nil {
		t.Fatal("leaf imported as CA")
	}
}
func TestACMEConfigAndEncryptedCache(t *testing.T) {
	m := manager(t)
	a, err := NewACME(t.Context(), m)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Configure(t.Context(), ACMEConfig{Enabled: true, Domain: "example.test", Email: "admin@example.test"}); err == nil {
		t.Fatal("missing terms accepted")
	}
	if err = a.Configure(t.Context(), ACMEConfig{Enabled: true, Domain: "*.example.test", Email: "admin@example.test", AcceptTerms: true}); err == nil {
		t.Fatal("wildcard accepted")
	}
	c := ACMEConfig{Enabled: true, Domain: "radius.example.test", Email: "admin@example.test", AcceptTerms: true, DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}
	if err = a.Configure(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	loaded, err := NewACME(t.Context(), m)
	if err != nil || loaded.Config().Domain != c.Domain {
		t.Fatal("ACME config persistence", err)
	}
	cert, err := a.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.test"})
	if err != nil || cert != nil {
		t.Fatal("unexpected domain served")
	}
	cache := acmeCache{m}
	if err = cache.Put(t.Context(), "test", []byte("private-key-value")); err != nil {
		t.Fatal(err)
	}
	value, err := cache.Get(t.Context(), "test")
	if err != nil || string(value) != "private-key-value" {
		t.Fatal("cache", err)
	}
	var raw string
	if err = m.Store.Row(t.Context(), "SELECT value FROM settings WHERE name='acme-cache:test'").Scan(&raw); err != nil || strings.Contains(raw, "private-key-value") {
		t.Fatal("ACME cache not encrypted")
	}
	if err = cache.Delete(t.Context(), "test"); err != nil {
		t.Fatal(err)
	}
	if _, err = cache.Get(t.Context(), "test"); err == nil {
		t.Fatal("cache delete")
	}
	w := httptest.NewRecorder()
	a.HTTPHandler().ServeHTTP(w, httptest.NewRequest("GET", "http://radius.example.test/unrelated", nil))
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
	if err = a.Configure(t.Context(), ACMEConfig{}); err != nil {
		t.Fatal(err)
	}
}
