package notification

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/sms"
	"github.com/rkislov/border/internal/store"
	"path/filepath"
	"strings"
	"testing"
)

func setup(t *testing.T) *Service {
	t.Helper()
	db, e := store.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.DB.Close() })
	if e = db.Migrate(t.Context()); e != nil {
		t.Fatal(e)
	}
	v, _ := auth.NewVault(make([]byte, 32))
	return &Service{Store: db, Vault: v}
}
func TestScopeInheritanceSecretsAndNoFallback(t *testing.T) {
	s := setup(t)
	ctx := t.Context()
	for _, id := range []string{"corp", "other"} {
		if e := s.Store.Exec(ctx, "INSERT INTO domains(id,name,config) VALUES(?,?,?)", id, id, "opaque"); e != nil {
			t.Fatal(e)
		}
	}
	c, _ := s.Config(ctx, "default")
	c.SMTP = SMTPConfig{Mode: "custom", Address: "smtp.example.test:465", Username: "sender", Password: "smtp-secret-only", From: "border@example.test", ImplicitTLS: true}
	c.SMS = SMSConfig{Mode: "custom", Config: sms.Config{Provider: "webhook", URL: "https://sms.example.test", Token: "sms-secret-12345678"}}
	c.Push = PushConfig{Mode: "custom", Contact: "admin@example.test"}
	if e := s.Save(ctx, c); e != nil {
		t.Fatal(e)
	}
	c, e := s.effective(ctx, "corp")
	if e != nil || c.SMTP.Password != "smtp-secret-only" {
		t.Fatal("inherit failed", e)
	}
	redacted, _ := json.Marshal(Redacted(c))
	if strings.Contains(string(redacted), "secret") || strings.Contains(string(redacted), "Private") {
		t.Fatal("secret in API")
	}
	var raw string
	s.Store.Row(ctx, "SELECT value FROM settings WHERE name='notifications:default'").Scan(&raw)
	if strings.Contains(raw, "smtp-secret") {
		t.Fatal("plaintext persisted")
	}
	c, _ = s.Config(ctx, "corp")
	c.SMTP.Mode = "disabled"
	c.SMS.Mode = "disabled"
	if e = s.Save(ctx, c); e != nil {
		t.Fatal(e)
	}
	if e = s.SendForIdentity(ctx, "corp/alice", "a@example.test", "event", "body"); e == nil || !strings.Contains(e.Error(), "disabled") {
		t.Fatal("domain disabled fallback", e)
	}
	if c, e = s.effective(ctx, "other"); e != nil || c.SMTP.Mode != "custom" {
		t.Fatal("other domain changed", e)
	}
	c, _ = s.Config(ctx, "default")
	key := c.Push.PublicKey
	c.SMTP.Password = ""
	c.SMTP.Address = "attacker.test:465"
	if e = s.Save(ctx, c); e == nil {
		t.Fatal("secret forwarded to new destination")
	}
	c, _ = s.Config(ctx, "default")
	c.SMTP.Password = ""
	c.SMS.Token = ""
	if e = s.Save(ctx, c); e != nil {
		t.Fatal(e)
	}
	c, _ = s.Config(ctx, "default")
	if c.SMTP.Password == "" || c.Push.PublicKey != key || c.Push.PrivateKey == "" {
		t.Fatal("credentials/key not preserved")
	}
	if _, e = s.effective(ctx, "missing"); e == nil {
		t.Fatal("unknown domain fallback")
	}
}
func TestPushOwnershipEncryptionValidation(t *testing.T) {
	s := setup(t)
	ctx := t.Context()
	c, _ := s.Config(ctx, "default")
	c.Push = PushConfig{Mode: "custom", Contact: "admin@example.test"}
	if e := s.Save(ctx, c); e != nil {
		t.Fatal(e)
	}
	for _, u := range []string{"local/alice", "local/bob"} {
		s.Store.Exec(ctx, "INSERT INTO identities(username,email) VALUES(?,?)", u, u+"@example.test")
	}
	key, _ := ecdh.P256().GenerateKey(rand.Reader)
	sub := webpush.Subscription{Endpoint: "https://fcm.googleapis.com/fcm/send/test", Keys: webpush.Keys{Auth: base64.RawURLEncoding.EncodeToString(make([]byte, 16)), P256dh: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())}}
	pub, _ := s.PushKey(ctx, "local/alice")
	if e := s.Subscribe(ctx, "local/alice", pub, sub); e != nil {
		t.Fatal(e)
	}
	if e := s.Subscribe(ctx, "local/bob", pub, sub); e == nil {
		t.Fatal("subscription stolen")
	}
	if e := s.Unsubscribe(ctx, "local/bob", sub.Endpoint); e != nil {
		t.Fatal(e)
	}
	var raw string
	s.Store.Row(ctx, "SELECT subscription FROM push_subscriptions").Scan(&raw)
	if strings.Contains(raw, "fcm.googleapis.com") {
		t.Fatal("push endpoint unencrypted")
	}
	for _, endpoint := range []string{"http://fcm.googleapis.com/test", "https://127.0.0.1/", "https://fcm.googleapis.com.attacker.test/", "https://user@fcm.googleapis.com/", "https://fcm.googleapis.com:8443/"} {
		bad := sub
		bad.Endpoint = endpoint
		if e := s.Subscribe(ctx, "local/alice", pub, bad); e == nil {
			t.Fatal("SSRF accepted", endpoint)
		}
	}
	if e := s.Subscribe(ctx, "local/alice", "wrong", sub); e == nil {
		t.Fatal("wrong VAPID key accepted")
	}
	if e := s.Unsubscribe(ctx, "local/alice", sub.Endpoint); e != nil {
		t.Fatal(e)
	}
	var n int
	s.Store.Row(ctx, "SELECT COUNT(*) FROM push_subscriptions").Scan(&n)
	if n != 0 {
		t.Fatal("unsubscribe failed")
	}
}
