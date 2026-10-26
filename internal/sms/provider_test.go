package sms

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPSDeliveryAndRedirectRejection(t *testing.T) {
	hits := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("Authorization") != "Bearer test-token-123456789" {
			t.Error("missing token")
		}
		var m map[string]string
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			t.Error(err)
		}
		if m["to"] != "+79991234567" {
			t.Error("wrong recipient")
		}
		if hits == 2 {
			w.Header().Set("Location", "https://example.org")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(202)
	}))
	defer server.Close()
	c := Config{Provider: "webhook", URL: server.URL, Token: "test-token-123456789", CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))}
	p, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err = p.Send(context.Background(), "+79991234567", "test"); err != nil {
		t.Fatal(err)
	}
	if err = p.Send(context.Background(), "+79991234567", "test"); err == nil {
		t.Fatal("redirect accepted")
	}
	c.URL = "http://localhost"
	if _, err = New(c); err == nil {
		t.Fatal("cleartext provider")
	}
}
