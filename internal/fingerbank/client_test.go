package fingerbank

import (
	"context"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/store"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPersistentCacheIsolationCoalescingAndStale(t *testing.T) {
	s, err := store.Open("sqlite", filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	ctx := context.Background()
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	vault, _ := auth.NewVault(make([]byte, 32))
	c := New(s, vault)
	var calls atomic.Int32
	var fail atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get("key") != "test-secret-123456789" {
			t.Error("key missing")
		}
		if fail.Load() {
			w.WriteHeader(429)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"device":{"id":42},"device_name":"Test device","score":80}`))
	}))
	defer server.Close()
	c.endpoint = server.URL
	c.http = server.Client()
	if err = c.Save(ctx, Config{Enabled: true, Key: "test-secret-123456789", TTLHours: 24}); err != nil {
		t.Fatal(err)
	}
	var raw string
	s.Row(ctx, "SELECT value FROM settings WHERE name='fingerbank_config'").Scan(&raw)
	if strings.Contains(raw, "test-secret") {
		t.Fatal("plaintext key")
	}
	e := Evidence{MAC: "00:11:22:33:44:55", DHCP: "1,3,6"}
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := c.Lookup(ctx, "tenant-a", e)
			if err != nil || r.DeviceID != 42 {
				t.Errorf("%+v %v", r, err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("duplicate network requests")
	}
	fresh := New(s, vault)
	fresh.endpoint = server.URL
	fresh.http = server.Client()
	r, err := fresh.Lookup(ctx, "tenant-a", e)
	if err != nil || !r.Cached {
		t.Fatal("cache not persistent")
	}
	if _, err = fresh.Lookup(ctx, "tenant-b", e); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("scope collision")
	}
	if err = s.Exec(ctx, "UPDATE fingerprint_cache SET expires_at=?", time.Now().Unix()-1); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	r, err = c.Lookup(ctx, "tenant-a", e)
	if err != nil || !r.Stale {
		t.Fatalf("stale %+v %v", r, err)
	}
	_, err = c.Lookup(ctx, "tenant-a", e)
	if err != nil || calls.Load() != 3 {
		t.Fatal("failed request not throttled")
	}
	if err = c.Save(ctx, Config{Enabled: true, TTLHours: 12}); err != nil {
		t.Fatal(err)
	}
	conf, err := c.Config(ctx)
	if err != nil || conf.Key != "test-secret-123456789" {
		t.Fatal("blank key not preserved")
	}
}
