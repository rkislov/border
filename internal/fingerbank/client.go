// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package fingerbank

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/identity"
	"github.com/rkislov/border/internal/store"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Enabled  bool
	Key      string
	TTLHours int
}
type Evidence struct {
	MAC    string `json:"mac,omitempty"`
	DHCP   string `json:"dhcp_fingerprint,omitempty"`
	Vendor string `json:"dhcp_vendor,omitempty"`
}
type Result struct {
	DeviceName              string
	DeviceID, Score         int
	Cached, Stale, NotFound bool
	UpdatedAt               int64
}
type Client struct {
	Store    *store.Store
	Vault    *auth.Vault
	mu       sync.Mutex
	http     *http.Client
	endpoint string
}

func New(s *store.Store, v *auth.Vault) *Client {
	return &Client{Store: s, Vault: v, endpoint: "https://api.fingerbank.org/api/v2/combinations/interrogate", http: &http.Client{Timeout: 7 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (c *Client) Config(ctx context.Context) (Config, error) {
	out := Config{TTLHours: 168}
	var raw string
	err := c.Store.Row(ctx, "SELECT value FROM settings WHERE name='fingerbank_config'").Scan(&raw)
	if err == sql.ErrNoRows {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if c.Vault == nil {
		return out, fmt.Errorf("BORDER_MASTER_KEY required")
	}
	b, err := c.Vault.Open(raw, "fingerbank:config")
	if err != nil {
		return out, fmt.Errorf("Fingerbank settings unavailable")
	}
	defer clear(b)
	err = json.Unmarshal(b, &out)
	return out, err
}
func (c *Client) Save(ctx context.Context, v Config) error {
	if c.Vault == nil {
		return fmt.Errorf("BORDER_MASTER_KEY required")
	}
	if v.TTLHours < 1 || v.TTLHours > 720 {
		return fmt.Errorf("cache TTL: 1–720 hours")
	}
	old, err := c.Config(ctx)
	if err != nil {
		return err
	}
	if v.Key == "" {
		v.Key = old.Key
	}
	if v.Enabled && (len(v.Key) < 16 || len(v.Key) > 256 || strings.ContainsAny(v.Key, "\r\n")) {
		return fmt.Errorf("invalid Fingerbank key")
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	defer clear(raw)
	return c.Store.Exec(ctx, "INSERT INTO settings(name,value) VALUES('fingerbank_config',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", c.Vault.Seal(raw, "fingerbank:config"))
}
func (c *Client) Lookup(ctx context.Context, scope string, e Evidence) (Result, error) {
	if scope == "" {
		return Result{}, fmt.Errorf("scope required")
	}
	mac, err := identity.MAC(e.MAC)
	if err != nil {
		return Result{}, err
	}
	e.MAC = strings.ReplaceAll(mac, ":", "")
	if len(e.DHCP) > 1024 || len(e.Vendor) > 253 {
		return Result{}, fmt.Errorf("fingerprint too large")
	}
	conf, err := c.Config(ctx)
	if err != nil {
		return Result{}, err
	}
	if !conf.Enabled {
		return Result{}, fmt.Errorf("Fingerbank is disabled")
	}
	raw, _ := json.Marshal(e)
	sum := sha256.Sum256(append([]byte("v2:"+scope+"\x00"), raw...))
	key := hex.EncodeToString(sum[:])
	// Recheck the persistent cache under the lock to coalesce simultaneous misses.
	c.mu.Lock()
	defer c.mu.Unlock()
	if err = ctx.Err(); err != nil {
		return Result{}, err
	}
	var saved string
	var updated, expires, retry int64
	err = c.Store.Row(ctx, "SELECT result,updated_at,expires_at,retry_at FROM fingerprint_cache WHERE cache_key=?", key).Scan(&saved, &updated, &expires, &retry)
	if err != nil && err != sql.ErrNoRows {
		return Result{}, err
	}
	now := time.Now().Unix()
	var previous Result
	has := saved != "" && json.Unmarshal([]byte(saved), &previous) == nil
	if has && expires > now {
		previous.Cached = true
		return previous, nil
	}
	stale := func() (Result, error) {
		if has && updated > now-30*86400 {
			previous.Cached = true
			previous.Stale = true
			return previous, nil
		}
		return Result{}, fmt.Errorf("Fingerbank temporarily unavailable")
	}
	if retry > now {
		return stale()
	}
	u, err := url.Parse(c.endpoint)
	if err != nil {
		return Result{}, fmt.Errorf("invalid endpoint")
	}
	q := u.Query()
	q.Set("key", conf.Key)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(raw))
	if err != nil {
		return Result{}, fmt.Errorf("Fingerbank request failed")
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	var result Result
	ok := false
	if err == nil {
		defer response.Body.Close()
		if response.StatusCode == 404 {
			result.NotFound = true
			ok = true
		} else if response.StatusCode == 200 {
			var body struct {
				DeviceName string `json:"device_name"`
				Score      int    `json:"score"`
				Device     struct {
					ID   int    `json:"id"`
					Name string `json:"name"`
				} `json:"device"`
			}
			b, e := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
			if e == nil && len(b) <= 1024*1024 && json.Unmarshal(b, &body) == nil && body.Device.ID > 0 && body.Score >= 0 && body.Score <= 100 {
				result = Result{DeviceName: body.DeviceName, DeviceID: body.Device.ID, Score: body.Score}
				if result.DeviceName == "" {
					result.DeviceName = body.Device.Name
				}
				ok = len(result.DeviceName) <= 2048
			}
		}
	}
	if !ok {
		if err = c.Store.Exec(ctx, "INSERT INTO fingerprint_cache(cache_key,result,updated_at,expires_at,retry_at) VALUES(?,?,?,?,?) ON CONFLICT(cache_key) DO UPDATE SET retry_at=excluded.retry_at", key, "", 0, 0, now+300); err != nil {
			return Result{}, fmt.Errorf("fingerprint cache unavailable")
		}
		return stale()
	}
	result.UpdatedAt = now
	ttl := int64(conf.TTLHours) * 3600
	if result.NotFound {
		ttl = 3600
	}
	encoded, _ := json.Marshal(result)
	if err = c.Store.Exec(ctx, "INSERT INTO fingerprint_cache(cache_key,result,updated_at,expires_at,retry_at) VALUES(?,?,?,?,0) ON CONFLICT(cache_key) DO UPDATE SET result=excluded.result,updated_at=excluded.updated_at,expires_at=excluded.expires_at,retry_at=0", key, string(encoded), now, now+ttl); err != nil {
		return Result{}, fmt.Errorf("fingerprint cache unavailable")
	}
	return result, nil
}
