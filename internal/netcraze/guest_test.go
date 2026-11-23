// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package netcraze

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rkislov/border/internal/aaa"
	"github.com/rkislov/border/internal/auth"
	"github.com/rkislov/border/internal/guest"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

const testNAS = "192.0.2.10"
const testMAC = "02:00:00:00:00:01"
const testSID = "session-123"
const testSecret = "radius-test-secret-12345"

type rig struct {
	service                                *Service
	cfg                                    Config
	mu                                     sync.Mutex
	commands, logins, requests             int
	active, duplicate, omitUnauthenticated bool
	omitDefaultPorts                       bool
	sid, bridge                            string
	beforeLogin                            func()
	server                                 *httptest.Server
}

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func fixture(t *testing.T) *rig {
	t.Helper()
	ctx := t.Context()
	db, e := store.Open("sqlite", filepath.Join(t.TempDir(), "tenant.db"))
	must(t, e)
	t.Cleanup(func() { db.DB.Close() })
	must(t, db.Migrate(ctx))
	v, e := auth.NewVault(make([]byte, 32))
	must(t, e)
	r := &rig{service: &Service{Store: db, Vault: v, PublicURL: "https://portal.example/portal/tenant-a"}, sid: testSID, bridge: "Bridge2"}
	for _, q := range []string{"INSERT INTO vlan_catalog VALUES(231,'Guest')", "INSERT INTO network_segments VALUES('guest','Guest')", "INSERT INTO nas(address,name,secret,dictionary,access_mode,portal_enabled) VALUES('192.0.2.10','Netcraze','radius-test-secret-12345','keenetic','network',1)", "UPDATE guest_policy SET enabled=1"} {
		must(t, db.Exec(ctx, q))
	}
	must(t, db.SaveAuthentication(ctx, store.AuthenticationPolicy{ID: "guest", Name: "Guest", Source: "guest", GuestMethods: []string{"sms", "email"}, Enabled: true}))
	must(t, db.SaveAccess(ctx, store.AccessPolicy{ID: "guest", Name: "Guest", AuthenticationID: "guest", Mode: "network", SegmentID: "guest", SessionSeconds: 600, Enabled: true}))
	must(t, db.SaveRules(ctx, store.RuleSet{PolicyID: "guest", Enabled: true, Rules: []store.AccessRule{{ID: "all", Name: "All", Effect: "allow", AllAuthenticated: true, Enabled: true}}}))
	must(t, db.SaveMapping(ctx, store.SegmentMapping{NAS: testNAS, SegmentID: "guest", VLAN: 231}))
	must(t, db.Exec(ctx, "UPDATE nas SET access_policy_id='guest'"))
	design, e := db.PortalDesign(ctx, "tenant")
	must(t, e)
	design.LoginMethod = "both"
	design.Custom = true
	must(t, db.SavePortalDesign(ctx, "tenant", design))
	r.server = httptest.NewTLSServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.server.Close)
	sum := sha256.Sum256(r.server.Certificate().Raw)
	r.cfg = Config{Enabled: true, Address: r.server.URL, HTTPHost: "192.0.2.10", Username: "border", Password: "private-management-password", CertificateSHA256: hex.EncodeToString(sum[:]), Chilli: "Chilli0", Bridge: "Bridge2", Subnet: "192.0.2.0/24", SegmentID: "guest", VLAN: 231, NASIdentifier: "border-guest", RadiusServer: "198.51.100.10", AuthPort: 1812, AccountingPort: 1813, UAMSecret: "private-uam-secret-12345"}
	must(t, r.service.Save(ctx, testNAS, r.cfg))
	return r
}
func (r *rig) serve(w http.ResponseWriter, q *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests++
	if q.Host != r.cfg.HTTPHost {
		http.Error(w, "Host mismatch", 403)
		return
	}
	if q.URL.Path == "/auth" {
		if q.Method == "GET" {
			w.Header().Set("X-NDM-Realm", "Netcraze")
			w.Header().Set("X-NDM-Challenge", "challenge")
			http.SetCookie(w, &http.Cookie{Name: "challenge", Value: "yes", Path: "/"})
			w.WriteHeader(401)
			return
		}
		var v map[string]string
		json.NewDecoder(q.Body).Decode(&v)
		inner := md5.Sum([]byte(r.cfg.Username + ":Netcraze:" + r.cfg.Password))
		outer := sha256.Sum256([]byte("challenge" + hex.EncodeToString(inner[:])))
		cookie, e := q.Cookie("challenge")
		if e != nil || cookie.Value != "yes" || v["login"] != r.cfg.Username || v["password"] != hex.EncodeToString(outer[:]) {
			w.WriteHeader(403)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "authorized", Value: "yes", Path: "/"})
		w.WriteHeader(200)
		return
	}
	if c, e := q.Cookie("authorized"); e != nil || c.Value != "yes" {
		w.WriteHeader(403)
		return
	}
	var v map[string]string
	json.NewDecoder(q.Body).Decode(&v)
	r.commands++
	var result any
	switch v["parse"] {
	case "show rc interface Chilli0":
		c := interfaceConfig{Up: true, Security: map[string]bool{"protected": true}}
		c.IP.Address.Address = "192.0.2.1"
		c.IP.Address.Mask = "255.255.255.0"
		c.Chilli.Dhcpif = r.bridge
		c.Chilli.Uamserver, _ = RedirectURL(r.service.PublicURL, testNAS)
		c.Chilli.Uamsecret = r.cfg.UAMSecret
		c.Chilli.Radiussecret = testSecret
		c.Chilli.Radiusnasid = r.cfg.NASIdentifier
		c.Chilli.Nasip.Address = testNAS
		c.Chilli.Radius.Server1 = r.cfg.RadiusServer
		c.Chilli.Radiusauthport = "1812"
		c.Chilli.Radiusacctport = "1813"
		c.Chilli.Coaport = "3799"
		if r.omitDefaultPorts {
			c.Chilli.Radiusauthport = ""
			c.Chilli.Radiusacctport = ""
		}
		result = map[string]any{"interface": map[string]any{"Chilli0": c}}
	case "show interface Chilli0 chilli":
		h := host{SessionID: r.sid, IP: "192.0.2.7", MAC: testMAC}
		if r.active {
			h.User = testMAC
		}
		hosts := []host{h}
		if r.omitUnauthenticated && !r.active {
			hosts = nil
		}
		if r.duplicate {
			hosts = append(hosts, h)
		}
		result = map[string]any{"host": hosts}
		if r.beforeLogin != nil {
			f := r.beforeLogin
			r.beforeLogin = nil
			f()
		}
	case "interface Chilli0 chilli login " + testMAC + " username " + testMAC + " password " + testMAC:
		r.logins++
		r.active = true
		result = map[string]any{"status": []any{map[string]string{"status": "message"}}}
	default:
		result = map[string]any{"status": []any{map[string]string{"status": "error", "message": "sensitive-router-error"}}}
	}
	json.NewEncoder(w).Encode(map[string]any{"parse": result})
}
func (r *rig) grant(t *testing.T) store.GuestAuthorization {
	t.Helper()
	b, e := r.service.Store.GuestAccessPolicy(t.Context(), testNAS, testMAC, "", "email")
	must(t, e)
	g := store.GuestAuthorization{ID: strings.Repeat("a", 64), NAS: testNAS, MAC: testMAC, NASSessionID: testSID, Identity: "guest-email:test", Method: "email", PolicyID: "guest", PolicyHash: store.GuestPolicyHash(b), Expires: time.Now().Unix() + 300, ActivationState: "pending"}
	must(t, r.service.Store.SaveGuestAuthorization(t.Context(), g))
	return g
}
func (r *rig) query(t *testing.T) string {
	t.Helper()
	u, e := RedirectURL(r.service.PublicURL, testNAS)
	must(t, e)
	q := url.Values{"res": {"notyet"}, "mac": {testMAC}, "ip": {"192.0.2.7"}, "sessionid": {testSID}, "nasid": {r.cfg.NASIdentifier}, "challenge": {strings.Repeat("a", 32)}, "uamip": {"192.0.2.1"}, "userurl": {"https://evil.example/"}}.Encode()
	h := md5.Sum([]byte(u + "?" + q + r.cfg.UAMSecret))
	return q + "&md=" + hex.EncodeToString(h[:])
}
func TestActivationGuardsAndRetry(t *testing.T) {
	for _, tc := range []string{"success", "wrong-pin", "wrong-bridge", "wrong-vlan", "changed-session", "duplicate-host", "revoked", "revoked-during-inspection", "expired", "disabled", "command-injection"} {
		t.Run(tc, func(t *testing.T) {
			r := fixture(t)
			g := r.grant(t)
			vlan := 231
			switch tc {
			case "wrong-pin":
				c := r.cfg
				c.CertificateSHA256 = strings.Repeat("0", 64)
				must(t, r.service.Save(t.Context(), testNAS, c))
				g = r.grant(t)
			case "wrong-bridge":
				r.bridge = "Bridge9"
			case "wrong-vlan":
				vlan = 232
			case "changed-session":
				r.sid = "replacement"
			case "duplicate-host":
				r.duplicate = true
			case "revoked":
				must(t, r.service.Store.RevokeGuest(t.Context(), testNAS, testMAC, g.ID))
			case "revoked-during-inspection":
				r.beforeLogin = func() { must(t, r.service.Store.RevokeGuest(context.Background(), testNAS, testMAC, g.ID)) }
			case "expired":
				must(t, r.service.Store.Exec(t.Context(), "UPDATE guest_authorizations SET expires_at=1"))
			case "disabled":
				c := r.cfg
				c.Enabled = false
				must(t, r.service.Save(t.Context(), testNAS, c))
			case "command-injection":
				g.MAC += "; system reboot"
			}
			handled, e := r.service.ActivateGuest(t.Context(), g, vlan)
			if tc == "success" {
				if !handled || e != nil {
					t.Fatal(handled, e)
				}
				handled, e = r.service.ActivateGuest(t.Context(), g, vlan)
				if !handled || e != nil {
					t.Fatal(handled, e)
				}
				if r.logins != 1 {
					t.Fatal("retry repeated login", r.logins)
				}
			} else if tc == "disabled" {
				if handled || e != nil {
					t.Fatal("disabled adapter not manual")
				}
			} else {
				if !handled || e == nil || r.logins != 0 {
					t.Fatal("unsafe activation", handled, e, r.logins)
				}
				if strings.Contains(e.Error(), r.cfg.Password) || strings.Contains(e.Error(), "sensitive-router-error") {
					t.Fatal("secret leak")
				}
			}
		})
	}
}
func TestRedirectSignatureScopeAndSession(t *testing.T) {
	for _, tc := range []string{"valid", "signature", "other-tenant", "other-nas", "duplicate", "changed-session", "authenticated"} {
		t.Run(tc, func(t *testing.T) {
			r := fixture(t)
			q := r.query(t)
			public := r.service.PublicURL
			nas := testNAS
			switch tc {
			case "signature":
				q = strings.Replace(q, "192.0.2.7", "192.0.2.8", 1)
			case "other-tenant":
				public = "https://portal.example/portal/tenant-b"
			case "other-nas":
				nas = "192.0.2.11"
			case "duplicate":
				q += "&md=" + strings.Repeat("0", 32)
			case "changed-session":
				r.sid = "new-session"
			case "authenticated":
				r.active = true
			}
			token, e := r.service.Redirect(t.Context(), nas, q, public)
			if tc == "valid" {
				if e != nil || token == "" {
					t.Fatal(e)
				}
				if strings.Contains(token, "evil.example") {
					t.Fatal("user URL forwarded")
				}
			} else if e == nil || token != "" {
				t.Fatal("invalid redirect accepted")
			}
			if (tc == "signature" || tc == "other-tenant" || tc == "other-nas" || tc == "duplicate") && r.requests != 0 {
				t.Fatal("unverified redirect contacted NAS")
			}
		})
	}
}
func TestEncryptedConfigIsolationAndRevocation(t *testing.T) {
	r := fixture(t)
	g := r.grant(t)
	var raw string
	must(t, r.service.Store.Row(t.Context(), "SELECT config FROM nas_netcraze").Scan(&raw))
	if strings.Contains(raw, r.cfg.Password) || strings.Contains(raw, r.cfg.UAMSecret) {
		t.Fatal("plaintext credentials")
	}
	if _, e := r.service.Vault.Open(raw, "netcraze:192.0.2.11"); e == nil {
		t.Fatal("NAS binding missing")
	}
	other, _ := auth.NewVault([]byte(strings.Repeat("b", 32)))
	if _, e := other.Open(raw, "netcraze:"+testNAS); e == nil {
		t.Fatal("tenant binding missing")
	}
	c := r.cfg
	c.Password = ""
	c.UAMSecret = ""
	must(t, r.service.Save(t.Context(), testNAS, c))
	saved, e := r.service.Config(t.Context(), testNAS)
	must(t, e)
	if saved.Password != r.cfg.Password || saved.UAMSecret != r.cfg.UAMSecret {
		t.Fatal("blank secret retention")
	}
	if _, e = r.service.Store.GuestAuthorization(t.Context(), testNAS, testMAC); e != nil {
		t.Fatal("unchanged config revoked access", e)
	}
	c.Address = "https://192.0.2.22"
	if e = r.service.Save(t.Context(), testNAS, c); e == nil {
		t.Fatal("credentials reused for changed target")
	}
	c = r.cfg
	c.Enabled = false
	must(t, r.service.Save(t.Context(), testNAS, c))
	if _, e = r.service.Store.GuestAuthorization(t.Context(), g.NAS, g.MAC); e == nil {
		t.Fatal("changed adapter retained guest authorization")
	}
	must(t, r.service.Store.Exec(t.Context(), "DELETE FROM nas WHERE address=?", testNAS))
	var n int
	must(t, r.service.Store.Row(t.Context(), "SELECT COUNT(*) FROM nas_netcraze").Scan(&n))
	if n != 0 {
		t.Fatal("orphan config")
	}
}
func radiusLogin(t *testing.T, r *rig, sid string) (*radius.Packet, error) {
	t.Helper()
	p := radius.New(radius.CodeAccessRequest, []byte(testSecret))
	rfc2865.UserName_SetString(p, testMAC)
	rfc2865.UserPassword_SetString(p, testMAC)
	rfc2865.CallingStationID_SetString(p, testMAC)
	rfc2866.AcctSessionID_SetString(p, sid)
	must(t, aaa.SignMessageAuthenticator(p))
	b, e := p.Encode()
	must(t, e)
	b, e = aaa.ProcessWithOptions(t.Context(), r.service.Store, b, &net.UDPAddr{IP: net.ParseIP(testNAS)}, false, aaa.Options{})
	if e != nil {
		return nil, e
	}
	return radius.Parse(b, []byte(testSecret))
}
func TestEmailActivationRestartAndRADIUSSessionBinding(t *testing.T) {
	r := fixture(t)
	r.omitUnauthenticated = true
	g, e := guest.New(r.service.Store, make([]byte, 32))
	must(t, e)
	defer g.Close()
	g.Activate = r.service.ActivateGuest
	g.PublicURL = r.service.PublicURL
	var message string
	g.AvailableChannels = func(context.Context, string, string) ([]string, error) { return []string{"email"}, nil }
	g.SendEmail = func(_ context.Context, _, _, _, body string) error { message = body; return nil }
	token, e := r.service.Redirect(t.Context(), testNAS, r.query(t), r.service.PublicURL)
	must(t, e)
	ch, e := g.RequestContact(t.Context(), token, "email", "guest@example.test")
	must(t, e)
	code := strings.Split(strings.Split(message, "code: ")[1], ".")[0]
	grant, e := g.Confirm(t.Context(), ch.ID, code)
	must(t, e)
	actual, e := r.service.Store.GuestAuthorization(t.Context(), testNAS, testMAC)
	must(t, e)
	if actual.NASSessionID != testSID {
		t.Fatal("lost NAS session binding")
	}
	must(t, g.ProcessActivations(t.Context()))
	status, e := g.ActivationStatus(t.Context(), grant.StatusToken)
	must(t, e)
	if status.State != "awaiting_accounting" {
		t.Fatal("management response treated as active", status)
	}
	must(t, r.service.Store.Exec(t.Context(), "UPDATE guest_authorizations SET activation_next=0"))
	restarted, e := guest.New(r.service.Store, make([]byte, 32))
	must(t, e)
	defer restarted.Close()
	restarted.Activate = (&Service{Store: r.service.Store, Vault: r.service.Vault, PublicURL: r.service.PublicURL}).ActivateGuest
	must(t, restarted.ProcessActivations(t.Context()))
	if r.logins != 1 {
		t.Fatal("restart repeated login")
	}
	var accepted *radius.Packet
	for _, sid := range []string{"", "replacement", testSID} {
		p, e := radiusLogin(t, r, sid)
		must(t, e)
		want := radius.CodeAccessReject
		if sid == testSID {
			want = radius.CodeAccessAccept
		}
		if p.Code != want {
			t.Fatalf("SID %q: %v", sid, p.Code)
		}
		if p.Code == radius.CodeAccessAccept {
			accepted = p
		}
	}
	acct := radius.New(radius.CodeAccountingRequest, []byte(testSecret))
	rfc2865.UserName_SetString(acct, testMAC)
	rfc2865.CallingStationID_SetString(acct, testMAC)
	rfc2866.AcctSessionID_SetString(acct, testSID)
	rfc2866.AcctStatusType_Set(acct, rfc2866.AcctStatusType_Value_Start)
	rfc2865.Class_Set(acct, rfc2865.Class_Get(accepted))
	wire, e := acct.Encode()
	must(t, e)
	reply, e := aaa.ProcessWithOptions(t.Context(), r.service.Store, wire, &net.UDPAddr{IP: net.ParseIP(testNAS)}, true, aaa.Options{})
	must(t, e)
	if !radius.IsAuthenticResponse(reply, wire, []byte(testSecret)) {
		t.Fatal("invalid Accounting response")
	}
	status, e = restarted.ActivationStatus(t.Context(), grant.StatusToken)
	must(t, e)
	if status.State != "active" {
		t.Fatal("linked Accounting did not confirm activation", status)
	}
	must(t, r.service.Store.RevokeGuest(t.Context(), testNAS, testMAC, actual.ID))
	p, e := radiusLogin(t, r, testSID)
	must(t, e)
	if p.Code != radius.CodeAccessReject {
		t.Fatal("revoked guest accepted")
	}
}
func TestConfigTransportValidation(t *testing.T) {
	r := fixture(t)
	for _, mutate := range []func(*Config){func(c *Config) { c.Address = "http://203.0.113.10"; c.TunnelHTTP = true }, func(c *Config) { c.Address = "http://10.0.0.1"; c.TunnelHTTP = false }, func(c *Config) { c.Address = "https://example.com" }, func(c *Config) { c.Address = "https://user:pass@192.0.2.1" }, func(c *Config) { c.HTTPHost = "evil/route" }, func(c *Config) { c.Chilli = "Chilli0 up" }, func(c *Config) { c.Bridge = "Bridge2;reboot" }, func(c *Config) { c.Subnet = "0.0.0.0/0" }, func(c *Config) { c.CertificateSHA256 = "" }} {
		c := r.cfg
		mutate(&c)
		if c.validate() == nil {
			t.Fatal(fmt.Sprintf("unsafe config accepted: address %s", c.Address))
		}
	}
}

func TestProbeReadOnly(t *testing.T) {
	r := fixture(t)
	r.omitDefaultPorts = true
	g := r.grant(t)
	must(t, r.service.Probe(t.Context(), testNAS))
	if r.logins != 0 || r.commands != 1 {
		t.Fatal("probe changed NAS", r.logins, r.commands)
	}
	actual, e := r.service.Store.GuestAuthorization(t.Context(), g.NAS, g.MAC)
	must(t, e)
	if actual.ID != g.ID {
		t.Fatal("probe replaced authorization")
	}
	c := r.cfg
	c.AuthPort = 18120
	must(t, r.service.Save(t.Context(), testNAS, c))
	if e := r.service.Probe(t.Context(), testNAS); e == nil {
		t.Fatal("omitted default accepted as custom port")
	}
	for _, port := range []string{"0", "65536"} {
		c := r.cfg
		c.Address = "https://192.0.2.1:" + port
		if c.validate() == nil {
			t.Fatal("invalid port accepted", port)
		}
	}
}

func TestProfileChangeRequiresDisablingAdapter(t *testing.T) {
	r := fixture(t)
	n := store.NAS{Address: testNAS, Name: "Changed", Dictionary: "mikrotik", Mode: "network", Credential: "codes", PortalEnabled: true, CoAPort: 3799, InterimSeconds: 300, StaleSeconds: 900}
	if e := r.service.Store.SaveNASMetadata(t.Context(), n, testSecret); e == nil {
		t.Fatal("profile changed with an enabled adapter")
	}
	c := r.cfg
	c.Enabled = false
	must(t, r.service.Save(t.Context(), testNAS, c))
	must(t, r.service.Store.SaveNASMetadata(t.Context(), n, testSecret))
}
