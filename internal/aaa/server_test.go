package aaa

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2868"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func database(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })
	if err = s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"INSERT INTO nas(address,name,secret) VALUES ('127.0.0.1','test','" + testSecret + "')", "INSERT INTO vlan_catalog VALUES (100,'data'),(200,'voice'),(999,'isolation')", "INSERT INTO mac_auth VALUES ('aa:bb:cc:dd:ee:ff',100,1,0,'printer'),('00:11:22:33:44:55',200,1,1,'phone'),('11:22:33:44:55:66',100,0,0,'blocked')"} {
		if err = s.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
	return s
}
func request(t *testing.T, mac string) *radius.Packet {
	t.Helper()
	p := radius.New(radius.CodeAccessRequest, []byte(testSecret))
	if err := rfc2865.CallingStationID_SetString(p, mac); err != nil {
		t.Fatal(err)
	}
	return p
}
func wire(t *testing.T, p *radius.Packet) []byte {
	t.Helper()
	if err := SignMessageAuthenticator(p); err != nil {
		t.Fatal(err)
	}
	b, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func source() net.Addr { return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345} }
func TestNormalizeMAC(t *testing.T) {
	for _, v := range []string{"AABBCCDDEEFF", "aa:bb:cc:dd:ee:ff", "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff"} {
		got, err := NormalizeMAC(v)
		if err != nil || got != "aa:bb:cc:dd:ee:ff" {
			t.Fatalf("%s: %s %v", v, got, err)
		}
	}
	for _, v := range []string{"", "not-a-mac", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00:11", "aa:bb:cc:dd:ee:ff:ssid"} {
		if _, err := NormalizeMAC(v); err == nil {
			t.Fatalf("accepted %q", v)
		}
	}
}
func TestMABPolicies(t *testing.T) {
	s := database(t)
	if err := s.Exec(t.Context(), "UPDATE nas SET dictionary='cisco'"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mac    string
		accept bool
		vlan   string
		voice  bool
	}{{"aa-bb-cc-dd-ee-ff", true, "100", false}, {"00:11:22:33:44:55", true, "200", true}, {"11:22:33:44:55:66", false, "", false}, {"12:34:56:78:90:ab", false, "", false}, {"invalid", false, "", false}} {
		t.Run(tc.mac, func(t *testing.T) {
			p := request(t, tc.mac)
			b := wire(t, p)
			out, err := Process(context.Background(), s, b, source(), false)
			if err != nil {
				t.Fatal(err)
			}
			if !radius.IsAuthenticResponse(out, b, []byte(testSecret)) {
				t.Fatal("invalid response authenticator")
			}
			r, err := radius.Parse(out, []byte(testSecret))
			if err != nil {
				t.Fatal(err)
			}
			if (r.Code == radius.CodeAccessAccept) != tc.accept {
				t.Fatal(r.Code)
			}
			_, v := rfc2868.TunnelPrivateGroupID_GetString(r)
			if v != tc.vlan {
				t.Fatalf("VLAN=%s", v)
			}
			if (len(r.Attributes.Get(26)) > 0) != tc.voice {
				t.Fatal("wrong voice attribute")
			}
			copy(out[4:20], b[4:20])
			if !VerifyMessageAuthenticator(out, []byte(testSecret)) {
				t.Fatal("invalid response Message-Authenticator")
			}
		})
	}
	if err := s.Exec(context.Background(), "UPDATE settings SET value='999' WHERE name='isolation_vlan'"); err != nil {
		t.Fatal(err)
	}
	d, err := Decide(context.Background(), s, "12:34:56:78:90:ab")
	if err != nil || !d.Accept || d.VLAN != 999 {
		t.Fatalf("isolation: %+v %v", d, err)
	}
	d, err = Decide(context.Background(), s, "11:22:33:44:55:66")
	if err != nil || d.Accept {
		t.Fatal("disabled MAC bypassed isolation")
	}
}
func TestProtocolRejections(t *testing.T) {
	s := database(t)
	p := request(t, "aa:bb:cc:dd:ee:ff")
	valid := wire(t, p)
	unsigned, err := request(t, "aa:bb:cc:dd:ee:ff").Encode()
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), valid...)
	tampered[4] ^= 1
	for _, b := range [][]byte{nil, {1, 2, 3}, unsigned, tampered, append(valid[:20:20], 80, 1)} {
		if _, err := Process(context.Background(), s, b, source(), false); err == nil {
			t.Fatal("accepted malformed or unsigned request")
		}
	}
	if _, err := Process(context.Background(), s, valid, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 123}, false); err == nil {
		t.Fatal("unknown NAS accepted")
	}
	for _, eap := range [][]byte{nil, {2, 1, 0, 5, 1}} {
		p := request(t, "aa:bb:cc:dd:ee:ff")
		p.Attributes.Add(79, eap)
		b, err := Process(context.Background(), s, wire(t, p), source(), false)
		if err != nil {
			t.Fatal(err)
		}
		r, err := radius.Parse(b, []byte(testSecret))
		if err != nil || r.Code != radius.CodeAccessReject {
			t.Fatal("EAP fell back to MAB")
		}
		message := r.Attributes.Get(79)
		if len(message) != 4 || message[0] != 4 {
			t.Fatal("EAP rejection must include EAP-Failure")
		}
	}
}
func TestUsernameFallbackAndDefaultVLAN(t *testing.T) {
	s := database(t)
	ctx := context.Background()
	if err := s.Exec(ctx, "UPDATE mac_auth SET vlan=NULL WHERE mac='aa:bb:cc:dd:ee:ff'"); err != nil {
		t.Fatal(err)
	}
	p := radius.New(radius.CodeAccessRequest, []byte(testSecret))
	if err := rfc2865.UserName_SetString(p, "aabbccddeeff"); err != nil {
		t.Fatal(err)
	}
	p.Attributes.Add(33, []byte("proxy"))
	b, err := Process(ctx, s, wire(t, p), source(), false)
	if err != nil {
		t.Fatal(err)
	}
	r, err := radius.Parse(b, []byte(testSecret))
	if err != nil || r.Code != radius.CodeAccessAccept || len(r.Attributes.Get(81)) != 0 || string(r.Attributes.Get(33)) != "proxy" {
		t.Fatal("default VLAN or proxy state")
	}
}
func TestAccounting(t *testing.T) {
	s := database(t)
	for _, status := range []rfc2866.AcctStatusType{rfc2866.AcctStatusType_Value_Start, rfc2866.AcctStatusType_Value_InterimUpdate, rfc2866.AcctStatusType_Value_Stop} {
		p := radius.New(radius.CodeAccountingRequest, []byte(testSecret))
		p.Attributes.Add(46, []byte{0, 0, 0, 0})
		if err := rfc2866.AcctSessionID_SetString(p, "session-1"); err != nil {
			t.Fatal(err)
		}
		if err := rfc2866.AcctStatusType_Set(p, status); err != nil {
			t.Fatal(err)
		}
		b, err := p.Encode()
		if err != nil {
			t.Fatal(err)
		}
		out, err := Process(context.Background(), s, b, source(), true)
		if err != nil {
			t.Fatal(err)
		}
		if !radius.IsAuthenticResponse(out, b, []byte(testSecret)) {
			t.Fatal("bad accounting response")
		}
		b[4] ^= 1
		if _, err = Process(context.Background(), s, b, source(), true); err == nil {
			t.Fatal("accepted bad accounting authenticator")
		}
	}
	sessions, err := s.Sessions(context.Background())
	if err != nil || len(sessions) != 1 || sessions[0].Status != "stopped" {
		t.Fatalf("%+v %v", sessions, err)
	}
}
func TestUDPWorkers(t *testing.T) {
	s := database(t)
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, conn, s, 4, false) }()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := request(t, "aa:bb:cc:dd:ee:ff")
			if err := SignMessageAuthenticator(p); err != nil {
				t.Error(err)
				return
			}
			c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			r, err := radius.Exchange(c, p, conn.LocalAddr().String())
			if err != nil {
				t.Error(err)
				return
			}
			if r.Code != radius.CodeAccessAccept {
				t.Error(r.Code)
			}
		}()
	}
	wg.Wait()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func FuzzVerifyMessageAuthenticator(f *testing.F) {
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, b []byte) { VerifyMessageAuthenticator(b, []byte(testSecret)) })
}

type testNetworkVerifier struct{ calls int }

func (v *testNetworkVerifier) VLAN() int { return 100 }
func (v *testNetworkVerifier) Verify(ctx context.Context, user, code string) (bool, error) {
	v.calls++
	return user == "user" && code == "12345678", nil
}
func TestPAPCodeDoesNotFallBackToMAB(t *testing.T) {
	s := database(t)
	v := &testNetworkVerifier{}
	for _, code := range []string{"12345678", "invalid"} {
		p := request(t, "aa:bb:cc:dd:ee:ff")
		if err := rfc2865.UserName_SetString(p, "user"); err != nil {
			t.Fatal(err)
		}
		if err := rfc2865.UserPassword_SetString(p, code); err != nil {
			t.Fatal(err)
		}
		out, err := ProcessAuthenticated(t.Context(), s, wire(t, p), source(), false, v)
		if err != nil {
			t.Fatal(err)
		}
		r, err := radius.Parse(out, []byte(testSecret))
		if err != nil {
			t.Fatal(err)
		}
		if (r.Code == radius.CodeAccessAccept) != (code == "12345678") {
			t.Fatal("bad network code fell back to allowed MAC")
		}
	}
	if v.calls != 2 {
		t.Fatal("verifier not called")
	}
}
