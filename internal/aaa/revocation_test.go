package aaa

import (
	"layeh.com/radius"
	"net"
	"testing"
	"time"
)

func TestAutomaticDisconnectRetryAndACK(t *testing.T) {
	s := database(t)
	ctx := t.Context()
	conn, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if e = s.Exec(ctx, "UPDATE nas SET coa_port=? WHERE address='127.0.0.1'", conn.LocalAddr().(*net.UDPAddr).Port); e != nil {
		t.Fatal(e)
	}
	token, e := s.NewAccessGrant(ctx, "127.0.0.1", "user", "", time.Now().Unix()-1)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Accounting(ctx, "127.0.0.1", "revoked-session", "", "user", "active", token); e != nil {
		t.Fatal(e)
	}
	for _, code := range []radius.Code{radius.CodeDisconnectNAK, radius.CodeDisconnectACK} {
		done := make(chan error, 1)
		go func() {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			var b [4096]byte
			n, remote, e := conn.ReadFrom(b[:])
			if e != nil {
				done <- e
				return
			}
			p, e := radius.Parse(b[:n], []byte(testSecret))
			if e != nil {
				done <- e
				return
			}
			wire, e := p.Response(code).Encode()
			if e == nil {
				_, e = conn.WriteTo(wire, remote)
			}
			done <- e
		}()
		if e = RevokeSessions(ctx, s); e != nil {
			t.Fatal(e)
		}
		if e = <-done; e != nil {
			t.Fatal(e)
		}
		var status string
		if e = s.Row(ctx, "SELECT status FROM sessions WHERE session_id='revoked-session'").Scan(&status); e != nil {
			t.Fatal(e)
		}
		if code == radius.CodeDisconnectNAK && status != "active" {
			t.Fatal("NAK counted as disconnected")
		}
		if code == radius.CodeDisconnectACK && status != "disconnect-ack" {
			t.Fatal("ACK not persisted")
		}
		if e = s.Exec(ctx, "UPDATE access_grants SET next_attempt=0 WHERE token=?", token); e != nil {
			t.Fatal(e)
		}
	}
}
