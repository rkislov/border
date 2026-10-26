package eap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rkislov/border/internal/pki"
)

func configurations(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	dir := t.TempDir()
	if err := pki.Generate(dir, "localhost"); err != nil {
		t.Fatal(err)
	}
	server, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := tls.LoadX509KeyPair(filepath.Join(dir, "admin.pem"), filepath.Join(dir, "admin.key"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	return &tls.Config{Certificates: []tls.Certificate{server}, ClientCAs: roots}, &tls.Config{Certificates: []tls.Certificate{client}, RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
}
func engine(t *testing.T, server *tls.Config, fragment int, deny bool) *Engine {
	t.Helper()
	e, err := New(Config{TLSConfig: func(context.Context) (*tls.Config, error) { return server, nil }, Authorize: func(_ context.Context, s tls.ConnectionState) (Authorization, error) {
		if deny {
			return Authorization{}, fmt.Errorf("revoked")
		}
		return Authorization{Identity: s.PeerCertificates[0].Subject.CommonName, VLAN: 123}, nil
	}, FragmentSize: fragment})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}
func identity(id byte) []byte {
	b := append([]byte{2, id, 0, 0, 1}, []byte("anonymous")...)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	return b
}
func response(id, flags byte, data []byte) []byte {
	b := append([]byte{2, id, 0, 0, 13, flags}, data...)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	return b
}
func peerFlight(t *testing.T, c *flightConn) ([]byte, *tlsResult) {
	t.Helper()
	var out []byte
	for {
		select {
		case event := <-c.events:
			out = append(out, event.data...)
			if event.read || event.result != nil {
				return out, event.result
			}
		case <-time.After(3 * time.Second):
			t.Fatal("TLS peer stalled")
			return nil, nil
		}
	}
}

// Run a real crypto/tls supplicant over an independently encoded EAP exchange.
// Both directions fragment independently; all requests may be retransmitted.
func conversation(t *testing.T, e *Engine, clientConfig *tls.Config, clientFragment int, retransmit bool) (Reply, *tlsResult) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	peer := newFlightConn(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		client := tls.Client(peer, clientConfig)
		err := client.HandshakeContext(ctx)
		result := &tlsResult{err: err}
		if err == nil {
			result.state = client.ConnectionState()
			result.key, result.err = result.state.ExportKeyingMaterial("client EAP encryption", nil, 128)
		}
		_ = peer.emit(flightEvent{result: result})
	}()
	defer func() { cancel(); <-done }()
	binding := "nas:station"
	reply := e.Handle(ctx, binding, nil, identity(255))
	if reply.Reject {
		t.Fatal(reply.Reason)
	}
	state := bytes.Clone(reply.State)
	exchange := func(msg []byte) Reply {
		r := e.Handle(ctx, binding, state, msg)
		if retransmit {
			again := e.Handle(ctx, binding, state, msg)
			if !bytes.Equal(r.Message, again.Message) || !bytes.Equal(r.Key, again.Key) || r.Accept != again.Accept {
				t.Fatal("retransmission changed EAP response")
			}
		}
		return r
	}
	outgoing, result := peerFlight(t, peer)
	for rounds := 0; rounds < 1000; rounds++ {
		if result != nil && result.err != nil {
			return reply, result
		}
		if len(outgoing) == 0 {
			reply = exchange(response(reply.Message[1], 0, nil))
			return reply, result
		}
		for offset := 0; offset < len(outgoing); {
			end := offset + clientFragment
			if end > len(outgoing) {
				end = len(outgoing)
			}
			flags := byte(0)
			payload := outgoing[offset:end]
			if offset == 0 && end < len(outgoing) {
				flags |= 0x80
				b := make([]byte, 4+len(payload))
				binary.BigEndian.PutUint32(b, uint32(len(outgoing)))
				copy(b[4:], payload)
				payload = b
			}
			if end < len(outgoing) {
				flags |= 0x40
			}
			reply = exchange(response(reply.Message[1], flags, payload))
			if reply.Reject {
				return reply, nil
			}
			offset = end
			if offset < len(outgoing) && len(reply.Message) != 6 {
				t.Fatal("server must ACK incoming fragment")
			}
		}
		var incoming []byte
		total := 0
		for {
			if len(reply.Message) < 6 || reply.Message[0] != 1 {
				t.Fatalf("invalid EAP-TLS request: %x", reply.Message)
			}
			flags := reply.Message[5]
			data := reply.Message[6:]
			if flags&0x80 != 0 {
				if len(data) < 4 {
					t.Fatal("missing TLS length")
				}
				total = int(binary.BigEndian.Uint32(data))
				data = data[4:]
			}
			incoming = append(incoming, data...)
			if flags&0x40 == 0 {
				break
			}
			reply = exchange(response(reply.Message[1], 0, nil))
			if reply.Reject {
				return reply, nil
			}
		}
		if total != 0 && total != len(incoming) {
			t.Fatal("wrong server TLS flight length")
		}
		select {
		case peer.input <- incoming:
		case <-ctx.Done():
			t.Fatal("peer input stalled")
		}
		outgoing, result = peerFlight(t, peer)
	}
	t.Fatal("too many EAP rounds")
	return Reply{}, nil
}
func TestTLSHandshakeAndKeys(t *testing.T) {
	for _, size := range []int{64, 128, 1000, 1400} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			server, client := configurations(t)
			e := engine(t, server, size, false)
			reply, result := conversation(t, e, client, 97, true)
			if !reply.Accept || reply.Reject || result == nil || result.err != nil {
				t.Fatalf("handshake rejected: %+v %+v", reply, result)
			}
			if !bytes.Equal(reply.Key, result.key) || len(reply.Key) != 128 {
				t.Fatal("exported key mismatch")
			}
			if reply.Authorization.Identity != "Border admin" || reply.Authorization.VLAN != 123 || reply.Message[0] != Success {
				t.Fatal("certificate authorization not applied")
			}
		})
	}
}
func TestRejectsMissingAndUntrustedCertificates(t *testing.T) {
	for _, mode := range []string{"missing", "untrusted", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			server, client := configurations(t)
			if mode == "missing" {
				client.Certificates = nil
			}
			if mode == "untrusted" {
				_, other := configurations(t)
				client.Certificates = other.Certificates
			}
			e := engine(t, server, 128, mode == "revoked")
			reply, _ := conversation(t, e, client, 100, false)
			if reply.Accept || !reply.Reject {
				t.Fatal("unauthorized client accepted")
			}
		})
	}
}
func TestStateBindingMalformedAndLimits(t *testing.T) {
	server, _ := configurations(t)
	e := engine(t, server, 128, false)
	ctx := t.Context()
	start := e.Handle(ctx, "nas1", nil, identity(1))
	duplicate := e.Handle(ctx, "nas1", nil, identity(1))
	if !bytes.Equal(start.State, duplicate.State) || !bytes.Equal(start.Message, duplicate.Message) {
		t.Fatal("initial retransmit")
	}
	if r := e.Handle(ctx, "nas2", start.State, response(start.Message[1], 0, []byte{1})); !r.Reject {
		t.Fatal("State accepted from different NAS")
	}
	for _, data := range [][]byte{nil, {2}, response(1, 0, nil), response(2, 0x20, nil), response(2, 0x40, []byte{1}), response(2, 0x80, []byte{0xff, 0xff, 0xff, 0xff}), response(2, 0x80, []byte{0, 0, 0, 5, 1})} {
		s := e.Handle(ctx, "station", nil, identity(1))
		r := e.Handle(ctx, "station", s.State, data)
		if !r.Reject {
			t.Fatalf("malformed TLS accepted: %x", data)
		}
	}
	limited, err := New(Config{TLSConfig: func(context.Context) (*tls.Config, error) { return server, nil }, Authorize: func(context.Context, tls.ConnectionState) (Authorization, error) { return Authorization{}, nil }, MaxSessions: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer limited.Close()
	s := limited.Handle(ctx, "a", nil, identity(1))
	if r := limited.Handle(ctx, "b", nil, identity(1)); !r.Reject {
		t.Fatal("session limit")
	}
	time.Sleep(1100 * time.Millisecond)
	if r := limited.Handle(ctx, "a", s.State, response(2, 0, nil)); !r.Reject {
		t.Fatal("expired State accepted")
	}
	limited.Close()
	if r := limited.Handle(ctx, "c", nil, identity(1)); !r.Reject {
		t.Fatal("closed engine accepted request")
	}
}
func FuzzMalformedEAP(f *testing.F) {
	f.Add([]byte{2, 1, 0, 5, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := New(Config{TLSConfig: func(context.Context) (*tls.Config, error) { return nil, fmt.Errorf("disabled") }, Authorize: func(context.Context, tls.ConnectionState) (Authorization, error) { return Authorization{}, nil }})
		if err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		r := e.Handle(t.Context(), "peer", nil, b)
		if r.Accept {
			t.Fatal("accepted without TLS configuration")
		}
	})
}
