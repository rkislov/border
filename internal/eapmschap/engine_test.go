package eapmschap

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/rkislov/border/internal/mschap"
	"testing"
	"time"
)

func response(challenge Reply, user, password string) []byte {
	peer := bytes.Repeat([]byte{0x42}, 16)
	hash := mschap.PasswordHash(password)
	defer clear(hash)
	nt := mschap.NTResponse(hash, challenge.Message[10:26], peer, user)
	body := append([]byte{26, 2, challenge.Message[6], 0, 0, 49}, peer...)
	body = append(body, make([]byte, 8)...)
	body = append(body, nt...)
	body = append(body, 0)
	body = append(body, user...)
	binary.BigEndian.PutUint16(body[3:5], uint16(len(body)-1))
	return packet(2, challenge.Message[1], body)
}
func TestExchangeAndIsolation(t *testing.T) {
	for _, mode := range []string{"success", "wrong-password", "wrong-peer", "wrong-identity", "malformed", "expired", "early-success"} {
		t.Run(mode, func(t *testing.T) {
			e := New()
			defer e.Close()
			calls := 0
			verify := func(ctx context.Context, user string, r *mschap.Request) (Result, error) {
				calls++
				hash := mschap.PasswordHash("clientPass")
				defer clear(hash)
				success, ok := r.Verify(hash, user)
				if !ok {
					return Result{}, ErrRejected
				}
				return Result{Identity: "local/" + user, Success: success, Key: mschap.SessionKeyFromHash(hash, r.Response)}, nil
			}
			id := packet(2, 1, append([]byte{1}, []byte("User")...))
			first := e.Handle(t.Context(), "peer", "User", nil, id, verify)
			again := e.Handle(t.Context(), "peer", "User", nil, id, verify)
			if !bytes.Equal(first.Message, again.Message) || !bytes.Equal(first.State, again.State) {
				t.Fatal("initial retransmission changed")
			}
			password := "clientPass"
			if mode == "wrong-password" {
				password = "wrong"
			}
			msg := response(first, "User", password)
			peer := "peer"
			user := "User"
			switch mode {
			case "wrong-peer":
				peer = "other"
			case "wrong-identity":
				user = "Other"
			case "malformed":
				msg[26] = 1
			case "expired":
				e.mu.Lock()
				e.sessions[string(first.State)].expires = time.Now().Add(-time.Second)
				e.mu.Unlock()
			case "early-success":
				msg = packet(2, first.Message[1], []byte{26, 3})
			}
			out := e.Handle(t.Context(), peer, user, first.State, msg, verify)
			if mode != "success" {
				if !out.Reject || len(out.Key) > 0 {
					t.Fatal("unsafe accept", mode)
				}
				return
			}
			if out.Accept || out.Reject || len(out.Key) > 0 || calls != 1 {
				t.Fatal("keys released before peer confirms authenticator")
			}
			oldInitial := e.Handle(t.Context(), peer, user, nil, id, verify)
			if !bytes.Equal(oldInitial.Message, first.Message) || !bytes.Equal(oldInitial.State, first.State) {
				t.Fatal("delayed initial retransmission changed state")
			}
			duplicate := e.Handle(t.Context(), peer, user, first.State, msg, verify)
			if calls != 1 || !bytes.Equal(duplicate.Message, out.Message) {
				t.Fatal("retransmission revalidated credentials")
			}
			final := packet(2, out.Message[1], []byte{26, 3})
			accepted := e.Handle(t.Context(), peer, user, first.State, final, verify)
			if !accepted.Accept || len(accepted.Key) != 32 || accepted.Identity != "local/User" {
				t.Fatal("final exchange failed")
			}
			clear(accepted.Key)
			replay := e.Handle(t.Context(), peer, user, first.State, final, verify)
			if !replay.Accept || bytes.Equal(replay.Key, make([]byte, 32)) {
				t.Fatal("reply aliasing corrupted cached keys")
			}
			clear(replay.Key)
		})
	}
}
func FuzzHandle(f *testing.F) {
	f.Add([]byte{2, 1, 0, 6, 26, 3})
	f.Fuzz(func(t *testing.T, b []byte) {
		e := New()
		defer e.Close()
		e.Handle(t.Context(), "peer", "user", nil, b, func(context.Context, string, *mschap.Request) (Result, error) { return Result{}, ErrRejected })
	})
}
