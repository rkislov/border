// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
// Package eapmschap implements EAP type 26 for certificate-authenticated IKEv2.
package eapmschap

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/rkislov/border/internal/mschap"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Identity, Success string
	Key               []byte
	Groups            []string
}
type Verify func(context.Context, string, *mschap.Request) (Result, error)
type Reply struct {
	Message, State, Key []byte
	Identity            string
	Groups              []string
	Accept, Reject      bool
}
type Engine struct {
	mu       sync.Mutex
	sessions map[string]*session
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
	closed   bool
}
type session struct {
	mu                sync.Mutex
	peer, user        string
	expires           time.Time
	token, challenge  []byte
	id, msid          byte
	stage             int
	initial, lastHash [32]byte
	last, start       Reply
	result            Result
}

func New() *Engine {
	e := &Engine{sessions: map[string]*session{}, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(e.done)
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-e.stop:
				return
			case <-t.C:
				e.prune()
			}
		}
	}()
	return e
}
func (e *Engine) prune() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, s := range e.sessions {
		if time.Now().After(s.expires) {
			s.mu.Lock()
			wipe(s)
			s.mu.Unlock()
			delete(e.sessions, k)
		}
	}
}
func wipe(s *session) { clear(s.result.Key); clear(s.last.Key); clear(s.challenge) }
func (e *Engine) Close() {
	e.once.Do(func() {
		close(e.stop)
		<-e.done
		e.mu.Lock()
		defer e.mu.Unlock()
		e.closed = true
		for _, s := range e.sessions {
			s.mu.Lock()
			wipe(s)
			s.mu.Unlock()
		}
		clear(e.sessions)
	})
}
func packet(code, id byte, data []byte) []byte {
	b := []byte{code, id, 0, 0}
	b = append(b, data...)
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}
func fail(id byte) Reply { return Reply{Message: packet(4, id, nil), Reject: true} }
func clone(r Reply) Reply {
	r.Message = bytes.Clone(r.Message)
	r.State = bytes.Clone(r.State)
	r.Key = bytes.Clone(r.Key)
	r.Groups = append([]string(nil), r.Groups...)
	return r
}
func method(id, op, msid byte, body []byte) []byte {
	b := []byte{26, op, msid, 0, 0}
	binary.BigEndian.PutUint16(b[3:], uint16(4+len(body)))
	return packet(1, id, append(b, body...))
}
func (e *Engine) Handle(ctx context.Context, peer, user string, state, msg []byte, verify Verify) Reply {
	id := byte(0)
	if len(msg) > 1 {
		id = msg[1]
	}
	if len(msg) < 5 || len(msg) > 512 || msg[0] != 2 || int(binary.BigEndian.Uint16(msg[2:4])) != len(msg) || len(user) == 0 || len(user) > 253 || strings.ContainsAny(user, "\x00\r\n") || verify == nil {
		return fail(id)
	}
	hash := sha256.Sum256(msg)
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return fail(id)
	}
	var s *session
	if len(state) == 0 {
		if msg[4] != 1 || string(msg[5:]) != user {
			e.mu.Unlock()
			return fail(id)
		}
		for _, candidate := range e.sessions {
			if candidate.peer == peer && candidate.initial == hash && !time.Now().After(candidate.expires) {
				candidate.mu.Lock()
				if candidate.stage != 2 {
					r := clone(candidate.start)
					candidate.mu.Unlock()
					e.mu.Unlock()
					return r
				}
				candidate.mu.Unlock()
			}
		}
		if len(e.sessions) >= 256 {
			e.mu.Unlock()
			return fail(id)
		}
		s = &session{peer: peer, user: user, expires: time.Now().Add(30 * time.Second), token: make([]byte, 32), challenge: make([]byte, 16), id: id + 1, msid: id + 1, initial: hash}
		if _, err := rand.Read(s.token); err != nil {
			e.mu.Unlock()
			return fail(id)
		}
		if _, err := rand.Read(s.challenge); err != nil {
			e.mu.Unlock()
			return fail(id)
		}
		s.last = Reply{Message: method(s.id, 1, s.msid, append(append([]byte{16}, s.challenge...), []byte("Border")...)), State: s.token}
		s.start = clone(s.last)
		e.sessions[string(s.token)] = s
		reply := clone(s.last)
		e.mu.Unlock()
		return reply
	}
	if len(state) != 32 {
		e.mu.Unlock()
		return fail(id)
	}
	s = e.sessions[string(state)]
	e.mu.Unlock()
	if s == nil {
		return fail(id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peer != peer || s.user != user || time.Now().After(s.expires) {
		return fail(id)
	}
	if hash == s.lastHash {
		return clone(s.last)
	}
	if s.stage == 2 || id != s.id || msg[4] != 26 {
		return fail(id)
	}
	var out Reply
	if s.stage == 0 {
		// Response: opcode, MS-ID, MS-Length, Value-Size=49, PeerChallenge,
		// eight reserved zeros, NT-Response, Flags=0 and Name.
		if len(msg) < 60 || msg[5] != 2 || msg[6] != s.msid || int(binary.BigEndian.Uint16(msg[7:9])) != len(msg)-5 || msg[9] != 49 || msg[58] != 0 || !bytes.Equal(msg[26:34], make([]byte, 8)) || string(msg[59:]) != user {
			out = fail(id)
		} else {
			r := &mschap.Request{ID: s.msid, Challenge: bytes.Clone(s.challenge), Peer: bytes.Clone(msg[10:26]), Response: bytes.Clone(msg[34:58])}
			result, err := verify(ctx, user, r)
			if err != nil || len(result.Key) != 32 || len(result.Success) != 42 || !strings.HasPrefix(result.Success, "S=") || result.Identity == "" {
				clear(result.Key)
				out = fail(id)
			} else {
				s.result = result
				s.stage = 1
				s.id++
				out = Reply{Message: method(s.id, 3, s.msid, []byte(result.Success+" M=OK")), State: s.token}
			}
		}
	} else {
		if len(msg) != 6 || msg[5] != 3 {
			out = fail(id)
		} else {
			out = Reply{Message: packet(3, id, nil), Accept: true, Key: bytes.Clone(s.result.Key), Identity: s.result.Identity, Groups: append([]string(nil), s.result.Groups...)}
		}
	}
	if out.Accept || out.Reject {
		s.stage = 2
		clear(s.result.Key)
	}
	s.lastHash = hash
	s.last = clone(out)
	return out
}

var ErrRejected = fmt.Errorf("EAP-MSCHAPv2 credentials rejected")
