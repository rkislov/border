// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
// Package eap implements EAP-TLS with TLS 1.2 (RFC 5216), independently of RADIUS.
package eap

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	Request    = 1
	Response   = 2
	Success    = 3
	Failure    = 4
	Identity   = 1
	TLS        = 13
	PEAP       = 25
	TTLS       = 21
	lengthFlag = 0x80
	moreFlag   = 0x40
	startFlag  = 0x20
	maxFlight  = 65536
)

type Authorization struct {
	Identity string
	VLAN     int
	Groups   []string
}
type Reply struct {
	Message, State, Key []byte
	Accept, Reject      bool
	Authorization       Authorization
	Reason              string
}
type Tunnel struct {
	Method       byte
	Authenticate func(context.Context, *tls.Conn) (Authorization, error)
}
type Config struct {
	TLSConfig                 func(context.Context) (*tls.Config, error)
	Authorize                 func(context.Context, tls.ConnectionState) (Authorization, error)
	FragmentSize, MaxSessions int
	Timeout                   time.Duration
}
type Engine struct {
	config   Config
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	sessions map[string]*session
	initial  map[string]*session
	wg       sync.WaitGroup
}
type session struct {
	mu                 sync.Mutex
	peer               string
	tunnel             *Tunnel
	token              []byte
	expires            time.Time
	config             *tls.Config
	initialHash        [32]byte
	start              Reply
	started            atomic.Bool
	pendingID          byte
	lastHash           [32]byte
	last               Reply
	hasLast, finished  bool
	incoming, outgoing []byte
	expectedLength     int
	outOffset          int
	conn               *flightConn
	cancel             context.CancelFunc
	result             *tlsResult
}

func New(config Config) (*Engine, error) {
	if config.TLSConfig == nil || config.Authorize == nil {
		return nil, fmt.Errorf("EAP requires TLS configuration and certificate authorization")
	}
	if config.FragmentSize == 0 {
		config.FragmentSize = 1000
	}
	if config.FragmentSize < 64 || config.FragmentSize > 1400 {
		return nil, fmt.Errorf("EAP fragment size: 64–1400")
	}
	if config.MaxSessions == 0 {
		config.MaxSessions = 256
	}
	if config.MaxSessions < 1 || config.MaxSessions > 4096 {
		return nil, fmt.Errorf("EAP sessions: 1–4096")
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Timeout < time.Second || config.Timeout > 2*time.Minute {
		return nil, fmt.Errorf("EAP timeout: 1–120 seconds")
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{config: config, ctx: ctx, cancel: cancel, sessions: make(map[string]*session), initial: make(map[string]*session)}
	e.wg.Add(1)
	go e.sweep()
	return e, nil
}
func (e *Engine) Close() { e.cancel(); e.wg.Wait() }
func (e *Engine) sweep() {
	defer e.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.ctx.Done():
			e.mu.Lock()
			for _, s := range e.sessions {
				s.mu.Lock()
				if s.cancel != nil {
					s.cancel()
				}
				clear(s.last.Key)
				if s.result != nil {
					clear(s.result.key)
				}
				s.mu.Unlock()
			}
			e.mu.Unlock()
			return
		case now := <-ticker.C:
			e.mu.Lock()
			for key, s := range e.sessions {
				if now.After(s.expires) {
					s.mu.Lock()
					if s.cancel != nil {
						s.cancel()
					}
					clear(s.last.Key)
					if s.result != nil {
						clear(s.result.key)
					}
					s.mu.Unlock()
					delete(e.sessions, key)
				}
			}
			for key, s := range e.initial {
				if now.After(s.expires) {
					delete(e.initial, key)
				}
			}
			e.mu.Unlock()
		}
	}
}
func packet(code, id, typ, flags byte, data []byte) []byte {
	n := 4
	if code == Request || code == Response {
		n += 2
	}
	out := make([]byte, n+len(data))
	out[0] = code
	out[1] = id
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	if n > 4 {
		out[4] = typ
		out[5] = flags
	}
	copy(out[n:], data)
	return out
}
func failed(id byte, reason string) Reply {
	return Reply{Message: packet(Failure, id, 0, 0, nil), Reject: true, Reason: reason}
}
func clone(r Reply) Reply {
	r.Message = bytes.Clone(r.Message)
	r.State = bytes.Clone(r.State)
	r.Key = bytes.Clone(r.Key)
	r.Authorization.Groups = append([]string(nil), r.Authorization.Groups...)
	return r
}
func (e *Engine) Handle(ctx context.Context, peer string, state, message []byte) Reply {
	return e.handle(ctx, peer, state, message, nil)
}
func (e *Engine) HandleTunnel(ctx context.Context, peer string, state, message []byte, t Tunnel) Reply {
	if (t.Method != PEAP && t.Method != TTLS) || t.Authenticate == nil {
		return failed(0, "invalid tunnel")
	}
	return e.handle(ctx, peer+string([]byte{t.Method}), state, message, &t)
}
func (s *session) method() byte {
	if s.tunnel != nil {
		return s.tunnel.Method
	}
	return TLS
}
func (e *Engine) handle(ctx context.Context, peer string, state, message []byte, tunnel *Tunnel) Reply {
	e.mu.Lock()
	if e.ctx.Err() != nil {
		e.mu.Unlock()
		return failed(0, "EAP unavailable")
	}
	e.wg.Add(1)
	e.mu.Unlock()
	defer e.wg.Done()
	id := byte(0)
	if len(message) > 1 {
		id = message[1]
	}
	if len(message) < 5 || len(message) > maxFlight || message[0] != Response || int(binary.BigEndian.Uint16(message[2:4])) != len(message) {
		return failed(id, "malformed EAP response")
	}
	if len(state) == 0 {
		if message[4] != Identity || len(message) > 1029 {
			return failed(id, "EAP identity required")
		}
		return e.begin(ctx, peer, message, tunnel)
	}
	if len(state) != 32 {
		return failed(id, "invalid EAP State")
	}
	e.mu.Lock()
	s := e.sessions[string(state)]
	e.mu.Unlock()
	if s == nil || s.peer != peer || time.Now().After(s.expires) {
		return failed(id, "unknown or expired EAP State")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := sha256.Sum256(message)
	if s.hasLast && hash == s.lastHash {
		return clone(s.last)
	}
	if s.finished {
		return failed(id, "EAP session complete")
	}
	var reply Reply
	if id != s.pendingID || message[4] != s.method() || len(message) < 6 {
		reply = failed(id, "unexpected EAP identifier or method")
	} else {
		reply = e.step(ctx, s, message)
	}
	if reply.Reject {
		if s.cancel != nil {
			s.cancel()
		}
		s.finished = true
	}
	s.lastHash = hash
	s.last = clone(reply)
	s.hasLast = true
	return reply
}
func (e *Engine) begin(ctx context.Context, peer string, message []byte, tunnel *Tunnel) Reply {
	hash := sha256.Sum256(message)
	e.mu.Lock()
	if previous := e.initial[peer]; previous != nil && !previous.started.Load() && previous.initialHash == hash && time.Now().Before(previous.expires) {
		r := clone(previous.start)
		e.mu.Unlock()
		return r
	}
	full := len(e.sessions) >= e.config.MaxSessions
	e.mu.Unlock()
	if full {
		return failed(message[1], "EAP session limit reached")
	}
	cfg, err := e.config.TLSConfig(ctx)
	if err != nil || cfg == nil || len(cfg.Certificates) == 0 || cfg.ClientCAs == nil {
		return failed(message[1], "EAP TLS configuration unavailable")
	}
	cfg = cfg.Clone()
	cfg.MinVersion = tls.VersionTLS12
	cfg.MaxVersion = tls.VersionTLS12
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	if tunnel != nil {
		cfg.ClientAuth = tls.NoClientCert
		cfg.VerifyConnection = nil
		cfg.VerifyPeerCertificate = nil
	}
	cfg.SessionTicketsDisabled = true
	cfg.GetConfigForClient = nil
	token := make([]byte, 32)
	if _, err = rand.Read(token); err != nil {
		return failed(message[1], "EAP state generation failed")
	}
	s := &session{tunnel: tunnel, peer: peer, token: token, expires: time.Now().Add(e.config.Timeout), config: cfg, pendingID: message[1] + 1, initialHash: hash}
	s.start = Reply{Message: packet(Request, s.pendingID, s.method(), startFlag, nil), State: bytes.Clone(token)}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.sessions) >= e.config.MaxSessions || e.ctx.Err() != nil {
		return failed(message[1], "EAP unavailable")
	}
	e.sessions[string(token)] = s
	e.initial[peer] = s
	return clone(s.start)
}
func (e *Engine) challenge(s *session, flags byte, data []byte) Reply {
	s.pendingID++
	return Reply{Message: packet(Request, s.pendingID, s.method(), flags, data), State: bytes.Clone(s.token)}
}
func (e *Engine) output(s *session) Reply {
	offset := s.outOffset
	remaining := len(s.outgoing) - offset
	n := remaining
	if n > e.config.FragmentSize {
		n = e.config.FragmentSize
	}
	var flags byte
	payload := s.outgoing[offset : offset+n]
	if offset == 0 && remaining > n {
		flags |= lengthFlag
		data := make([]byte, 4+n)
		binary.BigEndian.PutUint32(data[:4], uint32(len(s.outgoing)))
		copy(data[4:], payload)
		payload = data
	}
	s.outOffset += n
	if s.outOffset < len(s.outgoing) {
		flags |= moreFlag
	} else {
		s.outgoing = nil
		s.outOffset = 0
	}
	return e.challenge(s, flags, payload)
}
func (e *Engine) step(ctx context.Context, s *session, message []byte) Reply {
	s.started.Store(true)
	id := message[1]
	flags := message[5]
	data := message[6:]
	if flags&0x3f != 0 {
		return failed(id, "invalid EAP-TLS flags")
	}
	if len(s.outgoing) > 0 {
		if flags != 0 || len(data) != 0 {
			return failed(id, "fragment acknowledgement required")
		}
		return e.output(s)
	}
	if s.result != nil {
		if flags != 0 || len(data) != 0 {
			return failed(id, "final TLS acknowledgement required")
		}
		authorization, err := s.result.authorization, error(nil)
		if s.tunnel == nil {
			authorization, err = e.config.Authorize(ctx, s.result.state)
		} else {
			_, err = e.config.TLSConfig(ctx)
		}
		if err != nil || authorization.Identity == "" {
			return failed(id, "certificate authorization denied")
		}
		s.finished = true
		if s.cancel != nil {
			s.cancel()
		}
		return Reply{Message: packet(Success, id, 0, 0, nil), Accept: true, Key: bytes.Clone(s.result.key), Authorization: authorization, Reason: "EAP authentication"}
	}
	if flags&lengthFlag != 0 {
		if len(data) < 4 || (s.expectedLength != 0 && s.method() != PEAP) {
			return failed(id, "invalid TLS fragment length")
		}
		total := binary.BigEndian.Uint32(data[:4])
		if total == 0 || total > maxFlight || (s.expectedLength != 0 && int(total) != s.expectedLength) {
			return failed(id, "TLS flight exceeds limit")
		}
		s.expectedLength = int(total)
		data = data[4:]
	} else if flags&moreFlag != 0 && s.expectedLength == 0 {
		return failed(id, "first fragment requires TLS length")
	}
	if len(data) == 0 {
		return failed(id, "empty TLS flight")
	}
	if len(s.incoming)+len(data) > maxFlight {
		return failed(id, "TLS flight exceeds limit")
	}
	s.incoming = append(s.incoming, data...)
	if flags&moreFlag != 0 {
		if len(s.incoming) >= s.expectedLength {
			return failed(id, "invalid continuation fragment")
		}
		return e.challenge(s, 0, nil)
	}
	if s.expectedLength != 0 && len(s.incoming) != s.expectedLength {
		return failed(id, "TLS flight length mismatch")
	}
	input := s.incoming
	s.incoming = nil
	s.expectedLength = 0
	if s.conn == nil {
		s.started.Store(true)
		sessionCtx, cancel := context.WithDeadline(e.ctx, s.expires)
		s.cancel = cancel
		s.conn = newFlightConn(sessionCtx)
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			conn := tls.Server(s.conn, s.config)
			err := conn.HandshakeContext(sessionCtx)
			result := &tlsResult{err: err}
			if err == nil {
				result.state = conn.ConnectionState()
				label := "client EAP encryption"
				if s.tunnel != nil && s.tunnel.Method == TTLS {
					label = "ttls keying material"
				}
				result.key, result.err = result.state.ExportKeyingMaterial(label, nil, 128)
				if result.err == nil && s.tunnel != nil {
					result.authorization, result.err = s.tunnel.Authenticate(sessionCtx, conn)
				}
			}
			_ = s.conn.emit(flightEvent{result: result})
		}()
		// Consume the initial TLS server read before delivering ClientHello.
		select {
		case event := <-s.conn.events:
			if !event.read {
				return failed(id, "TLS initialization failed")
			}
		case <-ctx.Done():
			cancel()
			return failed(id, "EAP request timed out")
		case <-sessionCtx.Done():
			return failed(id, "EAP session expired")
		}
	}
	select {
	case s.conn.input <- input:
	case <-ctx.Done():
		return failed(id, "EAP request timed out")
	case <-s.conn.ctx.Done():
		return failed(id, "EAP session expired")
	}
	var output []byte
	for {
		select {
		case event := <-s.conn.events:
			if len(output)+len(event.data) > maxFlight {
				return failed(id, "TLS flight exceeds limit")
			}
			output = append(output, event.data...)
			if event.result != nil {
				if event.result.err != nil {
					clear(event.result.key)
					return failed(id, "TLS handshake failed")
				}
				s.result = event.result
			}
			if event.read || event.result != nil {
				if len(output) == 0 && s.result != nil && s.tunnel != nil {
					s.finished = true
					if _, err := e.config.TLSConfig(ctx); err != nil {
						return failed(id, "EAP disabled")
					}
					if s.result.authorization.Identity == "" {
						return failed(id, "inner authentication rejected")
					}
					s.cancel()
					return Reply{Message: packet(Success, id, 0, 0, nil), Accept: true, Key: bytes.Clone(s.result.key), Authorization: s.result.authorization, Reason: "tunneled EAP"}
				}
				if len(output) == 0 && event.read && s.tunnel != nil {
					return e.challenge(s, 0, nil)
				}
				if len(output) == 0 {
					return failed(id, "TLS produced no response")
				}
				s.outgoing = output
				s.outOffset = 0
				return e.output(s)
			}
		case <-ctx.Done():
			return failed(id, "EAP request timed out")
		case <-s.conn.ctx.Done():
			return failed(id, "EAP session expired")
		}
	}
}
