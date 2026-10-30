// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package eap

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"time"
)

// flightConn adapts TLS's byte stream to complete EAP flights. A read event
// marks a flight boundary without timing heuristics or polling sleeps.
type flightEvent struct {
	data   []byte
	read   bool
	result *tlsResult
}
type tlsResult struct {
	authorization Authorization
	state         tls.ConnectionState
	key           []byte
	err           error
}
type flightConn struct {
	ctx      context.Context
	input    chan []byte
	events   chan flightEvent
	buffered []byte
}

func newFlightConn(ctx context.Context) *flightConn {
	return &flightConn{ctx: ctx, input: make(chan []byte, 1), events: make(chan flightEvent, 8)}
}
func (c *flightConn) emit(event flightEvent) error {
	select {
	case c.events <- event:
		return nil
	case <-c.ctx.Done():
		return c.ctx.Err()
	}
}
func (c *flightConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(c.buffered) == 0 {
		if err := c.emit(flightEvent{read: true}); err != nil {
			return 0, err
		}
		select {
		case c.buffered = <-c.input:
		case <-c.ctx.Done():
			return 0, io.EOF
		}
	}
	n := copy(p, c.buffered)
	c.buffered = c.buffered[n:]
	return n, nil
}
func (c *flightConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := c.emit(flightEvent{data: append([]byte(nil), p...)}); err != nil {
		return 0, err
	}
	return len(p), nil
}
func (c *flightConn) Close() error { return nil }

type address string

func (a address) Network() string          { return "eap" }
func (a address) String() string           { return string(a) }
func (c *flightConn) LocalAddr() net.Addr  { return address("server") }
func (c *flightConn) RemoteAddr() net.Addr { return address("peer") }

// HandshakeContext supplies the deadline/cancellation for this virtual stream.
func (c *flightConn) SetDeadline(time.Time) error      { return nil }
func (c *flightConn) SetReadDeadline(time.Time) error  { return nil }
func (c *flightConn) SetWriteDeadline(time.Time) error { return nil }
