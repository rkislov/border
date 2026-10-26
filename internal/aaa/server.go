// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"context"
	"crypto/hmac"
	"crypto/md5" // RADIUS mandates HMAC-MD5.
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2868"
)

// VerifyMessageAuthenticator requires exactly one valid attribute 80.
// Its presence is required for every Access-Request, including MAB.
func VerifyMessageAuthenticator(raw, secret []byte) bool {
	if len(raw) < 20 {
		return false
	}
	n := int(binary.BigEndian.Uint16(raw[2:4]))
	if n < 20 || n > len(raw) || n > 4096 {
		return false
	}
	buf := append([]byte(nil), raw[:n]...)
	var expected []byte
	for i := 20; i < n; {
		if i+2 > n {
			return false
		}
		l := int(buf[i+1])
		if l < 2 || i+l > n {
			return false
		}
		if buf[i] == 80 {
			if l != 18 || expected != nil {
				return false
			}
			expected = append([]byte(nil), buf[i+2:i+l]...)
			clear(buf[i+2 : i+l])
		}
		i += l
	}
	if expected == nil {
		return false
	}
	m := hmac.New(md5.New, secret)
	m.Write(buf)
	return hmac.Equal(expected, m.Sum(nil))
}
func SignMessageAuthenticator(p *radius.Packet) error {
	p.Attributes.Set(80, make([]byte, 16))
	b, err := p.MarshalBinary()
	if err != nil {
		return err
	}
	m := hmac.New(md5.New, p.Secret)
	m.Write(b)
	p.Attributes.Set(80, m.Sum(nil))
	return nil
}

// Serve uses a fixed worker pool and a bounded queue. No goroutine is created
// for an individual datagram; overload is dropped for NAS retransmission.
type NetworkVerifier interface {
	Verify(context.Context, string, string) (bool, error)
	VLAN() int
}

func Serve(ctx context.Context, conn net.PacketConn, s *store.Store, workers int, accounting bool) error {
	return ServeAuthenticated(ctx, conn, s, workers, accounting, nil)
}
func ServeAuthenticated(ctx context.Context, conn net.PacketConn, s *store.Store, workers int, accounting bool, verifier NetworkVerifier) error {
	if workers < 1 || workers > 1024 {
		return fmt.Errorf("workers must be between 1 and 1024")
	}
	type job struct {
		raw  []byte
		addr net.Addr
	}
	jobs := make(chan job, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				func() {
					defer func() {
						if recover() != nil {
							slog.Error("RADIUS handler panic", "source", j.addr.String())
						}
					}()
					c, cancel := context.WithTimeout(ctx, 3*time.Second)
					defer cancel()
					reply, err := ProcessAuthenticated(c, s, j.raw, j.addr, accounting, verifier)
					if err != nil {
						slog.Debug("RADIUS packet dropped", "source", j.addr.String(), "reason", err.Error())
						return
					}
					if reply != nil {
						if _, err = conn.WriteTo(reply, j.addr); err != nil {
							slog.Debug("RADIUS write failed", "source", j.addr.String())
						}
					}
				}()
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	defer func() { close(done); close(jobs); wg.Wait() }()
	var raw [4097]byte
	for {
		n, addr, err := conn.ReadFrom(raw[:])
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if n > 4096 {
			continue
		}
		j := job{raw: append([]byte(nil), raw[:n]...), addr: addr}
		select {
		case jobs <- j:
		default:
		}
	}
}
func Process(ctx context.Context, s *store.Store, raw []byte, addr net.Addr, accounting bool) ([]byte, error) {
	return ProcessAuthenticated(ctx, s, raw, addr, accounting, nil)
}
func ProcessAuthenticated(ctx context.Context, s *store.Store, raw []byte, addr net.Addr, accounting bool, verifier NetworkVerifier) ([]byte, error) {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, err
	}
	secret, err := s.Secret(ctx, host)
	if err != nil || len(secret) < 16 {
		return nil, errors.New("unknown NAS")
	}
	p, err := radius.Parse(raw, secret)
	if err != nil {
		return nil, errors.New("malformed packet")
	}
	if accounting {
		if p.Code != radius.CodeAccountingRequest || !radius.IsAuthenticRequest(raw[:int(binary.BigEndian.Uint16(raw[2:4]))], secret) {
			return nil, errors.New("invalid accounting authenticator")
		}
		id := rfc2866.AcctSessionID_GetString(p)
		if id == "" {
			return nil, errors.New("missing session id")
		}
		var status string
		switch rfc2866.AcctStatusType_Get(p) {
		case rfc2866.AcctStatusType_Value_Start:
			status = "active"
		case rfc2866.AcctStatusType_Value_InterimUpdate:
			status = "active"
		case rfc2866.AcctStatusType_Value_Stop:
			status = "stopped"
		default:
			return nil, errors.New("unsupported accounting status")
		}
		mac, _ := NormalizeMAC(rfc2865.CallingStationID_GetString(p))
		if err = s.Accounting(ctx, host, id, mac, rfc2865.UserName_GetString(p), status); err != nil {
			return nil, errors.New("accounting write failed")
		}
		return p.Response(radius.CodeAccountingResponse).Encode()
	}
	if p.Code != radius.CodeAccessRequest || !VerifyMessageAuthenticator(raw, secret) {
		return nil, errors.New("missing or invalid Message-Authenticator")
	}
	decision := Decision{Reason: "EAP is not available in this version"}
	identity := ""
	hasEAP := false
	for _, a := range p.Attributes {
		if a.Type == 79 {
			hasEAP = true
		}
	}
	username := rfc2865.UserName_GetString(p)
	_, usernameMACError := NormalizeMAC(username)
	hasPAP := len(p.Attributes.Get(2)) > 0 && username != "" && usernameMACError != nil
	if !hasEAP && hasPAP {
		decision = Decision{Reason: "network code rejected"}
		identity = username
		if verifier != nil {
			vlan := verifier.VLAN()
			if vlan > 0 {
				var id int
				if err = s.Row(ctx, "SELECT id FROM vlan_catalog WHERE id=?", vlan).Scan(&id); err != nil {
					return nil, errors.New("portal VLAN unavailable")
				}
			}
			valid, verifyErr := verifier.Verify(ctx, username, rfc2865.UserPassword_GetString(p))
			if verifyErr != nil {
				return nil, errors.New("code validation unavailable")
			}
			decision = Decision{Accept: valid, VLAN: vlan, Reason: "network code"}
		}
	} else if !hasEAP {
		identity = rfc2865.CallingStationID_GetString(p)
		if identity == "" {
			identity = rfc2865.UserName_GetString(p)
		}
		identity, err = NormalizeMAC(identity)
		if err == nil {
			decision, err = Decide(ctx, s, identity)
			if err != nil {
				return nil, errors.New("policy lookup failed")
			}
		} else {
			decision = Decision{Reason: "invalid MAC"}
		}
	}
	code := radius.CodeAccessReject
	if decision.Accept {
		code = radius.CodeAccessAccept
	}
	out := p.Response(code)
	// Preserve Proxy-State as required by RFC 2865.
	for _, a := range p.Attributes {
		if a.Type == 33 {
			out.Attributes.Add(a.Type, a.Attribute)
		}
	}
	if decision.Accept {
		if decision.VLAN > 0 {
			if err = rfc2868.TunnelType_Set(out, 0, 13); err != nil {
				return nil, err
			}
			if err = rfc2868.TunnelMediumType_Set(out, 0, 6); err != nil {
				return nil, err
			}
			if err = rfc2868.TunnelPrivateGroupID_SetString(out, 0, strconv.Itoa(decision.VLAN)); err != nil {
				return nil, err
			}
		}
		if decision.Voice {
			v := []byte("device-traffic-class=voice")
			attr := make([]byte, 6+len(v))
			binary.BigEndian.PutUint32(attr[:4], 9)
			attr[4] = 1
			attr[5] = byte(2 + len(v))
			copy(attr[6:], v)
			out.Attributes.Add(26, attr)
		}
		if err = rfc2865.SessionTimeout_Set(out, 3600); err != nil {
			return nil, err
		}
	}
	if err = s.Audit(ctx, host, identity, code.String(), decision.Reason); err != nil {
		return nil, errors.New("audit write failed")
	}
	if err = SignMessageAuthenticator(out); err != nil {
		return nil, err
	}
	return out.Encode()
}
