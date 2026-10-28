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

	"github.com/rkislov/border/internal/directory"
	"github.com/rkislov/border/internal/eap"
	"github.com/rkislov/border/internal/identitysource"
	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
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

type Options struct {
	Resolve    func(context.Context, string) (*store.Store, Options, error)
	Identities *identitysource.Service
	TOTP       TOTPVerifier
	Directory  directory.Authenticator
	Network    NetworkVerifier
	EAP        *eap.Engine
}

func ServeAuthenticated(ctx context.Context, conn net.PacketConn, s *store.Store, workers int, accounting bool, verifier NetworkVerifier) error {
	return ServeWithOptions(ctx, conn, s, workers, accounting, Options{Network: verifier})
}
func ServeWithOptions(ctx context.Context, conn net.PacketConn, s *store.Store, workers int, accounting bool, options Options) error {
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
					reply, err := ProcessWithOptions(c, s, j.raw, j.addr, accounting, options)
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
	return ProcessWithOptions(ctx, s, raw, addr, accounting, Options{Network: verifier})
}
func ProcessWithOptions(ctx context.Context, s *store.Store, raw []byte, addr net.Addr, accounting bool, options Options) ([]byte, error) {
	verifier := options.Network
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, err
	}
	if options.Resolve != nil {
		resolved, next, e := options.Resolve(ctx, host)
		if e != nil {
			return nil, e
		}
		next.Resolve = nil
		return ProcessWithOptions(ctx, resolved, raw, addr, accounting, next)
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
		event, e := accountingEvent(p, host)
		if e != nil {
			return nil, e
		}
		if err = s.ApplyAccounting(ctx, event); err != nil {
			return nil, errors.New("accounting write failed")
		}

		return p.Response(radius.CodeAccountingResponse).Encode()
	}
	if p.Code != radius.CodeAccessRequest || !VerifyMessageAuthenticator(raw, secret) {
		return nil, errors.New("missing or invalid Message-Authenticator")
	}
	if mac, e := NormalizeMAC(rfc2865.CallingStationID_GetString(p)); e == nil {
		if e = s.ObserveFingerprint(ctx, store.Fingerprint{MAC: mac, NAS: host, Source: "radius"}); e != nil {
			return nil, errors.New("fingerprint write failed")
		}
	}
	profile, err := s.NASProfile(ctx, host)
	if err != nil {
		return nil, errors.New("NAS profile unavailable")
	}
	for _, a := range p.Attributes {
		if a.Type == 26 {
			vendor, data, e := radius.VendorSpecific(a.Attribute)
			if e == nil && vendor == 311 && len(data) > 0 && (data[0] == 1 || data[0] == 11 || data[0] == 25) {
				return nil, errors.New("MSCHAP is not supported")
			}
		}
	}
	if len(p.Attributes.Get(3)) > 0 {
		return nil, errors.New("CHAP is not supported")
	}
	bound, configured, err := selectPolicy(ctx, s, p, host)
	if err != nil {
		return nil, errors.New("access policy unavailable")
	}
	if bound != nil {
		return processPolicy(ctx, s, p, host, profile, bound, options)
	}
	if configured {
		out := p.Response(radius.CodeAccessReject)
		for _, a := range p.Attributes {
			if a.Type == 33 {
				out.Attributes.Add(33, a.Attribute)
			}
		}
		if msg := p.Attributes.Get(79); len(msg) > 1 {
			out.Attributes.Add(79, []byte{4, msg[1], 0, 4})
		}
		if err = s.Audit(ctx, host, rfc2865.UserName_GetString(p), "Access-Reject", "no NAS policy selector matched"); err != nil {
			return nil, err
		}
		if err = SignMessageAuthenticator(out); err != nil {
			return nil, err
		}
		return out.Encode()
	}
	if profile.Mode != "network" {
		return processService(ctx, s, p, host, profile, options)
	}
	decision := Decision{Reason: "EAP is not available in this version"}
	identity := ""
	hasEAP := false
	for _, a := range p.Attributes {
		if a.Type == 79 {
			hasEAP = true
		}
	}
	if hasEAP && options.EAP != nil {
		return processEAP(ctx, s, p, host, options.EAP)
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
			decision, err = DecideForNAS(ctx, s, host, identity)
			if err != nil {
				return nil, errors.New("policy lookup failed")
			}
		} else {
			decision = Decision{Reason: "invalid MAC"}
		}
	}
	if decision.Accept {
		enabled, e := s.IdentityEnabled(ctx, identity)
		if e != nil {
			return nil, e
		}
		decision.Accept = enabled
	}
	code := radius.CodeAccessReject
	if decision.Accept {
		code = radius.CodeAccessAccept
	}
	out := p.Response(code)
	if decision.Accept {
		ttl := int64(3600)
		if decision.Timeout > 0 {
			ttl = int64(decision.Timeout)
		}
		token, e := s.NewAccessGrant(ctx, host, identity, "", time.Now().Unix()+ttl)
		if e != nil {
			return nil, e
		}
		out.Attributes.Add(25, []byte(token))
		if err := setAccountingInterval(ctx, s, host, out); err != nil {
			return nil, err
		}
	}
	// Preserve Proxy-State as required by RFC 2865.
	for _, a := range p.Attributes {
		if a.Type == 33 {
			out.Attributes.Add(a.Type, a.Attribute)
		}
	}
	if hasEAP {
		var message []byte
		for _, a := range p.Attributes {
			if a.Type == 79 {
				message = append(message, a.Attribute...)
			}
		}
		var id byte
		if len(message) > 1 {
			id = message[1]
		}
		out.Attributes.Add(79, []byte{4, id, 0, 4})
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
		if decision.Voice && profile.Dictionary == "cisco" {
			v := []byte("device-traffic-class=voice")
			attr := make([]byte, 6+len(v))
			binary.BigEndian.PutUint32(attr[:4], 9)
			attr[4] = 1
			attr[5] = byte(2 + len(v))
			copy(attr[6:], v)
			out.Attributes.Add(26, attr)
		}
		timeout := uint32(3600)
		if decision.Timeout > 0 {
			timeout = decision.Timeout
		}
		if err = rfc2865.SessionTimeout_Set(out, rfc2865.SessionTimeout(timeout)); err != nil {
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
