// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/rkislov/border/internal/store"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2868"
)

var errRevocationRecord = errors.New("revocation result could not be recorded")

type DynamicResult struct {
	Acknowledged bool
	Code         string
	ErrorCause   uint32
}

// ChangeSession addresses only an active recorded session on a registered NAS.
// Authentication and Message-Authenticator follow RFC 5176 section 3.4.
func ChangeSession(ctx context.Context, s *store.Store, nas, id, action string, vlan int, expected ...store.Session) (resultValue DynamicResult, resultErr error) {
	return changeSession(ctx, s, nas, id, action, vlan, nil, expected...)
}

type DisconnectFallback func(context.Context, store.Session) (bool, error)

func ChangeSessionWithFallback(ctx context.Context, s *store.Store, nas, id, action string, vlan int, fallback DisconnectFallback, expected ...store.Session) (DynamicResult, error) {
	return changeSession(ctx, s, nas, id, action, vlan, fallback, expected...)
}
func changeSession(ctx context.Context, s *store.Store, nas, id, action string, vlan int, fallback DisconnectFallback, expected ...store.Session) (resultValue DynamicResult, resultErr error) {
	started := time.Now()
	defer func() {
		outcome := "nak"
		if resultValue.Acknowledged {
			outcome = "ack"
		}
		if resultErr != nil {
			outcome = "error"
		}
		s.Metrics.Observe("session_action", outcome, resultErr != nil || !resultValue.Acknowledged, time.Since(started))
	}()
	if id == "" || len(id) > 253 || (action != "disconnect" && action != "vlan") {
		return DynamicResult{}, fmt.Errorf("invalid session action")
	}
	var secret, mac, username, grantToken, generation string
	var port int
	var updated, startedAt int64
	if err := s.Row(ctx, "SELECT n.secret,n.coa_port,s.mac,s.username,s.updated_at,s.grant_token,s.generation,s.started_at FROM sessions s JOIN nas n ON n.address=s.nas WHERE s.nas=? AND s.session_id=? AND s.status IN ('active','stale')", nas, id).Scan(&secret, &port, &mac, &username, &updated, &grantToken, &generation, &startedAt); err != nil {
		return DynamicResult{}, fmt.Errorf("active session on registered NAS required")
	}
	if len(expected) > 0 {
		v := expected[0]
		if v.MAC != mac || v.Username != username || v.Updated != updated || (v.GrantToken != "" && v.GrantToken != grantToken) || (v.Generation != "" && v.Generation != generation) {
			return DynamicResult{}, fmt.Errorf("session changed; refresh the list")
		}
	}
	nasResponse := store.RevocationNASResponse{}
	session := store.Session{NAS: nas, ID: id, MAC: mac, Username: username, Updated: updated, GrantToken: grantToken, Generation: generation, StartedAt: startedAt}
	if action == "disconnect" {
		// Persist the authenticated NAS result for manual and automatic attempts,
		// even if the request context expired while waiting for the network.
		defer func() {
			message := ""
			if resultErr != nil {
				message = resultErr.Error()
			}
			next := time.Now().Add(time.Minute).Unix()
			if resultValue.Acknowledged {
				next = 0
			}
			recordCtx, cancelRecord := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer cancelRecord()
			if e := s.RecordRevocation(recordCtx, session, resultValue.Code, int64(resultValue.ErrorCause), message, next, nasResponse); e != nil {
				resultErr = fmt.Errorf("%w: %v", errRevocationRecord, e)
			}
		}()
	}
	if net.ParseIP(nas) == nil || len(secret) < 16 {
		return DynamicResult{}, fmt.Errorf("invalid NAS configuration")
	}
	code := radius.CodeDisconnectRequest
	ack, nak := radius.CodeDisconnectACK, radius.CodeDisconnectNAK
	if action == "vlan" {
		code = radius.CodeCoARequest
		ack, nak = radius.CodeCoAACK, radius.CodeCoANAK
		var existing int
		if vlan < 1 || vlan > 4094 {
			return DynamicResult{}, fmt.Errorf("VLAN: 1–4094")
		}
		if err := s.Row(ctx, "SELECT id FROM vlan_catalog WHERE id=?", vlan).Scan(&existing); err != nil {
			return DynamicResult{}, fmt.Errorf("unknown VLAN")
		}
	}
	request := radius.New(code, []byte(secret))
	clear(request.Authenticator[:])
	if err := rfc2866.AcctSessionID_SetString(request, id); err != nil {
		return DynamicResult{}, err
	}
	if mac != "" {
		if err := rfc2865.CallingStationID_SetString(request, mac); err != nil {
			return DynamicResult{}, err
		}
	}
	if username != "" {
		if err := rfc2865.UserName_SetString(request, username); err != nil {
			return DynamicResult{}, err
		}
	}
	timestamp := make([]byte, 4)
	binary.BigEndian.PutUint32(timestamp, uint32(time.Now().Unix()))
	request.Attributes.Add(55, timestamp)
	if action == "vlan" {
		if err := rfc2868.TunnelType_Set(request, 0, 13); err != nil {
			return DynamicResult{}, err
		}
		if err := rfc2868.TunnelMediumType_Set(request, 0, 6); err != nil {
			return DynamicResult{}, err
		}
		if err := rfc2868.TunnelPrivateGroupID_SetString(request, 0, strconv.Itoa(vlan)); err != nil {
			return DynamicResult{}, err
		}
	}
	if err := SignMessageAuthenticator(request); err != nil {
		return DynamicResult{}, err
	}
	wire, err := request.Encode()
	if err != nil {
		return DynamicResult{}, err
	}
	exchangeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	client := &radius.Client{Retry: time.Second, MaxPacketErrors: 3}
	if action == "disconnect" {
		if err = s.BeginPublicationRevocation(ctx, session); err != nil {
			return DynamicResult{}, err
		}
	}
	response, err := client.Exchange(exchangeCtx, request, net.JoinHostPort(nas, strconv.Itoa(port)))
	if err != nil {
		return DynamicResult{}, fmt.Errorf("NAS did not return an authenticated response")
	}
	if response.Identifier != request.Identifier || (response.Code != ack && response.Code != nak) {
		return DynamicResult{}, fmt.Errorf("unexpected dynamic authorization response")
	}
	// Response Authenticator was checked by Client. If MA is present, its input
	// uses the original request authenticator, not the response MD5 value.
	hasMA := false
	for _, a := range response.Attributes {
		if a.Type == 80 {
			hasMA = true
		}
	}
	if hasMA {
		raw, err := response.MarshalBinary()
		if err != nil {
			return DynamicResult{}, err
		}
		copy(raw[4:20], wire[4:20])
		if !VerifyMessageAuthenticator(raw, []byte(secret)) {
			return DynamicResult{}, fmt.Errorf("invalid response Message-Authenticator")
		}
	}
	if value := response.Attributes.Get(55); value != nil {
		if len(value) != 4 {
			return DynamicResult{}, fmt.Errorf("invalid response timestamp")
		}
		delta := time.Now().Unix() - int64(binary.BigEndian.Uint32(value))
		if delta > 300 || delta < -300 {
			return DynamicResult{}, fmt.Errorf("stale NAS response")
		}
	}
	result := DynamicResult{Acknowledged: response.Code == ack, Code: response.Code.String()}
	if cause := response.Attributes.Get(101); cause != nil {
		if len(cause) != 4 {
			return DynamicResult{}, fmt.Errorf("invalid Error-Cause")
		}
		result.ErrorCause = binary.BigEndian.Uint32(cause)
	}
	nasResponse = store.RevocationNASResponse{Code: result.Code, Cause: int64(result.ErrorCause)}
	outcome := "denied"
	if result.Acknowledged {
		outcome = "acknowledged"
	}
	if err = s.Audit(ctx, "web", nas+"/"+id, outcome, fmt.Sprintf("%s %s Error-Cause=%d", action, result.Code, result.ErrorCause)); err != nil {
		return result, fmt.Errorf("dynamic authorization completed but audit failed")
	}
	if !result.Acknowledged && result.ErrorCause == 406 && action == "disconnect" && fallback != nil {
		confirmed, e := fallback(ctx, store.Session{NAS: nas, ID: id, MAC: mac, Username: username, Updated: updated, GrantToken: grantToken, Generation: generation, StartedAt: startedAt})
		if e != nil {
			return result, e
		}
		if confirmed {
			result.Acknowledged = true
			result.Code = "RouterOS-SSH-Disconnect"
			result.ErrorCause = 0
			if e = s.Audit(ctx, "routeros", nas+"/"+id, "acknowledged", "management SSH session removal verified"); e != nil {
				return result, fmt.Errorf("RouterOS disconnected session but audit failed")
			}
		}
	}
	if result.Acknowledged && action == "disconnect" {
		if err = s.ConfirmDisconnect(ctx, store.Session{NAS: nas, ID: id, MAC: mac, Username: username, GrantToken: grantToken, Generation: generation}); err != nil {
			return result, fmt.Errorf("NAS disconnected session, local status update failed")
		}
	}
	return result, nil
}
