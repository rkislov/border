// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package aaa

import (
	"context"
	"encoding/binary"
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

type DynamicResult struct {
	Acknowledged bool
	Code         string
	ErrorCause   uint32
}

// ChangeSession addresses only an active recorded session on a registered NAS.
// Authentication and Message-Authenticator follow RFC 5176 section 3.4.
func ChangeSession(ctx context.Context, s *store.Store, nas, id, action string, vlan int, expected ...store.Session) (DynamicResult, error) {
	if id == "" || len(id) > 253 || (action != "disconnect" && action != "vlan") {
		return DynamicResult{}, fmt.Errorf("invalid session action")
	}
	var secret, mac, username string
	var port int
	var updated int64
	if err := s.Row(ctx, "SELECT n.secret,n.coa_port,s.mac,s.username,s.updated_at FROM sessions s JOIN nas n ON n.address=s.nas WHERE s.nas=? AND s.session_id=? AND s.status='active'", nas, id).Scan(&secret, &port, &mac, &username, &updated); err != nil {
		return DynamicResult{}, fmt.Errorf("active session on registered NAS required")
	}
	if len(expected) > 0 {
		v := expected[0]
		if v.MAC != mac || v.Username != username || v.Updated != updated {
			return DynamicResult{}, fmt.Errorf("session changed; refresh the list")
		}
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
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	client := &radius.Client{Retry: time.Second, MaxPacketErrors: 3}
	response, err := client.Exchange(ctx, request, net.JoinHostPort(nas, strconv.Itoa(port)))
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
	outcome := "denied"
	if result.Acknowledged {
		outcome = "acknowledged"
	}
	if err = s.Audit(ctx, "web", nas+"/"+id, outcome, fmt.Sprintf("%s %s Error-Cause=%d", action, result.Code, result.ErrorCause)); err != nil {
		return DynamicResult{}, fmt.Errorf("dynamic authorization completed but audit failed")
	}
	if result.Acknowledged && action == "disconnect" {
		if err = s.Exec(ctx, "UPDATE sessions SET status='disconnect-ack',updated_at=? WHERE nas=? AND session_id=? AND mac=? AND username=? AND updated_at=? AND status='active'", time.Now().Unix(), nas, id, mac, username, updated); err != nil {
			return DynamicResult{}, fmt.Errorf("NAS disconnected session, local status update failed")
		}
	}
	return result, nil
}
