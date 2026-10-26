// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/rkislov/border/internal/identity"
	"strconv"
	"strings"
	"time"
)

type Fingerprint struct {
	MAC, NAS, DHCPOptions, VendorClass, Hostname, OS, Manufacturer, DeviceType, Source string
	FirstSeen, LastSeen                                                                int64
	OUIManufacturer                                                                    string
}

func (s *Store) ObserveFingerprint(ctx context.Context, f Fingerprint) error {
	mac, err := identity.MAC(f.MAC)
	if err != nil {
		return err
	}
	f.MAC = mac
	for _, v := range []string{f.NAS, f.VendorClass, f.Hostname, f.OS, f.Manufacturer, f.DeviceType} {
		if len(v) > 253 || strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("invalid fingerprint field")
		}
	}
	if len(f.DHCPOptions) > 1024 {
		return fmt.Errorf("DHCP option list too long")
	}
	if f.DHCPOptions != "" {
		for _, v := range strings.Split(f.DHCPOptions, ",") {
			n, e := strconv.Atoi(v)
			if e != nil || n < 0 || n > 255 {
				return fmt.Errorf("DHCP options must be ordered comma-separated bytes")
			}
		}
	}
	if f.Source != "radius" && f.Source != "admin" {
		return fmt.Errorf("invalid observation source")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if f.Source == "radius" {
		_, err = tx.ExecContext(ctx, s.SQL("INSERT INTO device_fingerprints(mac,nas,source,first_seen,last_seen) VALUES(?,?,?,?,?) ON CONFLICT(mac) DO UPDATE SET nas=excluded.nas,last_seen=excluded.last_seen"), f.MAC, f.NAS, f.Source, now, now)
	} else {
		_, err = tx.ExecContext(ctx, s.SQL("INSERT INTO device_fingerprints(mac,nas,dhcp_options,vendor_class,hostname,os,manufacturer,device_type,source,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(mac) DO UPDATE SET nas=excluded.nas,dhcp_options=excluded.dhcp_options,vendor_class=excluded.vendor_class,hostname=excluded.hostname,os=excluded.os,manufacturer=excluded.manufacturer,device_type=excluded.device_type,source=excluded.source,last_seen=excluded.last_seen"), f.MAC, f.NAS, f.DHCPOptions, f.VendorClass, f.Hostname, f.OS, f.Manufacturer, f.DeviceType, f.Source, now, now)
	}
	if err != nil {
		return err
	}
	// Raw RADIUS packets only update presence. Administrative evidence is retained
	// separately and cannot be overwritten by an unauthenticated endpoint's hints.
	if f.Source == "admin" {
		raw, e := json.Marshal(f)
		if e != nil {
			return e
		}
		if _, err = tx.ExecContext(ctx, s.SQL("INSERT INTO fingerprint_history(id,mac,observed_at,source,detail) VALUES(?,?,?,?,?)"), uuid.NewString(), f.MAC, now, f.Source, string(raw)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, s.SQL("DELETE FROM fingerprint_history WHERE mac=? AND id NOT IN (SELECT id FROM fingerprint_history WHERE mac=? ORDER BY observed_at DESC,id DESC LIMIT 100)"), f.MAC, f.MAC); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) Fingerprints(ctx context.Context) ([]Fingerprint, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT mac,nas,dhcp_options,vendor_class,hostname,os,manufacturer,device_type,source,first_seen,last_seen FROM device_fingerprints ORDER BY last_seen DESC,mac LIMIT 1000")
	if err != nil {
		return nil, err
	}
	out := []Fingerprint{}
	for rows.Next() {
		var f Fingerprint
		if err = rows.Scan(&f.MAC, &f.NAS, &f.DHCPOptions, &f.VendorClass, &f.Hostname, &f.OS, &f.Manufacturer, &f.DeviceType, &f.Source, &f.FirstSeen, &f.LastSeen); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, f)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range out {
		compact := strings.ReplaceAll(out[i].MAC, ":", "")
		b, _ := hex.DecodeString(compact[:2])
		if b[0]&2 != 0 {
			continue
		} // randomized/local MAC: no trustworthy OUI vendor
		var vendor string
		err = s.Row(ctx, "SELECT manufacturer FROM oui_prefixes WHERE prefix IN (?,?,?) ORDER BY LENGTH(prefix) DESC LIMIT 1", compact[:6], compact[:7], compact[:9]).Scan(&vendor)
		if err == nil {
			out[i].OUIManufacturer = vendor
		}
	}
	return out, nil
}
func (s *Store) SetOUI(ctx context.Context, prefix, manufacturer string) error {
	prefix = strings.ToLower(strings.NewReplacer(":", "", "-", "").Replace(prefix))
	if len(prefix) != 6 && len(prefix) != 7 && len(prefix) != 9 {
		return fmt.Errorf("prefix must contain 6, 7 or 9 hex digits")
	}
	if _, err := strconv.ParseUint(prefix, 16, 64); err != nil {
		return fmt.Errorf("invalid OUI")
	}
	if manufacturer == "" || len(manufacturer) > 200 {
		return fmt.Errorf("manufacturer required")
	}
	return s.Exec(ctx, "INSERT INTO oui_prefixes(prefix,manufacturer) VALUES(?,?) ON CONFLICT(prefix) DO UPDATE SET manufacturer=excluded.manufacturer", prefix, manufacturer)
}
