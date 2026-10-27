// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/rkislov/border/internal/radprofile"
	"regexp"
	"strings"
	"time"
)

type AuthenticationPolicy struct {
	ID, Name, Source, DomainID string
	RequireTOTP, Enabled       bool
}
type AccessPolicy struct {
	ID, Name, AuthenticationID, Mode, SegmentID string
	ValidFrom, ValidUntil                       int64
	SessionSeconds, IdleSeconds                 int
	Privilege                                   int
	Group, Role, Filter                         string
	Enabled                                     bool
	Subjects                                    []string
}
type BoundPolicy struct {
	Authentication AuthenticationPolicy
	Access         AccessPolicy
	VLAN           int
}

func (s *Store) BoundPolicy(ctx context.Context, nas string) (*BoundPolicy, error) {
	var id, location sql.NullString
	if err := s.Row(ctx, "SELECT access_policy_id,location_id FROM nas WHERE address=?", nas).Scan(&id, &location); err != nil {
		return nil, err
	}
	if !id.Valid {
		return nil, nil
	}
	p := &BoundPolicy{}
	a, b := &p.Access, &p.Authentication
	var segment, domain sql.NullString
	err := s.Row(ctx, "SELECT p.id,p.name,p.authentication_id,p.mode,p.segment_id,p.valid_from,p.valid_until,p.session_seconds,p.idle_seconds,p.privilege,p.group_name,p.role,p.filter_id,p.enabled,a.id,a.name,a.source,a.domain_id,a.require_totp,a.enabled FROM access_policies p JOIN authentication_policies a ON a.id=p.authentication_id WHERE p.id=?", id.String).Scan(&a.ID, &a.Name, &a.AuthenticationID, &a.Mode, &segment, &a.ValidFrom, &a.ValidUntil, &a.SessionSeconds, &a.IdleSeconds, &a.Privilege, &a.Group, &a.Role, &a.Filter, &a.Enabled, &b.ID, &b.Name, &b.Source, &domain, &b.RequireTOTP, &b.Enabled)
	if err != nil {
		return nil, err
	}
	a.SegmentID = segment.String
	b.DomainID = domain.String
	if a.Mode == "network" {
		err = s.Row(ctx, "SELECT vlan FROM nas_segments WHERE nas=? AND segment_id=?", nas, a.SegmentID).Scan(&p.VLAN)
		if err == sql.ErrNoRows && location.Valid {
			err = s.Row(ctx, "SELECT vlan FROM location_segments WHERE location_id=? AND segment_id=?", location.String, a.SegmentID).Scan(&p.VLAN)
		}
		if err != nil {
			return nil, fmt.Errorf("logical segment is not mapped on this NAS")
		}
	}
	return p, nil
}
func (p BoundPolicy) Timeout(now time.Time) (uint32, error) {
	a := p.Access
	n := now.Unix()
	if !a.Enabled || !p.Authentication.Enabled || n < a.ValidFrom || (a.ValidUntil != 0 && n >= a.ValidUntil) {
		return 0, fmt.Errorf("policy disabled or outside validity period")
	}
	ttl := int64(a.SessionSeconds)
	if a.ValidUntil > 0 && a.ValidUntil-n < ttl {
		ttl = a.ValidUntil - n
	}
	if ttl <= 0 {
		return 0, fmt.Errorf("invalid session duration")
	}
	return uint32(ttl), nil
}
func (s *Store) PolicySubject(ctx context.Context, policy, user string) bool {
	var v int
	return s.Row(ctx, "SELECT 1 FROM policy_subjects WHERE policy_id=? AND identity=?", policy, user).Scan(&v) == nil
}
func (p BoundPolicy) Grant() radprofile.Grant {
	return radprofile.Grant{Mode: p.Access.Mode, Privilege: p.Access.Privilege, Group: p.Access.Group, Role: p.Access.Role, Filter: p.Access.Filter}
}

func (s *Store) SaveAuthentication(ctx context.Context, a AuthenticationPolicy) error {
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`).MatchString(a.ID) || a.Name == "" || len(a.Name) > 100 {
		return fmt.Errorf("policy ID and name required")
	}
	switch a.Source {
	case "local", "directory", "codes", "mab", "eap_tls":
	default:
		return fmt.Errorf("invalid authentication source")
	}
	if a.RequireTOTP && a.Source != "local" && a.Source != "directory" {
		return fmt.Errorf("TOTP requires local or directory password")
	}
	var domain any
	if a.Source == "directory" {
		if a.DomainID == "" {
			return fmt.Errorf("select a domain")
		}
		domain = a.DomainID
	} else if a.DomainID != "" {
		return fmt.Errorf("domain only applies to directory authentication")
	}
	return s.Exec(ctx, "INSERT INTO authentication_policies(id,name,source,domain_id,require_totp,enabled) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,source=excluded.source,domain_id=excluded.domain_id,require_totp=excluded.require_totp,enabled=excluded.enabled", a.ID, a.Name, a.Source, domain, integer(a.RequireTOTP), integer(a.Enabled))
}
func integer(b bool) int {
	if b {
		return 1
	}
	return 0
}
func (s *Store) SaveAccess(ctx context.Context, a AccessPolicy) error {
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`).MatchString(a.ID) || a.Name == "" || len(a.Name) > 100 || a.AuthenticationID == "" || a.SessionSeconds < 60 || a.SessionSeconds > 86400 || a.IdleSeconds < 0 || a.IdleSeconds > 86400 || a.ValidFrom < 0 || a.ValidUntil < 0 || (a.ValidUntil != 0 && a.ValidUntil <= a.ValidFrom) {
		return fmt.Errorf("invalid access policy or validity period")
	}
	if a.Mode != "network" && a.Mode != "ssh" && a.Mode != "vpn" {
		return fmt.Errorf("invalid access mode")
	}
	if strings.ContainsAny(a.Group+a.Role+a.Filter, "\r\n\x00") {
		return fmt.Errorf("invalid authorization attribute")
	}
	if a.Privilege < 0 || a.Privilege > 15 || len(a.Group) > 100 || len(a.Role) > 100 || len(a.Filter) > 100 {
		return fmt.Errorf("invalid RADIUS authorization attributes")
	}
	var segment any
	if a.Mode == "network" {
		if a.SegmentID == "" {
			return fmt.Errorf("logical segment required")
		}
		segment = a.SegmentID
	} else if a.SegmentID != "" {
		return fmt.Errorf("VLAN segment only applies to network access")
	}
	if len(a.Subjects) == 0 || len(a.Subjects) > 1000 {
		return fmt.Errorf("explicit identities required (1–1000)")
	}
	var source string
	if err := s.Row(ctx, "SELECT source FROM authentication_policies WHERE id=?", a.AuthenticationID).Scan(&source); err != nil {
		return fmt.Errorf("authentication policy required")
	}
	if a.Mode != "network" && (source == "mab" || source == "eap_tls") {
		return fmt.Errorf("SSH/VPN policy currently requires PAP authentication")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, s.SQL("INSERT INTO access_policies(id,name,authentication_id,mode,segment_id,valid_from,valid_until,session_seconds,idle_seconds,privilege,group_name,role,filter_id,enabled) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,authentication_id=excluded.authentication_id,mode=excluded.mode,segment_id=excluded.segment_id,valid_from=excluded.valid_from,valid_until=excluded.valid_until,session_seconds=excluded.session_seconds,idle_seconds=excluded.idle_seconds,privilege=excluded.privilege,group_name=excluded.group_name,role=excluded.role,filter_id=excluded.filter_id,enabled=excluded.enabled"), a.ID, a.Name, a.AuthenticationID, a.Mode, segment, a.ValidFrom, a.ValidUntil, a.SessionSeconds, a.IdleSeconds, a.Privilege, a.Group, a.Role, a.Filter, integer(a.Enabled))
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, s.SQL("DELETE FROM policy_subjects WHERE policy_id=?"), a.ID); err != nil {
		return err
	}
	for _, user := range a.Subjects {
		if user == "" || len(user) > 200 {
			return fmt.Errorf("invalid identity")
		}
		if _, err = tx.ExecContext(ctx, s.SQL("INSERT INTO policy_subjects(policy_id,identity) VALUES(?,?)"), a.ID, user); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) Authentications(ctx context.Context) ([]AuthenticationPolicy, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT id,name,source,COALESCE(domain_id,''),require_totp,enabled FROM authentication_policies ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuthenticationPolicy{}
	for rows.Next() {
		var a AuthenticationPolicy
		if err = rows.Scan(&a.ID, &a.Name, &a.Source, &a.DomainID, &a.RequireTOTP, &a.Enabled); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *Store) Accesses(ctx context.Context) ([]AccessPolicy, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT id,name,authentication_id,mode,COALESCE(segment_id,''),valid_from,valid_until,session_seconds,idle_seconds,privilege,group_name,role,filter_id,enabled FROM access_policies ORDER BY name")
	if err != nil {
		return nil, err
	}
	out := []AccessPolicy{}
	for rows.Next() {
		var a AccessPolicy
		if err = rows.Scan(&a.ID, &a.Name, &a.AuthenticationID, &a.Mode, &a.SegmentID, &a.ValidFrom, &a.ValidUntil, &a.SessionSeconds, &a.IdleSeconds, &a.Privilege, &a.Group, &a.Role, &a.Filter, &a.Enabled); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range out {
		rows, err := s.DB.QueryContext(ctx, s.SQL("SELECT identity FROM policy_subjects WHERE policy_id=? ORDER BY identity"), out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Subjects = []string{}
		for rows.Next() {
			var u string
			if err = rows.Scan(&u); err != nil {
				rows.Close()
				return nil, err
			}
			out[i].Subjects = append(out[i].Subjects, u)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

type Named struct{ ID, Name string }

func (s *Store) NamedList(ctx context.Context, kind string) ([]Named, error) {
	if kind != "locations" && kind != "network_segments" {
		return nil, fmt.Errorf("unknown catalog")
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT id,name FROM "+kind+" ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Named{}
	for rows.Next() {
		var n Named
		if err = rows.Scan(&n.ID, &n.Name); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

type SegmentMapping struct {
	LocationID, NAS, SegmentID string
	VLAN                       int
}

func (s *Store) SaveMapping(ctx context.Context, m SegmentMapping) error {
	if m.SegmentID == "" || m.VLAN < 1 || m.VLAN > 4094 || (m.LocationID == "") == (m.NAS == "") {
		return fmt.Errorf("choose exactly one location or NAS, segment and VLAN 1–4094")
	}
	if m.NAS != "" {
		return s.Exec(ctx, "INSERT INTO nas_segments(nas,segment_id,vlan) VALUES(?,?,?) ON CONFLICT(nas,segment_id) DO UPDATE SET vlan=excluded.vlan", m.NAS, m.SegmentID, m.VLAN)
	}
	return s.Exec(ctx, "INSERT INTO location_segments(location_id,segment_id,vlan) VALUES(?,?,?) ON CONFLICT(location_id,segment_id) DO UPDATE SET vlan=excluded.vlan", m.LocationID, m.SegmentID, m.VLAN)
}
func (s *Store) Mappings(ctx context.Context) ([]SegmentMapping, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT location_id,'',segment_id,vlan FROM location_segments UNION ALL SELECT '',nas,segment_id,vlan FROM nas_segments")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SegmentMapping{}
	for rows.Next() {
		var m SegmentMapping
		if err = rows.Scan(&m.LocationID, &m.NAS, &m.SegmentID, &m.VLAN); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
