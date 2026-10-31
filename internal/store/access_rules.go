// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"net"
	"regexp"
	"slices"
	"strings"
)

type UserGroup struct {
	ID, Name string
	Enabled  bool
	Members  []string
}
type AccessRule struct {
	ID, Name, Effect                                      string
	Priority                                              int
	Enabled, AllAuthenticated                             bool
	Subjects, Groups, DirectoryGroups                     []string
	NAS, Locations, SSIDs, OS, DeviceTypes, Manufacturers []string
}
type RuleSet struct {
	PolicyID string
	Enabled  bool
	Version  int64
	Rules    []AccessRule
}
type AccessContext struct {
	Username, NAS, Location, SSID, MAC, OS, DeviceType, Manufacturer string
	DirectoryGroups                                                  []string
}

var ruleID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func (s *Store) SaveUserGroup(ctx context.Context, g UserGroup) error {
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = s.saveGroupTx(ctx, tx, g); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) saveGroupTx(ctx context.Context, tx *sql.Tx, g UserGroup) error {
	if !ruleID.MatchString(g.ID) || g.Name == "" || len(g.Name) > 100 || len(g.Members) > 1000 {
		return fmt.Errorf("invalid group")
	}
	var e error
	if _, e = tx.ExecContext(ctx, s.SQL("INSERT INTO user_groups(id,name,enabled) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled"), g.ID, g.Name, integer(g.Enabled)); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, s.SQL("DELETE FROM user_group_members WHERE group_id=?"), g.ID); e != nil {
		return e
	}
	for _, member := range g.Members {
		member = strings.ToLower(strings.TrimSpace(member))
		domain, user, ok := strings.Cut(member, "/")
		if !regexp.MustCompile(`^oidc:[a-f0-9]{64}$`).MatchString(member) && (!ok || !ruleID.MatchString(domain) || user == "" || len(member) > 200 || strings.ContainsAny(member, "\r\n\x00")) {
			return fmt.Errorf("group members must use local/login or domain/login")
		}
		if _, e = tx.ExecContext(ctx, s.SQL("INSERT INTO user_group_members(group_id,username) VALUES(?,?)"), g.ID, member); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) UserGroups(ctx context.Context) ([]UserGroup, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT g.id,g.name,g.enabled,m.username FROM user_groups g LEFT JOIN user_group_members m ON m.group_id=g.id ORDER BY g.name,g.id,m.username")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []UserGroup{}
	for rows.Next() {
		var id, name string
		var enabled bool
		var user sql.NullString
		if e = rows.Scan(&id, &name, &enabled, &user); e != nil {
			return nil, e
		}
		if len(out) == 0 || out[len(out)-1].ID != id {
			out = append(out, UserGroup{ID: id, Name: name, Enabled: enabled, Members: []string{}})
		}
		if user.Valid {
			out[len(out)-1].Members = append(out[len(out)-1].Members, user.String)
		}
	}
	return out, rows.Err()
}
func (s *Store) Rules(ctx context.Context, id string) (RuleSet, error) {
	c := RuleSet{PolicyID: id, Rules: []AccessRule{}}
	var raw string
	e := s.Row(ctx, "SELECT version,config FROM access_rule_sets WHERE policy_id=?", id).Scan(&c.Version, &raw)
	if e == sql.ErrNoRows {
		return c, nil
	}
	if e != nil {
		return c, e
	}
	version := c.Version
	e = json.Unmarshal([]byte(raw), &c)
	c.Version = version
	if c.Rules == nil {
		c.Rules = []AccessRule{}
	}
	return c, e
}
func (s *Store) SaveRules(ctx context.Context, c RuleSet) error {
	tx, err := s.policyTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.saveRulesTx(ctx, tx, c); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) saveRulesTx(ctx context.Context, tx *sql.Tx, c RuleSet) error {
	if c.Rules == nil {
		c.Rules = []AccessRule{}
	}
	if len(c.Rules) > 100 || c.Version < 0 {
		return fmt.Errorf("maximum 100 rules")
	}
	var e error
	var source string
	q := "SELECT a.source FROM access_policies p JOIN authentication_policies a ON a.id=p.authentication_id WHERE p.id=?"
	if s.Driver == "pgx" {
		q += " FOR UPDATE OF p"
	}
	if e = tx.QueryRowContext(ctx, s.SQL(q), c.PolicyID).Scan(&source); e != nil {
		return fmt.Errorf("policy not found")
	}
	ids := map[string]bool{}
	priorities := map[int]bool{}
	for i := range c.Rules {
		r := &c.Rules[i]
		if !ruleID.MatchString(r.ID) || ids[r.ID] || r.Name == "" || len(r.Name) > 100 || r.Priority < 0 || r.Priority > 65535 || priorities[r.Priority] || (r.Effect != "allow" && r.Effect != "deny") {
			return fmt.Errorf("unique rule IDs and priorities, name and allow/deny effect required")
		}
		ids[r.ID] = true
		priorities[r.Priority] = true
		if !r.AllAuthenticated && len(r.Subjects)+len(r.Groups)+len(r.DirectoryGroups) == 0 {
			return fmt.Errorf("select subjects/groups or explicitly all authenticated")
		}
		for _, values := range [][]string{r.Subjects, r.Groups, r.DirectoryGroups, r.NAS, r.Locations, r.SSIDs, r.OS, r.DeviceTypes, r.Manufacturers} {
			if len(values) > 100 {
				return fmt.Errorf("maximum 100 values per condition")
			}
			for _, v := range values {
				if strings.TrimSpace(v) == "" || len(v) > 512 || strings.ContainsAny(v, "\r\n\x00") {
					return fmt.Errorf("invalid rule value")
				}
			}
		}
		for j := range r.Subjects {
			r.Subjects[j] = strings.ToLower(strings.TrimSpace(r.Subjects[j]))
		}
		for _, id := range r.Groups {
			var n int
			if tx.QueryRowContext(ctx, s.SQL("SELECT 1 FROM user_groups WHERE id=?"), id).Scan(&n) != nil {
				return fmt.Errorf("unknown local group")
			}
		}
		for _, id := range r.Locations {
			var n int
			if tx.QueryRowContext(ctx, s.SQL("SELECT 1 FROM locations WHERE id=?"), id).Scan(&n) != nil {
				return fmt.Errorf("unknown location")
			}
		}
		for _, address := range r.NAS {
			if ip := net.ParseIP(address); ip == nil || ip.String() != address {
				return fmt.Errorf("NAS condition requires canonical IP")
			}
			var n int
			if tx.QueryRowContext(ctx, s.SQL("SELECT 1 FROM nas WHERE address=?"), address).Scan(&n) != nil {
				return fmt.Errorf("unknown NAS")
			}
		}
		for _, ssid := range r.SSIDs {
			if len(ssid) > 32 {
				return fmt.Errorf("SSID must contain at most 32 bytes")
			}
		}
		if len(r.DirectoryGroups) > 0 && source != "directory" {
			return fmt.Errorf("LDAP groups require a directory-password authentication policy")
		}
		for _, dn := range r.DirectoryGroups {
			parsed, e := ldap.ParseDN(dn)
			if e != nil || len(parsed.RDNs) == 0 {
				return fmt.Errorf("LDAP group requires full distinguished name")
			}
		}
	}
	slices.SortFunc(c.Rules, func(a, b AccessRule) int { return a.Priority - b.Priority })
	var current int64
	e = tx.QueryRowContext(ctx, s.SQL("SELECT version FROM access_rule_sets WHERE policy_id=?"), c.PolicyID).Scan(&current)
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	if current != c.Version {
		return fmt.Errorf("rules changed; reload before saving")
	}
	c.Version, e = s.nextConfigurationVersion(ctx, tx, "rules", c.PolicyID, current)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(c)
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, s.SQL("INSERT INTO access_rule_sets(policy_id,version,config) VALUES(?,?,?) ON CONFLICT(policy_id) DO UPDATE SET version=excluded.version,config=excluded.config"), c.PolicyID, c.Version, string(raw)); e != nil {
		return e
	}
	return nil
}
func matches(values []string, value string, fold bool) bool {
	if len(values) == 0 {
		return true
	}
	if value == "" {
		return false
	}
	for _, v := range values {
		if v == value || (fold && strings.EqualFold(v, value)) {
			return true
		}
	}
	return false
}
func (s *Store) EvaluateAccess(ctx context.Context, b *BoundPolicy, c AccessContext) (bool, string, error) {
	rules := b.Rules
	if !rules.Enabled {
		return s.PolicySubject(ctx, b.Access.ID, c.Username), "explicit identity", nil
	}
	for _, r := range rules.Rules {
		if !r.Enabled {
			continue
		}
		if !matches(r.NAS, c.NAS, false) || !matches(r.Locations, c.Location, false) || !matches(r.SSIDs, c.SSID, false) || !matches(r.OS, c.OS, true) || !matches(r.DeviceTypes, c.DeviceType, true) || !matches(r.Manufacturers, c.Manufacturer, true) {
			continue
		}
		audience := r.AllAuthenticated || slices.Contains(r.Subjects, c.Username)
		for _, id := range r.Groups {
			var n int
			e := s.Row(ctx, "SELECT 1 FROM user_groups g JOIN user_group_members m ON m.group_id=g.id WHERE g.id=? AND g.enabled=1 AND m.username=?", id, c.Username).Scan(&n)
			if e != nil && e != sql.ErrNoRows {
				return false, "group lookup failed", e
			}
			audience = audience || e == nil
		}
		if b.Authentication.Source == "directory" && strings.HasPrefix(c.Username, b.Authentication.DomainID+"/") {
			for _, wanted := range r.DirectoryGroups {
				a, e := ldap.ParseDN(wanted)
				if e != nil {
					return false, "invalid group DN", e
				}
				for _, actual := range c.DirectoryGroups {
					d, e := ldap.ParseDN(actual)
					if e == nil && a.EqualFold(d) {
						audience = true
					}
				}
			}
		}
		if audience {
			return r.Effect == "allow", "rule " + r.ID, nil
		}
	}
	return false, "no matching rule", nil
}
