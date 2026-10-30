package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"regexp"
	"sort"
	"strings"
)

// Steps lists mandatory checks in execution order. primary is the policy source.
func (a AuthenticationPolicy) Chain() []string {
	if len(a.Steps) > 0 {
		return a.Steps
	}
	out := []string{"primary"}
	if a.RequireTOTP {
		out = append(out, "totp")
	}
	return out
}
func (a AuthenticationPolicy) ValidateChain() error {
	if a.EAPMethod != "" {
		if (a.EAPMethod != "peap" && a.EAPMethod != "ttls") || (a.Source != "local" && a.Source != "directory") {
			return fmt.Errorf("tunneled EAP requires local or directory source")
		}
		for _, step := range a.Chain() {
			if step != "primary" && step != "device" {
				return fmt.Errorf("tunneled EAP currently supports primary and device checks only")
			}
		}
	}

	seen := map[string]bool{}
	for _, step := range a.Chain() {
		if seen[step] {
			return fmt.Errorf("duplicate authentication step")
		}
		seen[step] = true
		switch step {
		case "primary":
		case "device":
			if a.Source == "mab" {
				return fmt.Errorf("MAB already checks device identity")
			}
			if a.Source == "eap_tls" && !seen["primary"] {
				return fmt.Errorf("EAP certificate must be the first step")
			}
		case "totp":
			if !seen["primary"] || (a.Source != "local" && a.Source != "directory") {
				return fmt.Errorf("TOTP must follow local or directory password")
			}
		default:
			return fmt.Errorf("unknown authentication step")
		}
	}
	if a.RequireTOTP && !seen["totp"] {
		return fmt.Errorf("RequireTOTP conflicts with explicit chain")
	}
	if !seen["primary"] {
		return fmt.Errorf("primary authentication required")
	}
	return nil
}

type PolicyBinding struct {
	ID, PolicyID, Protocol, IdentitySource, SSID string
	Priority, ServiceType                        int
	NASPortType                                  *int
	Enabled                                      bool
}
type NASPolicySet struct {
	NAS      string
	Version  int64
	Enabled  bool
	Bindings []PolicyBinding
}
type PolicyRequest struct {
	Protocol, Username, SSID string
	ServiceType              int
	NASPortType              *int
}

func (s *Store) NASPolicies(ctx context.Context, nas string) (NASPolicySet, error) {
	set := NASPolicySet{NAS: nas, Bindings: []PolicyBinding{}}
	var raw string
	err := s.Row(ctx, "SELECT version,config FROM nas_policy_sets WHERE nas=?", nas).Scan(&set.Version, &raw)
	if err == sql.ErrNoRows {
		return set, nil
	}
	if err != nil {
		return set, err
	}
	var saved NASPolicySet
	if err = json.Unmarshal([]byte(raw), &saved); err != nil {
		return set, err
	}
	set.Enabled = saved.Enabled
	set.Bindings = saved.Bindings
	return set, nil
}
func (s *Store) SaveNASPolicies(ctx context.Context, set NASPolicySet) error {
	if set.Version < 0 || len(set.Bindings) > 32 {
		return fmt.Errorf("invalid version or more than 32 policies")
	}
	priorities := map[int]bool{}
	ids := map[string]bool{}
	for _, b := range set.Bindings {
		if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`).MatchString(b.ID) || ids[b.ID] || b.Priority < 0 || b.Priority > 65535 || priorities[b.Priority] {
			return fmt.Errorf("unique binding ID and priority required")
		}
		ids[b.ID] = true
		priorities[b.Priority] = true
		if b.Protocol != "pap" && b.Protocol != "eap" && b.Protocol != "mab" && b.Protocol != "mschapv2" {
			return fmt.Errorf("select PAP, MS-CHAPv2, EAP or MAB")
		}
		if b.ServiceType < 0 || b.ServiceType > 255 || (b.NASPortType != nil && (*b.NASPortType < 0 || *b.NASPortType > 255)) || len(b.SSID) > 32 || strings.ContainsAny(b.SSID, "\x00\r\n") {
			return fmt.Errorf("invalid request selector")
		}
		if b.IdentitySource != "" && b.Protocol != "pap" && b.Protocol != "mschapv2" && b.Protocol != "eap" {
			return fmt.Errorf("domain selector requires password authentication")
		}
		var source, mode, method string
		if err := s.Row(ctx, "SELECT a.source,p.mode,a.eap_method FROM access_policies p JOIN authentication_policies a ON a.id=p.authentication_id WHERE p.id=?", b.PolicyID).Scan(&source, &mode, &method); err != nil {
			return fmt.Errorf("unknown access policy")
		}
		expected := "pap"
		if source == "mab" {
			expected = "mab"
		}
		if source == "eap_tls" {
			expected = "eap"
		}
		if b.Protocol == "mschapv2" && (source == "local" || source == "directory") {
			expected = "mschapv2"
		}
		if b.Protocol == "eap" && mode == "vpn" && (source == "local" || source == "directory") {
			expected = "eap"
		}
		if method != "" {
			expected = "eap"
			if mode != "network" {
				return fmt.Errorf("tunneled EAP requires network policy")
			}
		}
		if expected != b.Protocol {
			return fmt.Errorf("protocol does not match authentication source")
		}
		if b.IdentitySource != "" && b.IdentitySource != "local" {
			var exists int
			if err := s.Row(ctx, "SELECT 1 FROM domains WHERE id=?", b.IdentitySource).Scan(&exists); err != nil {
				return fmt.Errorf("unknown identity domain")
			}
		}
	}
	sort.Slice(set.Bindings, func(i, j int) bool { return set.Bindings[i].Priority < set.Bindings[j].Priority })
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Lock the NAS before the version check, including first creation.
	result, err := tx.ExecContext(ctx, s.SQL("UPDATE nas SET name=name WHERE address=?"), set.NAS)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return fmt.Errorf("unknown NAS")
	}
	var version int64
	err = tx.QueryRowContext(ctx, s.SQL("SELECT version FROM nas_policy_sets WHERE nas=?"), set.NAS).Scan(&version)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if version != set.Version {
		return fmt.Errorf("policy set changed; reload before saving")
	}
	set.Version++
	raw, err := json.Marshal(set)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, s.SQL("INSERT INTO nas_policy_sets(nas,version,enabled,config) VALUES(?,?,?,?) ON CONFLICT(nas) DO UPDATE SET version=excluded.version,enabled=excluded.enabled,config=excluded.config"), set.NAS, set.Version, integer(set.Enabled), string(raw)); err != nil {
		return err
	}
	return tx.Commit()
}

// First matching binding wins. Its authentication failure is terminal.
func (s *Store) SelectPolicy(ctx context.Context, nas string, request PolicyRequest) (*BoundPolicy, bool, error) {
	return s.selectPolicy(ctx, nas, request, nil)
}

func (s *Store) selectPolicy(ctx context.Context, nas string, request PolicyRequest, trace *[]BindingTrace) (*BoundPolicy, bool, error) {
	set, err := s.NASPolicies(ctx, nas)
	if err != nil {
		return nil, true, err
	}
	if !set.Enabled {
		p, err := s.BoundPolicy(ctx, nas)
		return p, p != nil, err
	}
	for _, b := range set.Bindings {
		reason := bindingMismatch(b, request)
		if trace != nil {
			*trace = append(*trace, BindingTrace{ID: b.ID, PolicyID: b.PolicyID, Priority: b.Priority, Reason: reason})
		}
		if reason != "selected" {
			continue
		}
		p, err := s.policyForNAS(ctx, nas, b.PolicyID)
		if err != nil {
			return nil, true, err
		}
		expected := "pap"
		if p.Authentication.Source == "mab" {
			expected = "mab"
		}
		if p.Authentication.Source == "eap_tls" || p.Authentication.EAPMethod != "" {
			expected = "eap"
		}
		if b.Protocol == "mschapv2" && (p.Authentication.Source == "local" || p.Authentication.Source == "directory") {
			expected = "mschapv2"
		}
		if b.Protocol == "eap" && p.Access.Mode == "vpn" && (p.Authentication.Source == "local" || p.Authentication.Source == "directory") {
			expected = "eap"
		}
		if p.Authentication.EAPMethod != "" {
			expected = "eap"
			if p.Access.Mode != "network" {
				return nil, true, fmt.Errorf("tunneled EAP requires network policy")
			}
		}
		if expected != b.Protocol {
			return nil, true, fmt.Errorf("binding protocol no longer matches authentication source")
		}
		p.BindingID = b.ID
		p.BindingVersion = set.Version
		return p, true, nil
	}
	return nil, true, nil
}

func (s *Store) NewPolicyGrant(ctx context.Context, nas, user string, p *BoundPolicy, expires int64) (string, error) {
	id := ""
	var version int64
	if p != nil {
		id = p.Access.ID
		version = p.BindingVersion
	}
	token := "border:" + uuid.NewString()
	return token, s.Exec(ctx, "INSERT INTO access_grants(token,nas,username,policy_id,expires_at,binding_version) VALUES(?,?,?,?,?,?)", token, nas, strings.ToLower(user), id, expires, version)
}
