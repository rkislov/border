// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package guest

import (
	"context"
	"crypto/hmac"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rkislov/border/internal/store"
)

type ActivationStatus struct {
	State    string
	Attempts int
	Expires  int64
}

func (s *Service) activationObserved(ctx context.Context, id string) (bool, error) {
	var n int
	err := s.Store.Row(ctx, `SELECT count(*) FROM guest_authorizations g JOIN access_grants a ON a.guest_authorization_id=g.id JOIN sessions x ON x.grant_token=a.token AND x.nas=a.nas WHERE g.id=? AND x.status='active' AND a.reason='' AND a.expires_at>?`, id, time.Now().Unix()).Scan(&n)
	return n > 0, err
}

// The receipt reveals no NAS, MAC or contact and is unusable in another tenant.
func (s *Service) ActivationStatus(ctx context.Context, receipt string) (ActivationStatus, error) {
	var result ActivationStatus
	id, signature, ok := strings.Cut(receipt, ".")
	if !ok || len(id) != 64 || len(signature) != 64 || !hmac.Equal([]byte(signature), []byte(s.digest("guest-status", id))) {
		return result, fmt.Errorf("invalid activation receipt")
	}
	var nas, mac string
	if e := s.Store.Row(ctx, "SELECT nas,mac,activation_state,activation_attempts,expires_at FROM guest_authorizations WHERE id=?", id).Scan(&nas, &mac, &result.State, &result.Attempts, &result.Expires); e != nil {
		return result, fmt.Errorf("guest authorization unavailable")
	}
	g, e := s.Store.GuestAuthorization(ctx, nas, mac)
	if e != nil || g.ID != id {
		return result, fmt.Errorf("guest authorization expired or revoked")
	}
	active, e := s.activationObserved(ctx, id)
	if e != nil {
		return result, e
	}
	if active {
		result.State = "active"
	} else if result.State == "active" {
		result.State = "disconnected"
	}
	return result, nil
}
func (s *Service) StartActivations(parent context.Context) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			started := time.Now()
			err := s.ProcessActivations(ctx)
			s.Store.Metrics.Finish("guest_activation", started, err)
			if err != nil && ctx.Err() == nil {
				slog.Error("guest activation scan failed")
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}

// Leases survive restarts; adapters must tolerate retry after an uncertain result.
func (s *Service) ProcessActivations(ctx context.Context) error {
	if s.Activate == nil {
		return nil
	}
	rows, e := s.Store.DB.QueryContext(ctx, s.Store.SQL("SELECT id,nas,mac,activation_attempts,activation_state FROM guest_authorizations WHERE activation_state IN ('pending','awaiting_accounting','failed') AND activation_next<=? ORDER BY activation_next,id LIMIT 20"), time.Now().Unix())
	if e != nil {
		return e
	}
	type job struct {
		id, nas, mac string
		attempts     int
		state        string
	}
	var jobs []job
	for rows.Next() {
		var j job
		if e = rows.Scan(&j.id, &j.nas, &j.mac, &j.attempts, &j.state); e != nil {
			rows.Close()
			return e
		}
		jobs = append(jobs, j)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, j := range jobs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		g, e := s.Store.GuestAuthorization(ctx, j.nas, j.mac)
		if e != nil || g.ID != j.id {
			if e = s.Store.Exec(ctx, "DELETE FROM guest_authorizations WHERE id=?", j.id); e != nil {
				return e
			}
			continue
		}
		observed, e := s.activationObserved(ctx, j.id)
		if e != nil {
			return e
		}
		if observed {
			if e = s.Store.Exec(ctx, "UPDATE guest_authorizations SET activation_state='active',activation_error='' WHERE id=?", j.id); e != nil {
				return e
			}
			continue
		}
		if j.attempts >= 5 {
			if e = s.Store.Exec(ctx, "UPDATE guest_authorizations SET activation_state='failed',activation_error=CASE WHEN activation_error='' THEN 'accounting_not_confirmed' ELSE activation_error END,activation_next=? WHERE id=?", time.Now().Unix()+30, j.id); e != nil {
				return e
			}
			continue
		}
		now := time.Now().Unix()
		claim, e := s.Store.DB.ExecContext(ctx, s.Store.SQL("UPDATE guest_authorizations SET activation_attempts=activation_attempts+1,activation_next=? WHERE id=? AND activation_attempts=? AND activation_next<=? AND activation_state IN ('pending','awaiting_accounting')"), now+30, j.id, j.attempts, now)
		if e != nil {
			return e
		}
		n, e := claim.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			continue
		}
		bound, e := s.Store.GuestAccessPolicy(ctx, g.NAS, g.MAC, g.DomainID, g.Method)
		if e != nil || store.GuestPolicyHash(bound) != g.PolicyHash {
			continue
		}
		callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		handled, err := s.Activate(callCtx, g, bound.VLAN)
		cancel()
		state, code := "awaiting_accounting", ""
		if err != nil {
			state, code = "pending", "nas_activation_failed"
		} else if !handled {
			state = "manual"
		}
		if e = s.Store.Exec(ctx, "UPDATE guest_authorizations SET activation_state=?,activation_error=?,activation_next=? WHERE id=?", state, code, time.Now().Unix()+int64(10*(j.attempts+1)), j.id); e != nil {
			return e
		}
		// Never write management errors, commands or credentials into the audit.
		if err != nil {
			_ = s.Store.Audit(ctx, "guest-activation", g.Identity, "retry", code+" NAS "+g.NAS)
		}
	}
	return nil
}
