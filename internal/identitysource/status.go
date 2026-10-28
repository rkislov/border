package identitysource

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"github.com/rkislov/border/internal/directory"
	"net/url"
	"strings"
	"time"
)

func (s *Service) AccountEnabled(ctx context.Context, user string) (enabledResult bool, resultErr error) {
	started := time.Now()
	defer func() { s.Store.Metrics.Finish("identity_status", started, resultErr) }()
	source, login, qualified := strings.Cut(user, "/")
	if !qualified {
		if l, ok := s.Legacy.(*directory.LDAP); ok {
			return l.AccountEnabled(ctx, user)
		}
		return false, fmt.Errorf("no account status provider")
	}
	if source == "local" {
		var enabled int
		err := s.Store.Row(ctx, "SELECT enabled FROM local_users WHERE username=?", login).Scan(&enabled)
		if err == sql.ErrNoRows {
			return false, nil
		}
		return enabled == 1, err
	}
	d, err := s.Domain(ctx, source)
	if err != nil {
		return false, err
	}
	if !d.Enabled {
		return false, nil
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if d.CAPEM != "" && !roots.AppendCertsFromPEM([]byte(d.CAPEM)) {
		return false, fmt.Errorf("invalid directory CA")
	}
	missing := 0
	for _, endpoint := range d.Endpoints {
		u, e := url.Parse(endpoint)
		if e != nil {
			return false, e
		}
		l := directory.LDAP{URL: endpoint, BaseDN: d.BaseDN, BindDN: d.BindDN, BindPassword: d.BindPassword, UserAttribute: d.UserAttribute, TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: u.Hostname()}}
		enabled, e := l.AccountEnabled(ctx, login)
		if e == nil {
			return enabled, nil
		}
		if errors.Is(e, directory.ErrAccountNotFound) {
			missing++
		}
		err = e
		if ctx.Err() != nil {
			break
		}
	}
	return missingAccountResult(d.RevokeMissingUsers, missing, len(d.Endpoints), err)
}

func missingAccountResult(revoke bool, missing, total int, err error) (bool, error) {
	if revoke && total > 0 && missing == total {
		return false, nil
	}
	if err == nil {
		err = fmt.Errorf("account status unavailable")
	}
	return false, err
}

// SyncAccountStatus uses a persisted per-identity interval; outages leave last
// known state intact and are retried, without generating false block events.
func (s *Service) SyncAccountStatus(ctx context.Context) error {
	if s == nil {
		return nil
	}
	rows, err := s.Store.DB.QueryContext(ctx, s.Store.SQL(`SELECT username FROM (SELECT username FROM identities UNION SELECT username FROM access_grants) u WHERE NOT EXISTS(SELECT 1 FROM identity_status st WHERE st.username=u.username AND st.checked_at>?) ORDER BY username LIMIT 100`), time.Now().Unix()-60)
	if err != nil {
		return err
	}
	users := []string{}
	for rows.Next() {
		var user string
		if err = rows.Scan(&user); err != nil {
			rows.Close()
			return err
		}
		users = append(users, user)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, user := range users {
		enabled, e := s.AccountEnabled(ctx, user)
		if e != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err = s.Store.Exec(ctx, "INSERT INTO identity_status(username,blocked,checked_at) VALUES(?,0,?) ON CONFLICT(username) DO UPDATE SET checked_at=excluded.checked_at", user, time.Now().Unix()); err != nil {
				return err
			}
			continue
		}
		blocked := 0
		if !enabled {
			blocked = 1
		}
		if err = s.Store.Exec(ctx, "INSERT INTO identity_status(username,blocked,checked_at) VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET blocked=excluded.blocked,checked_at=excluded.checked_at", user, blocked, time.Now().Unix()); err != nil {
			return err
		}
		if !enabled {
			if err = s.Store.RevokeIdentity(ctx, user); err != nil {
				return err
			}
		}
	}
	return nil
}
