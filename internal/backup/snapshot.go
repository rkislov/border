// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"time"

	"modernc.org/sqlite"
)

var tenantID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func openDB(path string) (*sql.DB, error) {
	f, err := regularFile(path)
	if err != nil {
		return nil, err
	}
	f.Close()
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("mode", "ro")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "trusted_schema(OFF)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err == nil {
		db.SetMaxOpenConns(1)
	}
	return db, err
}

// Snapshot uses SQLite's online backup API; copying the .db file alone loses WAL commits.
func Snapshot(ctx context.Context, src, dst string) (err error) {
	return snapshot(ctx, src, dst, 1<<40)
}
func snapshot(ctx context.Context, src, dst string, maxBytes int64) (err error) {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	f.Close()
	defer func() {
		if err != nil {
			os.Remove(dst)
		}
	}()
	db, err := openDB(src)
	if err != nil {
		return err
	}
	defer db.Close()
	var pageSize int64
	if err = db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	err = conn.Raw(func(raw any) (err error) {
		c, ok := raw.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("SQLite online backup unavailable")
		}
		u := url.URL{Scheme: "file", Path: dst}
		b, err := c.NewBackup(u.String())
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, b.Finish()) }()
		for {
			if err = ctx.Err(); err != nil {
				return err
			}
			more, e := b.Step(256)
			if int64(b.PageCount())*pageSize > maxBytes {
				return errors.New("database exceeds backup size limit")
			}
			if e != nil {
				var se *sqlite.Error
				if !errors.As(e, &se) || (se.Code()&255 != 5 && se.Code()&255 != 6) {
					return e
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(25 * time.Millisecond):
				}
				continue
			}
			if !more {
				return nil
			}
		}
	})
	if err != nil {
		return err
	}
	f, err = os.OpenFile(dst, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func tenants(ctx context.Context, path string) ([]string, error) {
	db, err := openDB(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, "SELECT id FROM tenant_instances ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		if !tenantID.MatchString(id) || id == "default" {
			return nil, fmt.Errorf("invalid tenant catalog")
		}
		ids = append(ids, id)
		if len(ids) > 64 {
			return nil, errors.New("tenant catalog exceeds supported limit")
		}
	}
	return ids, rows.Err()
}
