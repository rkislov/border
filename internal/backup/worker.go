// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/rkislov/border/internal/store"
	"golang.org/x/sys/unix"
)

// Process is called by a systemd oneshot. The OS lock is released even on SIGKILL.
// Sources/identity/destination come ONLY from the host-owned configuration.
func Process(ctx context.Context, c Config, runNow bool) (job *Job, err error) {
	if err = c.Validate(); err != nil {
		return nil, err
	}
	if err = privateDir(c.OutputDir); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(c.OutputDir, ".worker.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("backup worker is already running")
		}
		return nil, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	// No previous worker can still be using these private staging directories.
	if err = cleanStaging(c.OutputDir); err != nil {
		return nil, err
	}
	f, err := regularFile(c.RootDB)
	if err != nil {
		return nil, err
	}
	f.Close()
	u := url.URL{Scheme: "file", Path: c.RootDB}
	q := u.Query()
	q.Set("mode", "rw")
	q.Add("_pragma", "trusted_schema(OFF)")
	u.RawQuery = q.Encode()
	s, err := store.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	defer s.DB.Close()
	if err = controlOwnership(c.RootDB); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if err = s.Exec(ctx, "UPDATE backup_control SET worker_seen=? WHERE id=1", now); err != nil {
		return nil, err
	}
	if err = recoverInterrupted(ctx, s, c); err != nil {
		return nil, err
	}
	if err = s.Exec(ctx, "UPDATE backup_jobs SET state='failed',error_code='expired',finished_at=? WHERE state='pending' AND created_at<?", now, now-6*3600); err != nil {
		return nil, err
	}
	status, err := ReadStatus(ctx, s)
	if err != nil {
		return nil, err
	}
	if err = finishPruning(ctx, s, c); err != nil {
		return nil, err
	}
	var requested string
	if runNow {
		requested, err = enqueue(ctx, s, "backup", "", "manual:"+uuid.NewString(), "cli", now)
	} else {
		err = scheduleDue(ctx, s, status.Schedule, time.Unix(now, 0))
	}
	if err != nil {
		return nil, err
	}
	query := "SELECT " + jobColumns + " FROM backup_jobs WHERE state='pending' ORDER BY created_at,id LIMIT 1"
	var args []any
	if requested != "" {
		query = "SELECT " + jobColumns + " FROM backup_jobs WHERE id=? AND state='pending'"
		args = []any{requested}
	}
	j, err := scanJob(s.Row(ctx, query, args...).Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err = s.Exec(ctx, "UPDATE backup_jobs SET state='running',started_at=? WHERE id=? AND state='pending'", now, j.ID); err != nil {
		return nil, err
	}
	j.State = "running"
	j.StartedAt = now
	var report Report
	if j.Kind == "backup" {
		var name string
		name, err = archiveName(j.ID)
		if err == nil {
			report, err = Create(ctx, c, filepath.Join(c.OutputDir, name))
		}
	} else if j.Kind == "verify" {
		var name string
		name, err = archiveName(j.SourceID)
		if err == nil {
			report, err = Verify(ctx, filepath.Join(c.OutputDir, name), c.IdentityFile, c.OutputDir, c.MaxBytes)
		}
	} else {
		err = errors.New("unknown backup job kind")
	}
	// Persist outcome even if the operation deadline has elapsed.
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	j.FinishedAt = time.Now().Unix()
	j.Report = report
	j.State = "succeeded"
	if err != nil {
		j.State = "failed"
		j.ErrorCode = "backup_failed"
		if j.Kind == "verify" {
			j.ErrorCode = "verification_failed"
		}
	}
	raw, _ := json.Marshal(report)
	verification := "ok"
	verifiedAt := report.VerifiedAt
	if err != nil {
		verification = "failed"
		verifiedAt = 0
	}
	j.VerificationState = verification
	j.VerifiedAt = verifiedAt
	dbErr := s.Exec(finish, "UPDATE backup_jobs SET state=?,finished_at=?,report=?,error_code=?,verification_state=?,verified_at=? WHERE id=?", j.State, j.FinishedAt, string(raw), j.ErrorCode, verification, verifiedAt, j.ID)
	if j.Kind == "verify" {
		dbErr = errors.Join(dbErr, s.Exec(finish, "UPDATE backup_jobs SET verification_state=?,verified_at=? WHERE id=? AND kind='backup'", verification, verifiedAt, j.SourceID))
	}
	if err == nil && dbErr == nil && j.Kind == "backup" {
		var keep int
		dbErr = s.Row(finish, "SELECT keep_count FROM backup_control WHERE id=1").Scan(&keep)
		if dbErr == nil {
			dbErr = prune(finish, s, c, keep)
		}
	}
	return &j, errors.Join(err, dbErr)
}

func recoverInterrupted(ctx context.Context, s *store.Store, c Config) error {
	rows, e := s.DB.QueryContext(ctx, "SELECT id,kind FROM backup_jobs WHERE state='running'")
	if e != nil {
		return e
	}
	var jobs [][2]string
	for rows.Next() {
		var j [2]string
		if e = rows.Scan(&j[0], &j[1]); e != nil {
			rows.Close()
			return e
		}
		jobs = append(jobs, j)
	}
	e = errors.Join(rows.Err(), rows.Close())
	if e != nil {
		return e
	}
	for _, j := range jobs {
		// The process may have died after atomic archive promotion but before the DB commit.
		name, valid := archiveName(j[0])
		if j[1] == "backup" && valid == nil {
			p := filepath.Join(c.OutputDir, name)
			if _, exists := os.Lstat(p); exists == nil {
				r, verified := Verify(ctx, p, c.IdentityFile, c.OutputDir, c.MaxBytes)
				if verified == nil {
					raw, _ := json.Marshal(r)
					if e = s.Exec(ctx, "UPDATE backup_jobs SET state='succeeded',finished_at=?,report=?,error_code='',verification_state='ok',verified_at=? WHERE id=?", time.Now().Unix(), string(raw), r.VerifiedAt, j[0]); e != nil {
						return e
					}
					continue
				}
			}
		}
		if e = s.Exec(ctx, "UPDATE backup_jobs SET state='failed',error_code='interrupted',finished_at=? WHERE id=?", time.Now().Unix(), j[0]); e != nil {
			return e
		}
	}
	return nil
}

func cleanStaging(dir string) error {
	entries, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	for _, d := range entries {
		n := d.Name()
		if strings.HasPrefix(n, ".capture-") || strings.HasPrefix(n, ".verify-") {
			if d.Type()&os.ModeSymlink != 0 || !d.IsDir() {
				return errors.New("unsafe staging entry")
			}
			if e = os.RemoveAll(filepath.Join(dir, n)); e != nil {
				return e
			}
		} else if strings.HasPrefix(n, "backup-") && strings.HasSuffix(n, ".tar.gz.age.partial") {
			id := strings.TrimSuffix(strings.TrimPrefix(n, "backup-"), ".tar.gz.age.partial")
			if _, e = archiveName(id); e != nil {
				return e
			}
			if e = os.Remove(filepath.Join(dir, n)); e != nil {
				return e
			}
		}
	}
	return nil
}

// Root's control connection must not leave WAL sidecars inaccessible to the Border user.
func controlOwnership(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	i, e := os.Stat(path)
	if e != nil {
		return e
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("file ownership unavailable")
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		p := path + suffix
		f, e := regularFile(p)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		e = f.Chown(int(st.Uid), int(st.Gid))
		f.Close()
		if e != nil {
			return e
		}
	}
	return nil
}

func prune(ctx context.Context, s *store.Store, c Config, keep int) error {
	if keep < 2 {
		return errors.New("refusing unsafe retention")
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT id FROM backup_jobs WHERE kind='backup' AND state='succeeded' AND verification_state='ok' ORDER BY finished_at DESC,id DESC")
	if e != nil {
		return e
	}
	var old []string
	index := 0
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		if index >= keep {
			old = append(old, id)
		}
		index++
	}
	e = errors.Join(rows.Err(), rows.Close())
	if e != nil {
		return e
	}
	for _, id := range old {
		if e = s.Exec(ctx, "UPDATE backup_jobs SET state='pruning' WHERE id=? AND NOT EXISTS(SELECT 1 FROM backup_jobs q WHERE q.source_id=? AND q.state IN ('pending','running'))", id, id); e != nil {
			return e
		}
	}
	return finishPruning(ctx, s, c)
}
func finishPruning(ctx context.Context, s *store.Store, c Config) error {
	rows, e := s.DB.QueryContext(ctx, "SELECT id FROM backup_jobs WHERE state='pruning' AND kind='backup'")
	if e != nil {
		return e
	}
	var ids []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	e = errors.Join(rows.Err(), rows.Close())
	if e != nil {
		return e
	}
	for _, id := range ids {
		name, e := archiveName(id)
		if e != nil {
			return e
		}
		e = os.Remove(filepath.Join(c.OutputDir, name))
		if e != nil && !os.IsNotExist(e) {
			return fmt.Errorf("backup retention: %w", e)
		}
		if e = s.Exec(ctx, "UPDATE backup_jobs SET state='pruned' WHERE id=?", id); e != nil {
			return e
		}
	}
	return syncDir(c.OutputDir)
}
