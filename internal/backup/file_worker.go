// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rkislov/border/internal/store"
)

var fileBackoff = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 3 * time.Hour}

func processFileQueue(ctx context.Context, s *store.Store, c Config, checkMount func(FileDestination) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := enqueueAutomaticFiles(ctx, s, c); e != nil {
		return e
	}
	now := time.Now().Unix()
	// The global OS lock proves no previous worker is still writing these jobs.
	if e := s.Exec(ctx, "UPDATE backup_file_jobs SET state=CASE WHEN attempts>=6 THEN 'failed' ELSE 'retrying' END,error_code='interrupted',next_attempt=?,updated_at=? WHERE state='running'", now+60, now); e != nil {
		return e
	}
	if e := expireDownloads(ctx, s, c, now); e != nil {
		return e
	}
	target := ""
	if c.FileExport != nil {
		target = c.FileExport.target()
	}
	if e := s.Exec(ctx, "UPDATE backup_file_jobs SET state='paused',error_code='target_changed',updated_at=? WHERE state IN ('pending','retrying') AND ((kind='network' AND target<>?) OR (kind='download' AND target<>?))", now, target, DownloadTarget(c.DownloadDir)); e != nil {
		return e
	}
	var enabled int
	if e := s.Row(ctx, "SELECT file_enabled FROM backup_control WHERE id=1").Scan(&enabled); e != nil {
		return e
	}
	j, e := scanFileJob(s.Row(ctx, "SELECT "+fileColumns+" FROM backup_file_jobs WHERE state IN ('pending','retrying') AND next_attempt<=? AND ((kind='download' AND target=?) OR (kind='network' AND target=? AND ?=1)) ORDER BY updated_at,id LIMIT 1", now, DownloadTarget(c.DownloadDir), target, enabled).Scan)
	if e == sql.ErrNoRows {
		return nil
	}
	if e != nil {
		return e
	}
	if e = validFileJob(j); e != nil {
		return e
	}
	res, e := s.DB.ExecContext(ctx, "UPDATE backup_file_jobs SET state='running',attempts=attempts+1,updated_at=? WHERE id=? AND state=?", now, j.ID, j.State)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil || n != 1 {
		return e
	}
	j.State = "running"
	j.Attempts++
	code := "copy_failed"
	terminal := false
	var root *os.Root
	gid := -1
	if j.Kind == "download" {
		root, gid, e = openDownloads(c)
	} else if c.FileExport != nil {
		root, e = openNetwork(*c.FileExport, checkMount)
	} else {
		e = errors.New("destination not configured")
	}
	if e != nil {
		code = "destination_unavailable"
	} else {
		defer root.Close()
		// Clean only this job's abandoned attempts, never another directory.
		for attempt := 1; attempt <= 6; attempt++ {
			old := j
			old.Attempts = attempt
			if e = root.RemoveAll(partialName(old)); e != nil {
				break
			}
		}
		if e == nil {
			var archive Job
			archive, e = scanJob(s.Row(ctx, "SELECT "+jobColumns+" FROM backup_jobs WHERE id=? AND kind='backup' AND state='succeeded' AND verification_state='ok'", j.BackupID).Scan)
			if e != nil {
				code = "source_unavailable"
				terminal = true
			} else {
				name, _ := archiveName(j.BackupID)
				source := filepath.Join(c.OutputDir, name)
				var report Report
				report, e = Verify(ctx, source, c.IdentityFile, c.OutputDir, c.MaxBytes)
				if e != nil {
					code = "archive_invalid"
					terminal = true
				} else if (j.SHA256 != "" && j.SHA256 != report.SHA256) || (archive.Report.SHA256 != "" && archive.Report.SHA256 != report.SHA256) {
					e = errFileIntegrity
					code = "source_changed"
					terminal = true
				} else {
					j.SHA256 = report.SHA256
					j.Bytes = report.Bytes
					res, e = s.DB.ExecContext(ctx, "UPDATE backup_file_jobs SET sha256=?,bytes=? WHERE id=? AND state='running' AND attempts=?", j.SHA256, j.Bytes, j.ID, j.Attempts)
					if e == nil {
						var n int64
						n, e = res.RowsAffected()
						if n != 1 && e == nil {
							return nil
						}
					}
					if e == nil {
						e = copyFileBundle(ctx, root, source, j, gid)
					}
					if e == nil && j.Kind == "network" {
						e = checkMount(*c.FileExport)
					}
					if errors.Is(e, errFileConflict) {
						code = "destination_conflict"
						terminal = true
					} else if errors.Is(e, errFileIntegrity) {
						code = "integrity_failed"
					}
				}
			}
		}
	}
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	state := "succeeded"
	next, verified, expires := int64(0), time.Now().Unix(), int64(0)
	if e != nil {
		state = "retrying"
		verified = 0
		if terminal || j.Attempts >= 6 {
			state = "failed"
		} else {
			next = time.Now().Add(fileBackoff[j.Attempts-1]).Unix()
		}
	} else {
		code = ""
		if j.Kind == "download" {
			expires = verified + 3600
		}
	}
	dbErr := s.Exec(finish, "UPDATE backup_file_jobs SET state=?,error_code=?,next_attempt=?,verified_at=?,expires_at=?,updated_at=? WHERE id=? AND state='running' AND attempts=?", state, code, next, verified, expires, time.Now().Unix(), j.ID, j.Attempts)
	if e != nil {
		return errors.Join(fmt.Errorf("backup file transfer %s: %s", j.ID, code), dbErr)
	}
	if dbErr != nil {
		return dbErr
	}
	var keep int
	if e = s.Row(finish, "SELECT keep_count FROM backup_control WHERE id=1").Scan(&keep); e != nil {
		return e
	}
	return prune(finish, s, c, keep)
}

func expireDownloads(ctx context.Context, s *store.Store, c Config, now int64) error {
	if c.DownloadDir == "" {
		return nil
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT "+fileColumns+" FROM backup_file_jobs WHERE kind='download' AND target=? AND ((state='succeeded' AND expires_at<=?) OR state='cancelled') ORDER BY updated_at,id LIMIT 100", DownloadTarget(c.DownloadDir), now)
	if e != nil {
		return e
	}
	var jobs []FileJob
	for rows.Next() {
		j, e := scanFileJob(rows.Scan)
		if e != nil {
			rows.Close()
			return e
		}
		jobs = append(jobs, j)
	}
	e = errors.Join(rows.Err(), rows.Close())
	if e != nil {
		return e
	}
	if len(jobs) == 0 {
		return nil
	}
	r, _, e := openDownloads(c)
	if e != nil {
		return e
	}
	defer r.Close()
	for _, j := range jobs {
		if e = validFileJob(j); e != nil {
			return e
		}
		if e = r.RemoveAll(j.ID); e != nil {
			return e
		}
		for a := 1; a <= 6; a++ {
			old := j
			old.Attempts = a
			if e = r.RemoveAll(partialName(old)); e != nil {
				return e
			}
		}
		if e = s.Exec(ctx, "UPDATE backup_file_jobs SET state='expired',updated_at=? WHERE id=? AND state IN ('succeeded','cancelled','expired')", now, j.ID); e != nil {
			return e
		}
	}
	return nil
}

func FileJobByID(ctx context.Context, s *store.Store, id string) (FileJob, error) {
	return scanFileJob(s.Row(ctx, "SELECT "+fileColumns+" FROM backup_file_jobs WHERE id=?", id).Scan)
}
