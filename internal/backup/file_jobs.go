// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/rkislov/border/internal/store"
)

type FileJob struct {
	ID, BackupID, Kind, Target, Actor, State, ErrorCode, SHA256     string
	Attempts                                                        int
	CreatedAt, UpdatedAt, NextAttempt, VerifiedAt, ExpiresAt, Bytes int64
}
type FileStatus struct {
	DownloadTarget string `json:"-"`
	DownloadsReady bool
	Target, Label  string
	Enabled        bool
	Jobs           []FileJob
}

const fileColumns = "id,backup_id,kind,target,actor,state,attempts,created_at,updated_at,next_attempt,verified_at,expires_at,sha256,bytes,error_code"

func scanFileJob(scan func(...any) error) (FileJob, error) {
	var j FileJob
	e := scan(&j.ID, &j.BackupID, &j.Kind, &j.Target, &j.Actor, &j.State, &j.Attempts, &j.CreatedAt, &j.UpdatedAt, &j.NextAttempt, &j.VerifiedAt, &j.ExpiresAt, &j.SHA256, &j.Bytes, &j.ErrorCode)
	return j, e
}
func ReadFileStatus(ctx context.Context, s *store.Store) (FileStatus, error) {
	v := FileStatus{Jobs: []FileJob{}}
	var enabled int
	e := s.Row(ctx, "SELECT download_target,file_target,file_label,file_enabled FROM backup_control WHERE id=1").Scan(&v.DownloadTarget, &v.Target, &v.Label, &enabled)
	if e != nil {
		return v, e
	}
	v.Enabled = enabled == 1
	rows, e := s.DB.QueryContext(ctx, "SELECT "+fileColumns+" FROM backup_file_jobs ORDER BY created_at DESC,id DESC LIMIT 100")
	if e != nil {
		return v, e
	}
	defer rows.Close()
	for rows.Next() {
		j, e := scanFileJob(rows.Scan)
		if e != nil {
			return v, e
		}
		v.Jobs = append(v.Jobs, j)
	}
	return v, rows.Err()
}

func SaveFileExportEnabled(ctx context.Context, s *store.Store, enabled bool) error {
	if s.Driver != "sqlite" {
		return errors.New("поддерживается только SQLite")
	}
	flag := 0
	if enabled {
		flag = 1
	}
	r, e := s.DB.ExecContext(ctx, "UPDATE backup_control SET file_enabled=? WHERE id=1 AND (?=0 OR file_target<>'')", flag, flag)
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e == nil && n != 1 {
		return errors.New("сначала подключите сетевую папку в конфигурации службы")
	}
	return e
}

func RequestDownload(ctx context.Context, s *store.Store, backupID, dir, actor string) (string, error) {
	if s.Driver != "sqlite" || dir == "" {
		return "", errors.New("скачивание ещё не подключено")
	}
	if _, e := archiveName(backupID); e != nil {
		return "", e
	}
	target := DownloadTarget(dir)
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "UPDATE backup_control SET id=id WHERE id=1"); e != nil {
		return "", e
	}
	var configured string
	if e = tx.QueryRowContext(ctx, "SELECT download_target FROM backup_control WHERE id=1").Scan(&configured); e != nil {
		return "", e
	}
	if configured != target {
		return "", errors.New("каталог скачивания не подтверждён службой")
	}
	var n int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM backup_jobs WHERE id=? AND kind='backup' AND state='succeeded' AND verification_state='ok'", backupID).Scan(&n); e != nil {
		return "", e
	}
	if n != 1 {
		return "", errors.New("нет проверенного локального архива")
	}
	j, e := scanFileJob(tx.QueryRowContext(ctx, "SELECT "+fileColumns+" FROM backup_file_jobs WHERE backup_id=? AND kind='download' AND target=?", backupID, target).Scan)
	now := time.Now().Unix()
	if e == nil {
		if j.State == "pending" || j.State == "running" || j.State == "retrying" || (j.State == "succeeded" && j.ExpiresAt > now) {
			return j.ID, nil
		}
		if e = checkDownloadCapacity(ctx, tx, j.ID, now); e != nil {
			return "", e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE backup_file_jobs SET state='pending',attempts=0,next_attempt=0,expires_at=0,error_code='',actor=?,updated_at=? WHERE id=?", actor, now, j.ID); e != nil {
			return "", e
		}
		return j.ID, tx.Commit()
	}
	if e != sql.ErrNoRows {
		return "", e
	}
	if e = checkDownloadCapacity(ctx, tx, "", now); e != nil {
		return "", e
	}
	id := uuid.NewString()
	_, e = tx.ExecContext(ctx, "INSERT INTO backup_file_jobs(id,backup_id,kind,target,actor,state,created_at,updated_at) VALUES(?,?,'download',?,?,'pending',?,?)", id, backupID, target, actor, now, now)
	if e != nil {
		return "", e
	}
	return id, tx.Commit()
}

func checkDownloadCapacity(ctx context.Context, tx *sql.Tx, except string, now int64) error {
	var n int
	if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM backup_file_jobs WHERE id<>? AND kind='download' AND state IN ('pending','running','retrying','succeeded') AND (expires_at=0 OR expires_at>?)", except, now).Scan(&n); e != nil {
		return e
	}
	if n >= 10 {
		return errors.New("не более 10 подготовленных или ожидающих скачивания архивов")
	}
	return nil
}

func ChangeFileJob(ctx context.Context, s *store.Store, id, action, downloadDir string) error {
	if s.Driver != "sqlite" {
		return errors.New("поддерживается только SQLite")
	}
	if _, e := uuid.Parse(id); e != nil {
		return errors.New("неверный ID")
	}
	if action != "retry" && action != "cancel" {
		return errors.New("неизвестное действие")
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "UPDATE backup_control SET id=id WHERE id=1"); e != nil {
		return e
	}
	j, e := scanFileJob(tx.QueryRowContext(ctx, "SELECT "+fileColumns+" FROM backup_file_jobs WHERE id=?", id).Scan)
	if e != nil {
		return e
	}
	if action == "cancel" {
		if j.State == "succeeded" || j.State == "expired" {
			return errors.New("задание уже завершено")
		}
		_, e = tx.ExecContext(ctx, "UPDATE backup_file_jobs SET state='cancelled',error_code='',updated_at=? WHERE id=?", time.Now().Unix(), id)
	} else {
		if j.State == "running" {
			return errors.New("передача ещё выполняется")
		}
		if j.Kind == "network" && j.State == "succeeded" {
			return errors.New("файл уже доставлен")
		}
		var configured string
		if j.Kind == "network" {
			e = tx.QueryRowContext(ctx, "SELECT file_target FROM backup_control WHERE id=1").Scan(&configured)
		} else {
			configured = DownloadTarget(downloadDir)
		}
		if e != nil {
			return e
		}
		if configured == "" || j.Target != configured {
			return errors.New("назначение изменено; старое задание не перенаправляется")
		}
		if j.Kind == "download" {
			if e = checkDownloadCapacity(ctx, tx, j.ID, time.Now().Unix()); e != nil {
				return e
			}
		}
		var n int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM backup_jobs WHERE id=? AND state='succeeded' AND verification_state='ok'", j.BackupID).Scan(&n); e != nil {
			return e
		}
		if n != 1 {
			return errors.New("локальный архив недоступен")
		}
		_, e = tx.ExecContext(ctx, "UPDATE backup_file_jobs SET state='pending',attempts=0,next_attempt=0,expires_at=0,error_code='',updated_at=? WHERE id=?", time.Now().Unix(), id)
	}
	if e != nil {
		return e
	}
	return tx.Commit()
}

func enqueueAutomaticFiles(ctx context.Context, s *store.Store, c Config) error {
	if c.FileExport == nil {
		return nil
	}
	var enabled int
	var target string
	if e := s.Row(ctx, "SELECT file_enabled,file_target FROM backup_control WHERE id=1").Scan(&enabled, &target); e != nil {
		return e
	}
	if enabled != 1 || target != c.FileExport.target() {
		return nil
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT id FROM backup_jobs WHERE kind='backup' AND state='succeeded' AND verification_state='ok' AND NOT EXISTS(SELECT 1 FROM backup_file_jobs f WHERE f.backup_id=backup_jobs.id AND f.kind='network' AND f.target=?) ORDER BY created_at LIMIT 100", target)
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
		if _, e = archiveName(id); e != nil {
			return e
		}
		now := time.Now().Unix()
		if e = s.Exec(ctx, "INSERT INTO backup_file_jobs(id,backup_id,kind,target,actor,state,created_at,updated_at) VALUES(?,?,'network',?,'schedule','pending',?,?) ON CONFLICT(backup_id,kind,target) DO NOTHING", uuid.NewString(), id, target, now, now); e != nil {
			return e
		}
	}
	return nil
}

// This predicate also protects failed/paused network copies until the operator
// explicitly cancels them. Turning automatic export off must not silently lose data.
const fileRetentionGuard = `NOT EXISTS(SELECT 1 FROM backup_file_jobs f WHERE f.backup_id=backup_jobs.id AND ((f.kind='network' AND f.state NOT IN ('succeeded','cancelled')) OR (f.kind='download' AND f.state IN ('pending','running','retrying'))))
AND NOT EXISTS(SELECT 1 FROM backup_control c WHERE c.id=1 AND c.file_enabled=1 AND c.file_target<>'' AND NOT EXISTS(SELECT 1 FROM backup_file_jobs f WHERE f.backup_id=backup_jobs.id AND f.kind='network' AND f.target=c.file_target AND f.state IN ('succeeded','cancelled')))`
