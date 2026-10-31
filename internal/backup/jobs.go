// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	_ "time/tzdata"

	"github.com/google/uuid"
	"github.com/rkislov/border/internal/store"
)

type Schedule struct {
	Enabled  bool
	Time     string
	Timezone string
	Keep     int
}
type Job struct {
	ID, Kind, SourceID, Actor, State, ErrorCode, VerificationState string
	CreatedAt, StartedAt, FinishedAt, VerifiedAt                   int64
	Report                                                         Report
}
type Status struct {
	Supported  bool
	Schedule   Schedule
	WorkerSeen int64
	NextRun    int64
	Jobs       []Job
	Files      FileStatus
}

func (v Schedule) Validate() error {
	if _, e := time.Parse("15:04", v.Time); e != nil || len(v.Time) != 5 {
		return errors.New("выберите время в формате ЧЧ:ММ")
	}
	if _, e := time.LoadLocation(v.Timezone); e != nil || v.Timezone == "" || v.Timezone == "Local" {
		return errors.New("укажите часовой пояс IANA")
	}
	if v.Keep < 2 || v.Keep > 365 {
		return errors.New("хранение: от 2 до 365 проверенных копий")
	}
	return nil
}
func ReadStatus(ctx context.Context, s *store.Store) (Status, error) {
	v := Status{Supported: s.Driver == "sqlite", Jobs: []Job{}}
	var enabled int
	e := s.Row(ctx, "SELECT enabled,at_time,timezone,keep_count,worker_seen FROM backup_control WHERE id=1").Scan(&enabled, &v.Schedule.Time, &v.Schedule.Timezone, &v.Schedule.Keep, &v.WorkerSeen)
	if e != nil {
		return v, e
	}
	v.Schedule.Enabled = enabled != 0
	if e = v.Schedule.Validate(); e != nil {
		return v, e
	}
	v.NextRun = nextRun(v.Schedule, time.Now()).Unix()
	if !v.Schedule.Enabled {
		v.NextRun = 0
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT "+jobColumns+" FROM backup_jobs ORDER BY created_at DESC,id DESC LIMIT 100")
	if e != nil {
		return v, e
	}
	defer rows.Close()
	for rows.Next() {
		j, e := scanJob(rows.Scan)
		if e != nil {
			return v, e
		}
		v.Jobs = append(v.Jobs, j)
	}
	e = errors.Join(rows.Err(), rows.Close())
	if e != nil {
		return v, e
	}
	v.Files, e = ReadFileStatus(ctx, s)
	return v, e
}

func SaveSchedule(ctx context.Context, s *store.Store, v Schedule) error {
	if s.Driver != "sqlite" {
		return errors.New("резервное копирование PostgreSQL этим механизмом пока не поддерживается")
	}
	if e := v.Validate(); e != nil {
		return e
	}
	enabled := 0
	if v.Enabled {
		enabled = 1
	}
	return s.Exec(ctx, "UPDATE backup_control SET enabled=?,at_time=?,timezone=?,keep_count=?,updated_at=? WHERE id=1", enabled, v.Time, v.Timezone, v.Keep, time.Now().Unix())
}

func dueToday(v Schedule, now time.Time) time.Time {
	loc, _ := time.LoadLocation(v.Timezone)
	local := now.In(loc)
	clock, _ := time.Parse("15:04", v.Time)
	return time.Date(local.Year(), local.Month(), local.Day(), clock.Hour(), clock.Minute(), 0, 0, loc)
}
func nextRun(v Schedule, now time.Time) time.Time {
	d := dueToday(v, now)
	if !d.After(now) {
		d = dueToday(v, now.In(d.Location()).AddDate(0, 0, 1))
	}
	return d
}

const jobColumns = "id,kind,source_id,actor,state,created_at,started_at,finished_at,report,error_code,verification_state,verified_at"

func scanJob(scan func(...any) error) (Job, error) {
	var j Job
	var raw string
	e := scan(&j.ID, &j.Kind, &j.SourceID, &j.Actor, &j.State, &j.CreatedAt, &j.StartedAt, &j.FinishedAt, &raw, &j.ErrorCode, &j.VerificationState, &j.VerifiedAt)
	if e == nil {
		e = json.Unmarshal([]byte(raw), &j.Report)
	}
	return j, e
}

func Request(ctx context.Context, s *store.Store, kind, source, key, actor string) (string, error) {
	if s.Driver != "sqlite" {
		return "", errors.New("поддерживается только SQLite")
	}
	if kind != "backup" && kind != "verify" {
		return "", errors.New("неизвестная операция")
	}
	if _, e := uuid.Parse(key); e != nil {
		return "", errors.New("нужен идентификатор запроса")
	}
	if kind == "backup" {
		source = ""
	} else if _, e := uuid.Parse(source); e != nil {
		return "", errors.New("неверный ID копии")
	}
	return enqueue(ctx, s, kind, source, "manual:"+key, actor, time.Now().Unix())
}

func enqueue(ctx context.Context, s *store.Store, kind, source, key, actor string, now int64) (string, error) {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	// Serialize queue producers across the HTTP server and timer (SQLite deferred transactions).
	if _, e = tx.ExecContext(ctx, "UPDATE backup_control SET id=id WHERE id=1"); e != nil {
		return "", e
	}
	var id string
	e = tx.QueryRowContext(ctx, "SELECT id FROM backup_jobs WHERE request_key=?", key).Scan(&id)
	if e == nil {
		return id, nil
	}
	if e != sql.ErrNoRows {
		return "", e
	}
	if kind == "verify" {
		var n int
		e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM backup_jobs WHERE id=? AND kind='backup' AND state='succeeded'", source).Scan(&n)
		if e != nil {
			return "", e
		}
		if n != 1 {
			return "", errors.New("копия не найдена или уже удалена по сроку хранения")
		}
	}
	e = tx.QueryRowContext(ctx, "SELECT id FROM backup_jobs WHERE kind=? AND source_id=? AND state IN ('pending','running') LIMIT 1", kind, source).Scan(&id)
	if e == nil {
		return id, nil
	}
	if e != sql.ErrNoRows {
		return "", e
	}
	var pending int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM backup_jobs WHERE state='pending'").Scan(&pending); e != nil {
		return "", e
	}
	if pending >= 10 {
		return "", errors.New("очередь резервного копирования заполнена")
	}
	id = uuid.NewString()
	_, e = tx.ExecContext(ctx, "INSERT INTO backup_jobs(id,kind,source_id,request_key,actor,state,created_at) VALUES(?,?,?,?,?,'pending',?)", id, kind, source, key, actor, now)
	if e != nil {
		return "", e
	}
	return id, tx.Commit()
}

func scheduleDue(ctx context.Context, s *store.Store, v Schedule, now time.Time) error {
	if !v.Enabled {
		return nil
	}
	if e := v.Validate(); e != nil {
		return e
	}
	due := dueToday(v, now)
	// One run per civil date, at most six hours late. No backlog after a prolonged outage.
	if due.After(now) || now.Sub(due) > 6*time.Hour || due.Format("15:04") != v.Time {
		return nil
	}
	_, e := enqueue(ctx, s, "backup", "", "daily:"+due.Format("2006-01-02"), "schedule", now.Unix())
	return e
}

func archiveName(id string) (string, error) {
	if _, e := uuid.Parse(id); e != nil || len(id) != 36 {
		return "", fmt.Errorf("invalid backup ID")
	}
	return "backup-" + id + ".tar.gz.age", nil
}
