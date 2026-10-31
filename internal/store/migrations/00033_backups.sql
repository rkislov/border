-- +goose Up
CREATE TABLE backup_control(id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL DEFAULT 0,at_time TEXT NOT NULL DEFAULT '03:30',timezone TEXT NOT NULL DEFAULT 'Europe/Moscow',keep_count INTEGER NOT NULL DEFAULT 14,updated_at BIGINT NOT NULL DEFAULT 0,worker_seen BIGINT NOT NULL DEFAULT 0);
INSERT INTO backup_control(id) VALUES(1);
CREATE TABLE backup_jobs(id TEXT PRIMARY KEY,kind TEXT NOT NULL,source_id TEXT NOT NULL DEFAULT '',request_key TEXT NOT NULL UNIQUE,actor TEXT NOT NULL,state TEXT NOT NULL,created_at BIGINT NOT NULL,started_at BIGINT NOT NULL DEFAULT 0,finished_at BIGINT NOT NULL DEFAULT 0,report TEXT NOT NULL DEFAULT '{}',error_code TEXT NOT NULL DEFAULT '',verification_state TEXT NOT NULL DEFAULT '',verified_at BIGINT NOT NULL DEFAULT 0);
CREATE INDEX backup_jobs_queue ON backup_jobs(state,created_at);
-- +goose Down
DROP TABLE backup_jobs;
DROP TABLE backup_control;
