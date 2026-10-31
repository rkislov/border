-- +goose Up
ALTER TABLE backup_control ADD COLUMN download_target TEXT NOT NULL DEFAULT '';
ALTER TABLE backup_control ADD COLUMN file_target TEXT NOT NULL DEFAULT '';
ALTER TABLE backup_control ADD COLUMN file_label TEXT NOT NULL DEFAULT '';
ALTER TABLE backup_control ADD COLUMN file_enabled INTEGER NOT NULL DEFAULT 0;
CREATE TABLE backup_file_jobs(id TEXT PRIMARY KEY,backup_id TEXT NOT NULL REFERENCES backup_jobs(id),kind TEXT NOT NULL,target TEXT NOT NULL,actor TEXT NOT NULL,state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL,next_attempt BIGINT NOT NULL DEFAULT 0,verified_at BIGINT NOT NULL DEFAULT 0,expires_at BIGINT NOT NULL DEFAULT 0,sha256 TEXT NOT NULL DEFAULT '',bytes BIGINT NOT NULL DEFAULT 0,error_code TEXT NOT NULL DEFAULT '',UNIQUE(backup_id,kind,target));
CREATE INDEX backup_files_queue ON backup_file_jobs(state,next_attempt);
-- +goose Down
DROP TABLE backup_file_jobs;
ALTER TABLE backup_control DROP COLUMN file_enabled;
ALTER TABLE backup_control DROP COLUMN file_label;
ALTER TABLE backup_control DROP COLUMN file_target;
ALTER TABLE backup_control DROP COLUMN download_target;
