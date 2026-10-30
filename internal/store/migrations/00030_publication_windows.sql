-- +goose Up
CREATE TABLE publication_window_settings(id INTEGER PRIMARY KEY,revision BIGINT NOT NULL DEFAULT 0,enabled INTEGER NOT NULL DEFAULT 0,timezone TEXT NOT NULL DEFAULT 'Europe/Moscow',max_delay_seconds BIGINT NOT NULL DEFAULT 3600,windows TEXT NOT NULL DEFAULT '[]');
INSERT INTO publication_window_settings(id) VALUES(1);
ALTER TABLE policy_schedules ADD COLUMN expires_at BIGINT NOT NULL DEFAULT 0;
UPDATE policy_schedules SET expires_at=due_at+3600;
-- +goose Down
ALTER TABLE policy_schedules DROP COLUMN expires_at;
DROP TABLE publication_window_settings;
