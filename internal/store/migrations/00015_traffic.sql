-- +goose Up
ALTER TABLE sessions ADD COLUMN input_bytes TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN output_bytes TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN input_gigawords INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN output_gigawords INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN traffic_warning TEXT NOT NULL DEFAULT '';
-- +goose Down
ALTER TABLE sessions DROP COLUMN traffic_warning;
ALTER TABLE sessions DROP COLUMN output_gigawords;
ALTER TABLE sessions DROP COLUMN input_gigawords;
ALTER TABLE sessions DROP COLUMN output_bytes;
ALTER TABLE sessions DROP COLUMN input_bytes;
