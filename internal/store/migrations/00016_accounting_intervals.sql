-- +goose Up
ALTER TABLE nas ADD COLUMN interim_seconds INTEGER NOT NULL DEFAULT 300 CHECK(interim_seconds BETWEEN 60 AND 86400);
ALTER TABLE nas ADD COLUMN stale_seconds INTEGER NOT NULL DEFAULT 900 CHECK(stale_seconds BETWEEN 180 AND 604800 AND stale_seconds >= interim_seconds * 3);
-- +goose Down
ALTER TABLE nas DROP COLUMN stale_seconds;
ALTER TABLE nas DROP COLUMN interim_seconds;
