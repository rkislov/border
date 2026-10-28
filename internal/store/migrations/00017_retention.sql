-- +goose Up
CREATE TABLE session_tombstones (
 nas TEXT NOT NULL,
 session_id TEXT NOT NULL,
 event_at BIGINT NOT NULL,
 grant_token TEXT NOT NULL,
 generation TEXT NOT NULL,
 PRIMARY KEY(nas,session_id)
);
CREATE INDEX sessions_retention ON sessions(status,updated_at);
-- +goose Down
DROP INDEX sessions_retention;
DROP TABLE session_tombstones;
