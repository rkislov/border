-- +goose Up
ALTER TABLE sessions ADD COLUMN grant_token TEXT NOT NULL DEFAULT '';
CREATE TABLE access_grants(token TEXT PRIMARY KEY,nas TEXT NOT NULL,username TEXT NOT NULL,policy_id TEXT NOT NULL,expires_at BIGINT NOT NULL,reason TEXT NOT NULL DEFAULT '',attempts INTEGER NOT NULL DEFAULT 0,next_attempt BIGINT NOT NULL DEFAULT 0);
CREATE INDEX access_grants_expiry ON access_grants(expires_at);
CREATE TABLE identity_status(username TEXT PRIMARY KEY,blocked INTEGER NOT NULL,checked_at BIGINT NOT NULL);
-- +goose Down
DROP TABLE identity_status;
DROP TABLE access_grants;
ALTER TABLE sessions DROP COLUMN grant_token;
