-- +goose Up
ALTER TABLE admins ADD COLUMN mfa_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE admins ADD COLUMN mfa_pending TEXT NOT NULL DEFAULT '';
ALTER TABLE admins ADD COLUMN mfa_pending_until BIGINT NOT NULL DEFAULT 0;
ALTER TABLE admins ADD COLUMN mfa_pending_revision BIGINT NOT NULL DEFAULT 0;
ALTER TABLE admins ADD COLUMN mfa_last_step BIGINT NOT NULL DEFAULT -1;
ALTER TABLE admins ADD COLUMN mfa_failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE admins ADD COLUMN mfa_blocked_until BIGINT NOT NULL DEFAULT 0;
CREATE TABLE admin_recovery_codes(username TEXT NOT NULL REFERENCES admins(username),digest TEXT NOT NULL,created_at BIGINT NOT NULL,used_at BIGINT NOT NULL DEFAULT 0,PRIMARY KEY(username,digest));
CREATE TABLE monitoring_tokens(id TEXT PRIMARY KEY,name TEXT NOT NULL,created_by TEXT NOT NULL REFERENCES admins(username),creator_revision BIGINT NOT NULL,token_hash TEXT NOT NULL,scopes TEXT NOT NULL,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,revoked_at BIGINT NOT NULL DEFAULT 0,last_used_at BIGINT NOT NULL DEFAULT 0);
-- +goose Down
DROP TABLE monitoring_tokens;
DROP TABLE admin_recovery_codes;
ALTER TABLE admins DROP COLUMN mfa_blocked_until;
ALTER TABLE admins DROP COLUMN mfa_failures;
ALTER TABLE admins DROP COLUMN mfa_last_step;
ALTER TABLE admins DROP COLUMN mfa_pending_revision;
ALTER TABLE admins DROP COLUMN mfa_pending_until;
ALTER TABLE admins DROP COLUMN mfa_pending;
ALTER TABLE admins DROP COLUMN mfa_secret;
