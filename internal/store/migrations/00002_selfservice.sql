-- +goose Up
CREATE TABLE identities (username TEXT PRIMARY KEY, email TEXT NOT NULL, totp_secret TEXT NOT NULL DEFAULT '', pending_secret TEXT NOT NULL DEFAULT '', last_step BIGINT NOT NULL DEFAULT -1, last_email BIGINT NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0);
CREATE TABLE user_codes (digest TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES identities(username), kind TEXT NOT NULL, expires_at BIGINT NOT NULL);
CREATE INDEX user_codes_owner ON user_codes(username,kind);
CREATE TABLE certificate_authorities (id TEXT PRIMARY KEY, name TEXT NOT NULL, certificate TEXT NOT NULL, private_key TEXT NOT NULL, created_at BIGINT NOT NULL);
CREATE TABLE certificates (serial TEXT PRIMARY KEY, ca_id TEXT NOT NULL REFERENCES certificate_authorities(id), owner TEXT NOT NULL, certificate TEXT NOT NULL, expires_at BIGINT NOT NULL, revoked_at BIGINT NOT NULL DEFAULT 0);
CREATE INDEX certificates_owner ON certificates(owner);
-- +goose Down
DROP TABLE certificates;
DROP TABLE certificate_authorities;
DROP TABLE user_codes;
DROP TABLE identities;
