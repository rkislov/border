-- +goose Up
ALTER TABLE identities ADD COLUMN phone TEXT NOT NULL DEFAULT '';
ALTER TABLE local_users ADD COLUMN phone TEXT NOT NULL DEFAULT '';
CREATE TABLE push_subscriptions (
 endpoint_hash TEXT PRIMARY KEY,
 username TEXT NOT NULL REFERENCES identities(username) ON DELETE CASCADE,
 subscription TEXT NOT NULL,
 key_id TEXT NOT NULL,
 created_at BIGINT NOT NULL
);
CREATE INDEX push_user ON push_subscriptions(username);
-- +goose Down
DROP TABLE push_subscriptions;
ALTER TABLE local_users DROP COLUMN phone;
ALTER TABLE identities DROP COLUMN phone;
