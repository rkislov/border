-- +goose Up
CREATE TABLE local_mschap_credentials(username TEXT PRIMARY KEY REFERENCES local_users(username) ON DELETE CASCADE,encrypted_hash TEXT NOT NULL);
-- +goose Down
DROP TABLE local_mschap_credentials;
