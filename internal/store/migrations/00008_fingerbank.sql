-- +goose Up
CREATE TABLE fingerprint_cache (cache_key TEXT PRIMARY KEY,result TEXT NOT NULL,updated_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,retry_at BIGINT NOT NULL);
-- +goose Down
DROP TABLE fingerprint_cache;
