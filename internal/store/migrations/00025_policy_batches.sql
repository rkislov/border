-- +goose Up
ALTER TABLE policy_releases ADD COLUMN batch_id TEXT NOT NULL DEFAULT '';
CREATE INDEX policy_releases_batch ON policy_releases(batch_id);
-- +goose Down
DROP INDEX policy_releases_batch;
ALTER TABLE policy_releases DROP COLUMN batch_id;
