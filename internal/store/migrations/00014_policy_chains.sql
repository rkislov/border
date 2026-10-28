-- +goose Up
ALTER TABLE authentication_policies ADD COLUMN steps TEXT NOT NULL DEFAULT '[]';
CREATE TABLE nas_policy_sets(nas TEXT PRIMARY KEY REFERENCES nas(address) ON DELETE CASCADE,version BIGINT NOT NULL,enabled INTEGER NOT NULL,config TEXT NOT NULL);
ALTER TABLE access_grants ADD COLUMN binding_version BIGINT NOT NULL DEFAULT 0;
-- +goose Down
ALTER TABLE access_grants DROP COLUMN binding_version;
DROP TABLE nas_policy_sets;
ALTER TABLE authentication_policies DROP COLUMN steps;
