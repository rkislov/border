-- +goose Up
ALTER TABLE access_grants ADD COLUMN accounting_key TEXT NOT NULL DEFAULT '';
ALTER TABLE access_grants ADD COLUMN issued_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE access_grants ADD COLUMN accounting_session TEXT NOT NULL DEFAULT '';
ALTER TABLE access_grants ADD COLUMN accounting_started BIGINT NOT NULL DEFAULT 0;
CREATE INDEX access_grants_accounting ON access_grants(nas,accounting_key,issued_at);
-- +goose Down
DROP INDEX access_grants_accounting;
ALTER TABLE access_grants DROP COLUMN accounting_started;
ALTER TABLE access_grants DROP COLUMN accounting_session;
ALTER TABLE access_grants DROP COLUMN issued_at;
ALTER TABLE access_grants DROP COLUMN accounting_key;
