-- +goose Up
-- Replacing only the source column preserves policy IDs and all foreign keys.
ALTER TABLE authentication_policies RENAME COLUMN source TO previous_source;
ALTER TABLE authentication_policies ADD COLUMN source TEXT NOT NULL DEFAULT 'local' CHECK(source IN ('local','directory','codes','mab','eap_tls','oidc'));
UPDATE authentication_policies SET source=previous_source;
ALTER TABLE authentication_policies DROP COLUMN previous_source;
CREATE TABLE guest_oidc_providers(scope TEXT NOT NULL,id TEXT NOT NULL,config TEXT NOT NULL,secret TEXT NOT NULL DEFAULT '',revision TEXT NOT NULL,PRIMARY KEY(scope,id));
CREATE TABLE guest_oidc_sessions(id TEXT PRIMARY KEY,nas TEXT NOT NULL REFERENCES nas(address) ON DELETE CASCADE,mac TEXT NOT NULL,identity TEXT NOT NULL,provider_scope TEXT NOT NULL,provider_id TEXT NOT NULL,provider_revision TEXT NOT NULL,domain_id TEXT NOT NULL DEFAULT '',policy_id TEXT NOT NULL,policy_hash TEXT NOT NULL,expires_at BIGINT NOT NULL,UNIQUE(nas,mac));
ALTER TABLE access_grants ADD COLUMN guest_oidc_id TEXT NOT NULL DEFAULT '';
CREATE INDEX access_grants_guest_oidc ON access_grants(guest_oidc_id);
-- +goose Down
DROP INDEX access_grants_guest_oidc;
ALTER TABLE access_grants DROP COLUMN guest_oidc_id;
DROP TABLE guest_oidc_sessions;
DROP TABLE guest_oidc_providers;
-- OIDC policies must be removed before downgrading.
ALTER TABLE authentication_policies RENAME COLUMN source TO previous_source;
ALTER TABLE authentication_policies ADD COLUMN source TEXT NOT NULL DEFAULT 'local' CHECK(source IN ('local','directory','codes','mab','eap_tls'));
UPDATE authentication_policies SET source=previous_source;
ALTER TABLE authentication_policies DROP COLUMN previous_source;
