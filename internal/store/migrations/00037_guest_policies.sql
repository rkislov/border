-- +goose Up
ALTER TABLE authentication_policies RENAME COLUMN source TO previous_source;
ALTER TABLE authentication_policies ADD COLUMN source TEXT NOT NULL DEFAULT 'local' CHECK(source IN ('local','directory','codes','mab','eap_tls','oidc','guest'));
UPDATE authentication_policies SET source=previous_source;
ALTER TABLE authentication_policies DROP COLUMN previous_source;
ALTER TABLE authentication_policies ADD COLUMN guest_methods TEXT NOT NULL DEFAULT '[]';

ALTER TABLE guest_oidc_sessions RENAME TO guest_authorizations;
ALTER TABLE guest_authorizations ADD COLUMN method TEXT NOT NULL DEFAULT 'oidc' CHECK(method IN ('sms','email','oidc'));
ALTER TABLE guest_authorizations ADD COLUMN masked_contact TEXT NOT NULL DEFAULT '';
ALTER TABLE access_grants RENAME COLUMN guest_oidc_id TO guest_authorization_id;
DROP INDEX access_grants_guest_oidc;
CREATE INDEX access_grants_guest_authorization ON access_grants(guest_authorization_id);

ALTER TABLE guest_policy ADD COLUMN generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE guest_challenges ADD COLUMN channel TEXT NOT NULL DEFAULT '';
ALTER TABLE guest_challenges ADD COLUMN domain_id TEXT NOT NULL DEFAULT '';
ALTER TABLE guest_challenges ADD COLUMN policy_id TEXT NOT NULL DEFAULT '';
ALTER TABLE guest_challenges ADD COLUMN policy_hash TEXT NOT NULL DEFAULT '';
-- Legacy codes/grants have no trustworthy policy or identity binding. They
-- must be renewed under an explicitly published guest policy, never upgraded
-- into a more permissive policy automatically. Existing OIDC IDs survive.
UPDATE guest_challenges SET code_digest='',expires_at=0 WHERE verified_at=0;
UPDATE access_grants SET reason='legacy guest authorization retired',next_attempt=0 WHERE reason='' AND policy_id='' AND EXISTS(SELECT 1 FROM guest_sessions g WHERE g.nas=access_grants.nas AND g.mac=access_grants.username);
DELETE FROM guest_sessions;

-- +goose Down
-- Remove policies using source=guest before downgrade. Runtime grants and
-- challenges for SMS/email must never become legacy VLAN-only permissions.
UPDATE access_grants SET reason='guest policy downgrade',next_attempt=0 WHERE reason='' AND guest_authorization_id IN (SELECT id FROM guest_authorizations WHERE method<>'oidc');
DELETE FROM guest_authorizations WHERE method<>'oidc';
UPDATE guest_challenges SET code_digest='',expires_at=0 WHERE verified_at=0;
ALTER TABLE guest_challenges DROP COLUMN policy_hash;
ALTER TABLE guest_challenges DROP COLUMN policy_id;
ALTER TABLE guest_challenges DROP COLUMN domain_id;
ALTER TABLE guest_challenges DROP COLUMN channel;
ALTER TABLE guest_policy DROP COLUMN generation;
DROP INDEX access_grants_guest_authorization;
ALTER TABLE access_grants RENAME COLUMN guest_authorization_id TO guest_oidc_id;
CREATE INDEX access_grants_guest_oidc ON access_grants(guest_oidc_id);
ALTER TABLE guest_authorizations DROP COLUMN masked_contact;
ALTER TABLE guest_authorizations DROP COLUMN method;
ALTER TABLE guest_authorizations RENAME TO guest_oidc_sessions;
ALTER TABLE authentication_policies DROP COLUMN guest_methods;
ALTER TABLE authentication_policies RENAME COLUMN source TO previous_source;
ALTER TABLE authentication_policies ADD COLUMN source TEXT NOT NULL DEFAULT 'local' CHECK(source IN ('local','directory','codes','mab','eap_tls','oidc'));
UPDATE authentication_policies SET source=previous_source;
ALTER TABLE authentication_policies DROP COLUMN previous_source;
