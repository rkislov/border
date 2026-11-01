-- +goose Up
ALTER TABLE guest_authorizations ADD COLUMN activation_state TEXT NOT NULL DEFAULT 'manual';
ALTER TABLE guest_authorizations ADD COLUMN activation_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE guest_authorizations ADD COLUMN activation_next BIGINT NOT NULL DEFAULT 0;
ALTER TABLE guest_authorizations ADD COLUMN activation_error TEXT NOT NULL DEFAULT '';
CREATE INDEX guest_activation_due ON guest_authorizations(activation_state,activation_next);
-- +goose Down
DROP INDEX guest_activation_due;
ALTER TABLE guest_authorizations DROP COLUMN activation_error;
ALTER TABLE guest_authorizations DROP COLUMN activation_next;
ALTER TABLE guest_authorizations DROP COLUMN activation_attempts;
ALTER TABLE guest_authorizations DROP COLUMN activation_state;
