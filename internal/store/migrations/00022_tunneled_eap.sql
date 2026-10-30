-- +goose Up
ALTER TABLE authentication_policies ADD COLUMN eap_method TEXT NOT NULL DEFAULT '' CHECK(eap_method IN ('','peap','ttls'));
-- +goose Down
ALTER TABLE authentication_policies DROP COLUMN eap_method;
