-- +goose Up
INSERT INTO settings(name,value) VALUES ('eap_enabled','0');
INSERT INTO settings(name,value) VALUES ('eap_vlan','0');
-- +goose Down
DELETE FROM settings WHERE name IN ('eap_enabled','eap_vlan');
