-- +goose Up
CREATE TABLE device_fingerprints(mac TEXT PRIMARY KEY,nas TEXT NOT NULL DEFAULT '',dhcp_options TEXT NOT NULL DEFAULT '',vendor_class TEXT NOT NULL DEFAULT '',hostname TEXT NOT NULL DEFAULT '',os TEXT NOT NULL DEFAULT '',manufacturer TEXT NOT NULL DEFAULT '',device_type TEXT NOT NULL DEFAULT '',source TEXT NOT NULL,first_seen BIGINT NOT NULL,last_seen BIGINT NOT NULL);
CREATE TABLE fingerprint_history(id TEXT PRIMARY KEY,mac TEXT NOT NULL REFERENCES device_fingerprints(mac) ON DELETE CASCADE,observed_at BIGINT NOT NULL,source TEXT NOT NULL,detail TEXT NOT NULL);
CREATE INDEX fingerprint_history_mac ON fingerprint_history(mac,observed_at);
CREATE TABLE oui_prefixes(prefix TEXT PRIMARY KEY,manufacturer TEXT NOT NULL);
-- +goose Down
DROP TABLE oui_prefixes;
DROP TABLE fingerprint_history;
DROP TABLE device_fingerprints;
