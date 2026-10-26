-- +goose Up
ALTER TABLE nas ADD COLUMN portal_enabled INTEGER NOT NULL DEFAULT 0 CHECK(portal_enabled IN (0,1));
CREATE TABLE guest_policy (id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),vlan INTEGER REFERENCES vlan_catalog(id),session_seconds INTEGER NOT NULL DEFAULT 3600 CHECK(session_seconds BETWEEN 300 AND 86400),max_per_hour INTEGER NOT NULL DEFAULT 1000 CHECK(max_per_hour BETWEEN 1 AND 100000));
INSERT INTO guest_policy(id) VALUES (1);
CREATE TABLE guest_challenges (id TEXT PRIMARY KEY,nas TEXT NOT NULL REFERENCES nas(address) ON DELETE CASCADE,mac TEXT NOT NULL,session_id TEXT NOT NULL,phone_hash TEXT NOT NULL,phone_cipher TEXT NOT NULL,code_digest TEXT NOT NULL,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,verified_at BIGINT NOT NULL DEFAULT 0);
CREATE INDEX guest_phone_rate ON guest_challenges(phone_hash,created_at);
CREATE INDEX guest_device_rate ON guest_challenges(nas,mac,created_at);
CREATE INDEX guest_challenge_created ON guest_challenges(created_at);
CREATE TABLE guest_sessions (nas TEXT NOT NULL REFERENCES nas(address) ON DELETE CASCADE,mac TEXT NOT NULL,masked_phone TEXT NOT NULL,vlan INTEGER NOT NULL REFERENCES vlan_catalog(id),expires_at BIGINT NOT NULL,PRIMARY KEY(nas,mac));
CREATE INDEX guest_sessions_expiry ON guest_sessions(expires_at);
-- +goose Down
DROP TABLE guest_sessions;
DROP TABLE guest_challenges;
DROP TABLE guest_policy;
ALTER TABLE nas DROP COLUMN portal_enabled;
