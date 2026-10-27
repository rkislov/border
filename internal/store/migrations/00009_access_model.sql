-- +goose Up
CREATE TABLE tenant_instances(id TEXT PRIMARY KEY,name TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE locations(id TEXT PRIMARY KEY,name TEXT NOT NULL);
CREATE TABLE network_segments(id TEXT PRIMARY KEY,name TEXT NOT NULL);
CREATE TABLE domains(id TEXT PRIMARY KEY,name TEXT NOT NULL,config TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)));
CREATE TABLE local_users(username TEXT PRIMARY KEY,email TEXT NOT NULL,password_hash TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)));
CREATE TABLE authentication_policies(id TEXT PRIMARY KEY,name TEXT NOT NULL,source TEXT NOT NULL CHECK(source IN ('local','directory','codes','mab','eap_tls')),domain_id TEXT REFERENCES domains(id),require_totp INTEGER NOT NULL DEFAULT 0 CHECK(require_totp IN (0,1)),enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)));
CREATE TABLE access_policies(id TEXT PRIMARY KEY,name TEXT NOT NULL,authentication_id TEXT NOT NULL REFERENCES authentication_policies(id),mode TEXT NOT NULL CHECK(mode IN ('network','ssh','vpn')),segment_id TEXT REFERENCES network_segments(id),valid_from BIGINT NOT NULL DEFAULT 0,valid_until BIGINT NOT NULL DEFAULT 0,session_seconds INTEGER NOT NULL CHECK(session_seconds BETWEEN 60 AND 86400),idle_seconds INTEGER NOT NULL DEFAULT 0 CHECK(idle_seconds BETWEEN 0 AND 86400),privilege INTEGER NOT NULL DEFAULT 0 CHECK(privilege BETWEEN 0 AND 15),group_name TEXT NOT NULL DEFAULT '',role TEXT NOT NULL DEFAULT '',filter_id TEXT NOT NULL DEFAULT '',enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),CHECK(valid_until=0 OR valid_until>valid_from));
CREATE TABLE policy_subjects(policy_id TEXT NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE,identity TEXT NOT NULL,PRIMARY KEY(policy_id,identity));
ALTER TABLE nas ADD COLUMN location_id TEXT REFERENCES locations(id);
ALTER TABLE nas ADD COLUMN access_policy_id TEXT REFERENCES access_policies(id);
CREATE TABLE location_segments(location_id TEXT NOT NULL REFERENCES locations(id),segment_id TEXT NOT NULL REFERENCES network_segments(id),vlan INTEGER NOT NULL CHECK(vlan BETWEEN 1 AND 4094),PRIMARY KEY(location_id,segment_id));
CREATE TABLE nas_segments(nas TEXT NOT NULL REFERENCES nas(address) ON DELETE CASCADE,segment_id TEXT NOT NULL REFERENCES network_segments(id),vlan INTEGER NOT NULL CHECK(vlan BETWEEN 1 AND 4094),PRIMARY KEY(nas,segment_id));
-- +goose Down
DROP TABLE nas_segments;
DROP TABLE location_segments;
ALTER TABLE nas DROP COLUMN access_policy_id;
ALTER TABLE nas DROP COLUMN location_id;
DROP TABLE policy_subjects;
DROP TABLE access_policies;
DROP TABLE authentication_policies;
DROP TABLE local_users;
DROP TABLE domains;
DROP TABLE network_segments;
DROP TABLE locations;
DROP TABLE tenant_instances;
