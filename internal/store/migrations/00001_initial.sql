-- +goose Up
CREATE TABLE admins (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL);
CREATE TABLE nas (address TEXT PRIMARY KEY, name TEXT NOT NULL, secret TEXT NOT NULL);
CREATE TABLE vlan_catalog (id INTEGER PRIMARY KEY CHECK (id BETWEEN 1 AND 4094), name TEXT NOT NULL);
CREATE TABLE mac_auth (mac TEXT PRIMARY KEY, vlan INTEGER REFERENCES vlan_catalog(id), active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), voice INTEGER NOT NULL DEFAULT 0 CHECK(voice IN (0,1)), comment TEXT NOT NULL DEFAULT '');
CREATE TABLE settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO settings(name,value) VALUES ('isolation_vlan','0');
CREATE TABLE auth_log (id TEXT PRIMARY KEY, occurred_at BIGINT NOT NULL, source TEXT NOT NULL, identity TEXT NOT NULL, result TEXT NOT NULL, reason TEXT NOT NULL);
CREATE INDEX auth_log_time ON auth_log(occurred_at);
CREATE TABLE sessions (nas TEXT NOT NULL, session_id TEXT NOT NULL, mac TEXT NOT NULL, username TEXT NOT NULL, status TEXT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY(nas,session_id));
-- +goose Down
DROP TABLE sessions;
DROP TABLE auth_log;
DROP TABLE settings;
DROP TABLE mac_auth;
DROP TABLE vlan_catalog;
DROP TABLE nas;
DROP TABLE admins;
