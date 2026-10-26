-- +goose Up
ALTER TABLE nas ADD COLUMN dictionary TEXT NOT NULL DEFAULT 'standard';
ALTER TABLE nas ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'network' CHECK(access_mode IN ('network','ssh','vpn'));
ALTER TABLE nas ADD COLUMN credential TEXT NOT NULL DEFAULT 'codes' CHECK(credential IN ('codes','directory'));
CREATE TABLE nas_grants (nas TEXT NOT NULL REFERENCES nas(address) ON DELETE CASCADE, username TEXT NOT NULL, mode TEXT NOT NULL CHECK(mode IN ('ssh','vpn')), role TEXT NOT NULL DEFAULT '', group_name TEXT NOT NULL DEFAULT '', filter_id TEXT NOT NULL DEFAULT '', privilege INTEGER NOT NULL DEFAULT 0 CHECK(privilege BETWEEN 0 AND 15), PRIMARY KEY(nas,username,mode));
-- +goose Down
DROP TABLE nas_grants;
ALTER TABLE nas DROP COLUMN credential;
ALTER TABLE nas DROP COLUMN access_mode;
ALTER TABLE nas DROP COLUMN dictionary;
