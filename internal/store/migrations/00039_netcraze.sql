-- +goose Up
CREATE TABLE nas_netcraze(nas TEXT PRIMARY KEY REFERENCES nas(address) ON DELETE CASCADE,enabled INTEGER NOT NULL DEFAULT 0,config TEXT NOT NULL);
ALTER TABLE guest_authorizations ADD COLUMN nas_session_id TEXT NOT NULL DEFAULT '';
-- +goose Down
ALTER TABLE guest_authorizations DROP COLUMN nas_session_id;
DROP TABLE nas_netcraze;
