-- +goose Up
CREATE TABLE nas_routeros(nas TEXT PRIMARY KEY REFERENCES nas(address) ON DELETE CASCADE,config TEXT NOT NULL);
-- +goose Down
DROP TABLE nas_routeros;
