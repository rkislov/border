-- +goose Up
ALTER TABLE admins ADD COLUMN role TEXT NOT NULL DEFAULT 'admin' CHECK(role IN ('admin','operator','viewer'));
ALTER TABLE admins ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1));
ALTER TABLE admins ADD COLUMN location_id TEXT NOT NULL DEFAULT '';
ALTER TABLE admins ADD COLUMN revision BIGINT NOT NULL DEFAULT 0;
-- +goose Down
ALTER TABLE admins DROP COLUMN revision;
ALTER TABLE admins DROP COLUMN location_id;
ALTER TABLE admins DROP COLUMN enabled;
ALTER TABLE admins DROP COLUMN role;
