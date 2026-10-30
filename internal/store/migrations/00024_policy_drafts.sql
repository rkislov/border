-- +goose Up
CREATE TABLE policy_write_lock(id INTEGER PRIMARY KEY, revision BIGINT NOT NULL);
INSERT INTO policy_write_lock(id,revision) VALUES(1,0);
CREATE TABLE policy_draft_versions(kind TEXT NOT NULL,policy_id TEXT NOT NULL,revision BIGINT NOT NULL,PRIMARY KEY(kind,policy_id));
CREATE TABLE policy_drafts(kind TEXT NOT NULL,policy_id TEXT NOT NULL,revision BIGINT NOT NULL,base TEXT NOT NULL,payload TEXT NOT NULL,actor TEXT NOT NULL,updated_at BIGINT NOT NULL,PRIMARY KEY(kind,policy_id));
CREATE TABLE policy_releases(id TEXT PRIMARY KEY,kind TEXT NOT NULL,policy_id TEXT NOT NULL,before_payload TEXT NOT NULL,after_payload TEXT NOT NULL,actor TEXT NOT NULL,created_at BIGINT NOT NULL);
-- +goose Down
DROP TABLE policy_releases;
DROP TABLE policy_drafts;
DROP TABLE policy_draft_versions;
DROP TABLE policy_write_lock;
