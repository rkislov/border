-- +goose Up
CREATE TABLE policy_review_settings(id INTEGER PRIMARY KEY,required INTEGER NOT NULL DEFAULT 0,revision BIGINT NOT NULL DEFAULT 0);
INSERT INTO policy_review_settings(id,required,revision) VALUES(1,0,0);
CREATE TABLE policy_draft_authors(kind TEXT NOT NULL,policy_id TEXT NOT NULL,username TEXT NOT NULL,PRIMARY KEY(kind,policy_id,username));
INSERT INTO policy_draft_authors(kind,policy_id,username) SELECT kind,policy_id,actor FROM policy_drafts;
CREATE TABLE policy_reviews(id TEXT PRIMARY KEY,digest TEXT NOT NULL,state TEXT NOT NULL,requester TEXT NOT NULL,reviewer TEXT NOT NULL DEFAULT '',reviewer_revision BIGINT NOT NULL DEFAULT 0,request_comment TEXT NOT NULL,decision_comment TEXT NOT NULL DEFAULT '',reason TEXT NOT NULL DEFAULT '',refs TEXT NOT NULL,snapshot TEXT NOT NULL,authors TEXT NOT NULL,created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL,batch_id TEXT NOT NULL DEFAULT '');
CREATE UNIQUE INDEX policy_reviews_active ON policy_reviews(digest) WHERE state IN ('pending','approved');
CREATE TABLE policy_review_items(review_id TEXT NOT NULL REFERENCES policy_reviews(id) ON DELETE CASCADE,kind TEXT NOT NULL,policy_id TEXT NOT NULL,revision BIGINT NOT NULL,PRIMARY KEY(review_id,kind,policy_id));
CREATE INDEX policy_review_item_object ON policy_review_items(kind,policy_id);
-- +goose Down
DROP TABLE policy_review_items;
DROP TABLE policy_reviews;
DROP TABLE policy_draft_authors;
DROP TABLE policy_review_settings;
