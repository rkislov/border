-- +goose Up
CREATE TABLE policy_schedules(id TEXT PRIMARY KEY,review_id TEXT NOT NULL REFERENCES policy_reviews(id),actor TEXT NOT NULL,actor_revision BIGINT NOT NULL,due_at BIGINT NOT NULL,state TEXT NOT NULL,reason TEXT NOT NULL DEFAULT '',batch_id TEXT NOT NULL DEFAULT '',created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL);
CREATE UNIQUE INDEX policy_schedule_pending_review ON policy_schedules(review_id) WHERE state='pending';
CREATE INDEX policy_schedule_due ON policy_schedules(state,due_at);
-- +goose Down
DROP TABLE policy_schedules;
