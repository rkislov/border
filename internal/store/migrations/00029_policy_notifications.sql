-- +goose Up
CREATE TABLE policy_notification_targets(id TEXT PRIMARY KEY,username TEXT NOT NULL,channel TEXT NOT NULL,scope TEXT NOT NULL,destination TEXT NOT NULL,endpoint_hash TEXT NOT NULL DEFAULT '',enabled INTEGER NOT NULL,revision BIGINT NOT NULL);
CREATE UNIQUE INDEX policy_notification_push_owner ON policy_notification_targets(endpoint_hash) WHERE channel='push' AND enabled=1;
CREATE TABLE policy_notification_events(id TEXT PRIMARY KEY,event_key TEXT NOT NULL UNIQUE,message TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE policy_notification_deliveries(id TEXT PRIMARY KEY,event_id TEXT NOT NULL REFERENCES policy_notification_events(id),target_id TEXT NOT NULL,target_revision BIGINT NOT NULL,state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_attempt BIGINT NOT NULL,lease_until BIGINT NOT NULL DEFAULT 0,lease_token TEXT NOT NULL DEFAULT '',last_error TEXT NOT NULL DEFAULT '',updated_at BIGINT NOT NULL,UNIQUE(event_id,target_id));
CREATE INDEX policy_delivery_due ON policy_notification_deliveries(state,next_attempt,lease_until);
-- +goose Down
DROP TABLE policy_notification_deliveries;
DROP TABLE policy_notification_events;
DROP TABLE policy_notification_targets;
