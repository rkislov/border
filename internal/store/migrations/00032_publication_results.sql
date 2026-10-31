-- +goose Up
CREATE TABLE publication_results(batch_id TEXT PRIMARY KEY,review_id TEXT NOT NULL DEFAULT '',created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL,state TEXT NOT NULL DEFAULT 'in_progress',checked_at BIGINT NOT NULL DEFAULT 0);
CREATE INDEX publication_result_scan ON publication_results(state,checked_at);
CREATE TABLE publication_pending_grants(batch_id TEXT NOT NULL REFERENCES publication_results(batch_id),token TEXT NOT NULL,nas TEXT NOT NULL,username TEXT NOT NULL,policy_id TEXT NOT NULL,deadline_at BIGINT NOT NULL,state TEXT NOT NULL DEFAULT 'waiting_accounting',PRIMARY KEY(batch_id,token));
CREATE INDEX publication_pending_token ON publication_pending_grants(nas,token,state);
CREATE TABLE publication_session_results(batch_id TEXT NOT NULL REFERENCES publication_results(batch_id),nas TEXT NOT NULL,session_id TEXT NOT NULL,generation TEXT NOT NULL,grant_token TEXT NOT NULL DEFAULT '',username TEXT NOT NULL,policy_id TEXT NOT NULL DEFAULT '',state TEXT NOT NULL,session_status TEXT NOT NULL,started_at BIGINT NOT NULL,event_at BIGINT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,last_attempt BIGINT NOT NULL DEFAULT 0,next_attempt BIGINT NOT NULL DEFAULT 0,response TEXT NOT NULL DEFAULT '',nas_response TEXT NOT NULL DEFAULT '',nas_cause BIGINT NOT NULL DEFAULT 0,error_cause BIGINT NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',ack_at BIGINT NOT NULL DEFAULT 0,deadline_at BIGINT NOT NULL,updated_at BIGINT NOT NULL,PRIMARY KEY(batch_id,nas,session_id,generation));
CREATE INDEX publication_session_generation ON publication_session_results(nas,session_id,generation);
CREATE TABLE publication_revocation_attempts(id TEXT PRIMARY KEY,batch_id TEXT NOT NULL REFERENCES publication_results(batch_id),nas TEXT NOT NULL,session_id TEXT NOT NULL,generation TEXT NOT NULL,attempted_at BIGINT NOT NULL,response TEXT NOT NULL,nas_response TEXT NOT NULL DEFAULT '',nas_cause BIGINT NOT NULL DEFAULT 0,error_cause BIGINT NOT NULL,message TEXT NOT NULL);
CREATE INDEX publication_attempt_batch ON publication_revocation_attempts(batch_id,attempted_at);
-- +goose Down
DROP TABLE publication_revocation_attempts;
DROP TABLE publication_session_results;
DROP TABLE publication_pending_grants;
DROP TABLE publication_results;
