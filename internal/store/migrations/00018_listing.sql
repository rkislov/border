-- +goose Up
CREATE INDEX sessions_page ON sessions(updated_at DESC,nas,session_id);
CREATE INDEX auth_log_page ON auth_log(occurred_at DESC,id DESC);
CREATE INDEX auth_log_result_page ON auth_log(result,occurred_at DESC,id DESC);
-- +goose Down
DROP INDEX auth_log_result_page;
DROP INDEX auth_log_page;
DROP INDEX sessions_page;
