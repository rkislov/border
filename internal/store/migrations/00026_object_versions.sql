-- +goose Up
CREATE TABLE configuration_versions(kind TEXT NOT NULL,object_id TEXT NOT NULL,version BIGINT NOT NULL,PRIMARY KEY(kind,object_id));
INSERT INTO configuration_versions(kind,object_id,version) SELECT 'rules',policy_id,version FROM access_rule_sets;
INSERT INTO configuration_versions(kind,object_id,version) SELECT 'nas-policies',nas,version FROM nas_policy_sets;
-- +goose Down
DROP TABLE configuration_versions;
