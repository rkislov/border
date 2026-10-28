-- +goose Up
CREATE TABLE user_groups(id TEXT PRIMARY KEY,name TEXT NOT NULL,enabled INTEGER NOT NULL CHECK(enabled IN (0,1)));
CREATE TABLE user_group_members(group_id TEXT NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,username TEXT NOT NULL,PRIMARY KEY(group_id,username));
CREATE TABLE access_rule_sets(policy_id TEXT PRIMARY KEY REFERENCES access_policies(id) ON DELETE CASCADE,version BIGINT NOT NULL,config TEXT NOT NULL);
-- +goose Down
DROP TABLE access_rule_sets;
DROP TABLE user_group_members;
DROP TABLE user_groups;
