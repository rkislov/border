-- +goose Up
CREATE TABLE change_journal(seq BIGINT PRIMARY KEY,id TEXT NOT NULL UNIQUE,occurred_at BIGINT NOT NULL,action TEXT NOT NULL,actor TEXT NOT NULL,review_id TEXT NOT NULL DEFAULT '',batch_id TEXT NOT NULL DEFAULT '',schedule_id TEXT NOT NULL DEFAULT '',summary TEXT NOT NULL DEFAULT '',detail TEXT NOT NULL DEFAULT '{}',release_id TEXT NOT NULL DEFAULT '',legacy INTEGER NOT NULL DEFAULT 0);
CREATE INDEX change_journal_review ON change_journal(review_id);
CREATE INDEX change_journal_batch ON change_journal(batch_id);
CREATE TABLE draft_journal_cycles(kind TEXT NOT NULL,policy_id TEXT NOT NULL,cycle_id TEXT NOT NULL,PRIMARY KEY(kind,policy_id));
INSERT INTO draft_journal_cycles(kind,policy_id,cycle_id) SELECT kind,policy_id,'legacy:' || kind || ':' || policy_id FROM policy_drafts;
CREATE TABLE change_journal_objects(event_id TEXT NOT NULL REFERENCES change_journal(id),kind TEXT NOT NULL,policy_id TEXT NOT NULL,revision BIGINT NOT NULL,cycle_id TEXT NOT NULL,PRIMARY KEY(event_id,kind,policy_id));
CREATE INDEX change_journal_cycle ON change_journal_objects(cycle_id);
INSERT INTO change_journal(seq,id,occurred_at,action,actor,batch_id,release_id,legacy,summary,review_id)
 SELECT ROW_NUMBER() OVER(ORDER BY created_at,id),'legacy-release:' || id,created_at,'published_legacy',actor,batch_id,id,1,'Историческая публикация; снимок влияния не сохранялся',COALESCE((SELECT r.id FROM policy_reviews r WHERE r.batch_id=policy_releases.batch_id AND r.batch_id<>'' LIMIT 1),'') FROM policy_releases;
INSERT INTO change_journal_objects(event_id,kind,policy_id,revision,cycle_id)
 SELECT 'legacy-release:' || id,kind,policy_id,0,'release:' || id FROM policy_releases;
INSERT INTO change_journal(seq,id,occurred_at,action,actor,review_id,batch_id,legacy,summary)
 SELECT (SELECT COALESCE(MAX(seq),0) FROM change_journal)+ROW_NUMBER() OVER(ORDER BY updated_at,id),'legacy-review:' || id,updated_at,'legacy_review_state',requester,id,batch_id,1,'Состояние при обновлении: ' || state || '; согласующий: ' || reviewer FROM policy_reviews;
-- +goose Down
DROP TABLE change_journal_objects;
DROP TABLE draft_journal_cycles;
DROP TABLE change_journal;
