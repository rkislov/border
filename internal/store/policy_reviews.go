// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"sort"
	"strings"
	"time"
)

type ReviewSettings struct {
	Required bool
	Revision int64
}
type PolicyReview struct {
	ID, Digest, State, Requester, Reviewer, RequestComment, DecisionComment, Reason, BatchID string
	ReviewerRevision, CreatedAt, UpdatedAt                                                   int64
	Drafts                                                                                   []DraftRef
	Authors                                                                                  []string
	Snapshot                                                                                 []PolicyDraft `json:",omitempty"`
}

func reviewDigest(ds []PolicyDraft) string {
	copyDrafts := append([]PolicyDraft(nil), ds...)
	sort.Slice(copyDrafts, func(i, j int) bool {
		if copyDrafts[i].Kind != copyDrafts[j].Kind {
			return copyDrafts[i].Kind < copyDrafts[j].Kind
		}
		return copyDrafts[i].PolicyID < copyDrafts[j].PolicyID
	})
	sum := sha256.Sum256(policyJSON(copyDrafts))
	return hex.EncodeToString(sum[:])
}
func (s *Store) reviewSettingsTx(ctx context.Context, tx *sql.Tx) (ReviewSettings, error) {
	var v ReviewSettings
	e := tx.QueryRowContext(ctx, "SELECT required,revision FROM policy_review_settings WHERE id=1").Scan(&v.Required, &v.Revision)
	return v, e
}
func (s *Store) ReviewSettings(ctx context.Context) (ReviewSettings, error) {
	var v ReviewSettings
	e := s.Row(ctx, "SELECT required,revision FROM policy_review_settings WHERE id=1").Scan(&v.Required, &v.Revision)
	return v, e
}
func (s *Store) reviewAdmin(ctx context.Context, tx *sql.Tx, user string) (int64, error) {
	q := "SELECT role,enabled,revision FROM admins WHERE username=?"
	if s.Driver == "pgx" {
		q += " FOR SHARE"
	}
	var role string
	var enabled bool
	var revision int64
	if e := tx.QueryRowContext(ctx, s.SQL(q), user).Scan(&role, &enabled, &revision); e != nil || role != "admin" || !enabled {
		return 0, fmt.Errorf("approval: active administrator required")
	}
	return revision, nil
}
func (s *Store) reviewAudit(ctx context.Context, tx *sql.Tx, actor, action string) error {
	_, e := tx.ExecContext(ctx, s.SQL("INSERT INTO auth_log(id,occurred_at,source,identity,result,reason) VALUES(?,?,?,?,?,?)"), uuid.NewString(), time.Now().Unix(), "web", actor, "updated", action)
	return e
}
func (s *Store) SaveReviewSettings(ctx context.Context, v ReviewSettings, actor string) error {
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = s.reviewAdmin(ctx, tx, actor); e != nil {
		return e
	}
	old, e := s.reviewSettingsTx(ctx, tx)
	if e != nil {
		return e
	}
	if old.Revision != v.Revision {
		return fmt.Errorf("approval settings changed; reload")
	}
	if old.Required == v.Required {
		return nil
	}
	if v.Required {
		var count int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM admins WHERE role='admin' AND enabled=1").Scan(&count); e != nil {
			return e
		}
		if count < 2 {
			return fmt.Errorf("approval: enable at least two administrators first")
		}
	}
	if _, e = tx.ExecContext(ctx, s.SQL("UPDATE policy_review_settings SET required=?,revision=revision+1 WHERE id=1"), integer(v.Required)); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, s.SQL("UPDATE policy_reviews SET state='stale',reason='approval mode changed',updated_at=? WHERE state IN ('pending','approved')"), time.Now().Unix()); e != nil {
		return e
	}
	if e = s.reviewAudit(ctx, tx, actor, fmt.Sprintf("require policy approval: %t", v.Required)); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) invalidateDraftReviews(ctx context.Context, tx *sql.Tx, kind, id, reason string) error {
	_, e := tx.ExecContext(ctx, s.SQL("UPDATE policy_reviews SET state='stale',reason=?,updated_at=? WHERE state IN ('pending','approved') AND EXISTS(SELECT 1 FROM policy_review_items i WHERE i.review_id=policy_reviews.id AND i.kind=? AND i.policy_id=?)"), reason, time.Now().Unix(), kind, id)
	return e
}
func (s *Store) refreshReviewAccounts(ctx context.Context, tx *sql.Tx) error {
	_, e := tx.ExecContext(ctx, s.SQL("UPDATE policy_reviews SET state='stale',reason='reviewer account changed',updated_at=? WHERE state='approved' AND NOT EXISTS(SELECT 1 FROM admins a WHERE a.username=policy_reviews.reviewer AND a.role='admin' AND a.enabled=1 AND a.revision=policy_reviews.reviewer_revision)"), time.Now().Unix())
	return e
}
func (s *Store) validateReviewBatch(ctx context.Context, tx *sql.Tx, ds []PolicyDraft) error {
	if _, e := tx.ExecContext(ctx, "SAVEPOINT review_check"); e != nil {
		return e
	}
	if _, e := s.applyBatch(ctx, tx, ds, newTargets()); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT review_check"); e != nil {
		return e
	}
	_, e := tx.ExecContext(ctx, "RELEASE SAVEPOINT review_check")
	return e
}
func (s *Store) SubmitPolicyReview(ctx context.Context, refs []DraftRef, comment, actor string) (string, error) {
	if len(comment) > 1000 {
		return "", fmt.Errorf("approval: comment exceeds 1000 bytes")
	}
	tx, e := s.policyTx(ctx)
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	if _, e = s.reviewAdmin(ctx, tx, actor); e != nil {
		return "", e
	}
	settings, e := s.reviewSettingsTx(ctx, tx)
	if e != nil {
		return "", e
	}
	if !settings.Required {
		return "", fmt.Errorf("approval: review mode is disabled")
	}
	if e = s.refreshReviewAccounts(ctx, tx); e != nil {
		return "", e
	}
	ds, e := s.batchDrafts(ctx, tx, refs)
	if e != nil {
		return "", e
	}
	if e = s.validateReviewBatch(ctx, tx, ds); e != nil {
		return "", e
	}
	digest := reviewDigest(ds)
	var existing string
	e = tx.QueryRowContext(ctx, s.SQL("SELECT id FROM policy_reviews WHERE digest=? AND state IN ('pending','approved')"), digest).Scan(&existing)
	if e == nil {
		return "", fmt.Errorf("approval: this package already has an active request")
	}
	if e != sql.ErrNoRows {
		return "", e
	}
	authors := map[string]bool{actor: true}
	for _, d := range ds {
		authors[d.Actor] = true
		rows, e := tx.QueryContext(ctx, s.SQL("SELECT username FROM policy_draft_authors WHERE kind=? AND policy_id=?"), d.Kind, d.PolicyID)
		if e != nil {
			return "", e
		}
		for rows.Next() {
			var user string
			if e = rows.Scan(&user); e != nil {
				rows.Close()
				return "", e
			}
			authors[user] = true
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return "", e
		}
	}
	names := []string{}
	for name := range authors {
		names = append(names, name)
	}
	sort.Strings(names)
	id := uuid.NewString()
	now := time.Now().Unix()
	_, e = tx.ExecContext(ctx, s.SQL("INSERT INTO policy_reviews(id,digest,state,requester,request_comment,refs,snapshot,authors,created_at,updated_at) VALUES(?,?,'pending',?,?,?,?,?,?,?)"), id, digest, actor, strings.TrimSpace(comment), string(policyJSON(refs)), string(policyJSON(ds)), string(policyJSON(names)), now, now)
	if e != nil {
		return "", e
	}
	for _, d := range ds {
		if _, e = tx.ExecContext(ctx, s.SQL("INSERT INTO policy_review_items(review_id,kind,policy_id,revision) VALUES(?,?,?,?)"), id, d.Kind, d.PolicyID, d.Revision); e != nil {
			return "", e
		}
	}
	if e = s.reviewAudit(ctx, tx, actor, "submit policy approval "+id); e != nil {
		return "", e
	}
	if e = tx.Commit(); e != nil {
		return "", e
	}
	return id, nil
}

const reviewColumns = "id,digest,state,requester,reviewer,reviewer_revision,request_comment,decision_comment,reason,refs,authors,created_at,updated_at,batch_id"

func scanReview(scan func(...any) error) (PolicyReview, error) {
	var v PolicyReview
	var refs, authors string
	e := scan(&v.ID, &v.Digest, &v.State, &v.Requester, &v.Reviewer, &v.ReviewerRevision, &v.RequestComment, &v.DecisionComment, &v.Reason, &refs, &authors, &v.CreatedAt, &v.UpdatedAt, &v.BatchID)
	if e != nil {
		return v, e
	}
	if e = json.Unmarshal([]byte(refs), &v.Drafts); e != nil {
		return v, e
	}
	e = json.Unmarshal([]byte(authors), &v.Authors)
	return v, e
}
func (s *Store) PolicyReviews(ctx context.Context) ([]PolicyReview, error) {
	tx, e := s.policyTx(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if e = s.refreshReviewAccounts(ctx, tx); e != nil {
		return nil, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+reviewColumns+" FROM policy_reviews WHERE state IN ('pending','approved') OR id IN (SELECT id FROM policy_reviews ORDER BY updated_at DESC,id DESC LIMIT 100) ORDER BY updated_at DESC,id DESC")
	if e != nil {
		return nil, e
	}
	out := []PolicyReview{}
	for rows.Next() {
		v, e := scanReview(rows.Scan)
		if e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return out, nil
}
func (s *Store) PolicyReview(ctx context.Context, id string) (PolicyReview, error) {
	v, e := scanReview(s.Row(ctx, "SELECT "+reviewColumns+" FROM policy_reviews WHERE id=?", id).Scan)
	if e != nil {
		return v, e
	}
	var raw string
	if e = s.Row(ctx, "SELECT snapshot FROM policy_reviews WHERE id=?", id).Scan(&raw); e != nil {
		return v, e
	}
	e = json.Unmarshal([]byte(raw), &v.Snapshot)
	return v, e
}
func (s *Store) DecidePolicyReview(ctx context.Context, id string, approve bool, comment, actor string) error {
	comment = strings.TrimSpace(comment)
	if len(comment) > 1000 || (!approve && comment == "") {
		return fmt.Errorf("approval: rejection comment required (maximum 1000 bytes)")
	}
	tx, e := s.policyTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	revision, e := s.reviewAdmin(ctx, tx, actor)
	if e != nil {
		return e
	}
	settings, e := s.reviewSettingsTx(ctx, tx)
	if e != nil {
		return e
	}
	if !settings.Required {
		return fmt.Errorf("approval: review mode is disabled")
	}
	v, e := scanReview(tx.QueryRowContext(ctx, s.SQL("SELECT "+reviewColumns+" FROM policy_reviews WHERE id=?"), id).Scan)
	if e != nil {
		return e
	}
	if v.State != "pending" {
		return fmt.Errorf("approval: request is no longer pending")
	}
	for _, author := range v.Authors {
		if author == actor {
			return fmt.Errorf("approval: requester and draft authors cannot review their own package")
		}
	}
	if approve {
		ds, err := s.batchDrafts(ctx, tx, v.Drafts)
		if err != nil {
			return err
		}
		if reviewDigest(ds) != v.Digest {
			return fmt.Errorf("approval: package changed")
		}
		if e = s.validateReviewBatch(ctx, tx, ds); e != nil {
			return e
		}
	}
	state := "rejected"
	if approve {
		state = "approved"
	}
	_, e = tx.ExecContext(ctx, s.SQL("UPDATE policy_reviews SET state=?,reviewer=?,reviewer_revision=?,decision_comment=?,updated_at=? WHERE id=?"), state, actor, revision, comment, time.Now().Unix(), id)
	if e != nil {
		return e
	}
	if e = s.reviewAudit(ctx, tx, actor, state+" policy approval "+id); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) requireBatchApproval(ctx context.Context, tx *sql.Tx, ds []PolicyDraft, actor string) (string, error) {
	settings, e := s.reviewSettingsTx(ctx, tx)
	if e != nil {
		return "", e
	}
	if !settings.Required {
		return "", nil
	}
	if _, e = s.reviewAdmin(ctx, tx, actor); e != nil {
		return "", e
	}
	var id, reviewer string
	var revision int64
	e = tx.QueryRowContext(ctx, s.SQL("SELECT id,reviewer,reviewer_revision FROM policy_reviews WHERE digest=? AND state='approved'"), reviewDigest(ds)).Scan(&id, &reviewer, &revision)
	if e != nil {
		return "", fmt.Errorf("approval: second administrator approval required for this exact package")
	}
	current, e := s.reviewAdmin(ctx, tx, reviewer)
	if e != nil || current != revision {
		return "", fmt.Errorf("approval: reviewer account changed; submit a new request")
	}
	return id, nil
}
