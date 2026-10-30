package web

import (
	"encoding/json"
	"github.com/rkislov/border/internal/store"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReviewAPISelfApprovalCSRFAndPublicationGuard(t *testing.T) {
	s, e := store.Open("sqlite", filepath.Join(t.TempDir(), "reviews.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	ctx := t.Context()
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"alice", "bob"} {
		if e = s.Admin(ctx, name, "test-password-123", false); e != nil {
			t.Fatal(e)
		}
	}
	h := HandlerWithOptions(s, nil, nil, false)
	send := func(method, path, user, body, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://localhost"+path, strings.NewReader(body))
		r.SetBasicAuth(user, "test-password-123")
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	page := send("GET", "/", "alice", "", "")
	csrf := strings.Split(strings.Split(page.Body.String(), `name="csrf-token" content="`)[1], `"`)[0]
	for _, path := range []string{"/api/policy-drafts/maintenance", "/api/policy-notifications/recipient", "/api/policy-notifications/retry", "/api/policy-notifications/push", "/api/policy-notifications/push-disable", "/api/policy-drafts/schedules", "/api/policy-drafts/schedules/cancel", "/api/policy-drafts/review-settings", "/api/policy-drafts/reviews", "/api/policy-drafts/reviews/decision"} {
		if w := send("POST", path, "alice", `{}`, ""); w.Code != 403 {
			t.Fatal("review CSRF", path, w.Code)
		}
	}

	if w := send("POST", "/api/policy-notifications/recipient", "alice", `{"Channel":"email","Scope":"default","Destination":"alice@example.test","Enabled":true,"Username":"bob"}`, csrf); w.Code != 400 {
		t.Fatal("recipient spoof", w.Code)
	}
	if w := send("POST", "/api/policy-notifications/recipient", "alice", `{"Channel":"email","Scope":"default","Destination":"alice@example.test","Enabled":true}`, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if targets, e := s.PolicyNotificationTargets(ctx, "bob"); e != nil || len(targets) != 0 {
		t.Fatal("cross-account settings", targets, e)
	}

	maintenance := `{"Revision":0,"Enabled":false,"Timezone":"Europe/Moscow","MaxDelaySeconds":3600,"Windows":[]}`
	if w := send("POST", "/api/policy-drafts/maintenance", "alice", maintenance, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := send("POST", "/api/policy-drafts/maintenance", "alice", maintenance, csrf); w.Code != 409 {
		t.Fatal("stale maintenance version", w.Code)
	}
	if w := send("POST", "/api/policy-drafts/review-settings", "alice", `{"Required":true,"Revision":0}`, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := send("POST", "/api/policy-drafts", "alice", `{"Kind":"group","PolicyID":"staff","Payload":{"ID":"staff","Name":"Staff","Enabled":true}}`, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	batch := `{"Drafts":[{"Kind":"group","PolicyID":"staff","Revision":1}]}`
	if w := send("POST", "/api/policy-drafts/batch/publish", "alice", batch, csrf); w.Code != 409 {
		t.Fatal("approval bypass", w.Code)
	}
	spoof := `{"Drafts":[{"Kind":"group","PolicyID":"staff","Revision":1}],"Requester":"bob"}`
	if w := send("POST", "/api/policy-drafts/reviews", "alice", spoof, csrf); w.Code != 400 {
		t.Fatal("requester spoof", w.Code)
	}
	w := send("POST", "/api/policy-drafts/reviews", "alice", batch, csrf)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var request struct{ ID string }
	json.Unmarshal(w.Body.Bytes(), &request)
	decision, _ := json.Marshal(map[string]any{"ID": request.ID, "Approve": true, "Comment": "Проверено"})
	if w = send("POST", "/api/policy-drafts/reviews/decision", "alice", string(decision), csrf); w.Code != 409 {
		t.Fatal("self review", w.Code)
	}
	if w = send("POST", "/api/policy-drafts/reviews/decision", "bob", string(decision), csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}

	scheduleBody, _ := json.Marshal(map[string]any{"ReviewID": request.ID, "DueAt": time.Now().Add(time.Hour).Unix()})
	w = send("POST", "/api/policy-drafts/schedules", "alice", string(scheduleBody), csrf)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var job struct{ ID string }
	if e = json.Unmarshal(w.Body.Bytes(), &job); e != nil {
		t.Fatal(e)
	}
	cancelBody, _ := json.Marshal(job)
	if w = send("POST", "/api/policy-drafts/schedules/cancel", "bob", string(cancelBody), csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = send("GET", "/api/policy-drafts", "alice", "", "")
	var list struct{ Schedules []store.PolicySchedule }
	if e = json.Unmarshal(w.Body.Bytes(), &list); e != nil {
		t.Fatal(e)
	}
	if len(list.Schedules) != 1 || list.Schedules[0].Actor != "alice" || list.Schedules[0].State != "cancelled" {
		t.Fatal(list)
	}
	if w = send("POST", "/api/policy-drafts/batch/publish", "alice", batch, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = send("GET", "/api/policy-drafts/reviews/"+request.ID, "alice", "", "")
	var review store.PolicyReview
	json.Unmarshal(w.Body.Bytes(), &review)
	if w.Code != 200 || review.Requester != "alice" || review.Reviewer != "bob" || review.State != "published" || len(review.Snapshot) != 1 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = send("GET", "/api/change-journal?action=published&actor=alice&q=staff&limit=1", "alice", "", "")
	var journal store.ChangePage
	if e = json.Unmarshal(w.Body.Bytes(), &journal); e != nil || w.Code != 200 || len(journal.Items) != 1 || journal.Items[0].ReviewID != request.ID {
		t.Fatal(w.Code, w.Body.String(), e)
	}
	w = send("GET", "/api/change-journal/"+journal.Items[0].ID, "alice", "", "")
	var change store.ChangeDetail
	if e = json.Unmarshal(w.Body.Bytes(), &change); e != nil || w.Code != 200 || change.Event.Actor != "alice" || len(change.Objects) != 1 || len(change.Timeline) != 6 {
		t.Fatal(w.Code, w.Body.String(), e)
	}
	for _, path := range []string{"?before=bad", "?before=-1", "?limit=0", "?limit=101", "?limit=bad"} {
		if w = send("GET", "/api/change-journal"+path, "alice", "", ""); w.Code != 400 {
			t.Fatal("invalid journal filter", path, w.Code)
		}
	}
	if w = send("GET", "/api/change-journal/missing", "alice", "", ""); w.Code != 404 {
		t.Fatal("missing journal record", w.Code)
	}
}
