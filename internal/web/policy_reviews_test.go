package web

import (
	"encoding/json"
	"github.com/rkislov/border/internal/store"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
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
	for _, path := range []string{"/api/policy-drafts/review-settings", "/api/policy-drafts/reviews", "/api/policy-drafts/reviews/decision"} {
		if w := send("POST", path, "alice", `{}`, ""); w.Code != 403 {
			t.Fatal("review CSRF", path, w.Code)
		}
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
	if w = send("POST", "/api/policy-drafts/batch/publish", "alice", batch, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = send("GET", "/api/policy-drafts/reviews/"+request.ID, "alice", "", "")
	var review store.PolicyReview
	json.Unmarshal(w.Body.Bytes(), &review)
	if w.Code != 200 || review.Requester != "alice" || review.Reviewer != "bob" || review.State != "published" || len(review.Snapshot) != 1 {
		t.Fatal(w.Code, w.Body.String())
	}
}
