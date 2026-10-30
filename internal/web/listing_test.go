package web

import (
	"github.com/rkislov/border/internal/store"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestListingAPI(t *testing.T) {
	s, e := store.Open("sqlite", filepath.Join(t.TempDir(), "list.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	if e = s.Migrate(t.Context()); e != nil {
		t.Fatal(e)
	}
	if e = s.Admin(t.Context(), "admin", "strong-password-123", false); e != nil {
		t.Fatal(e)
	}
	h := HandlerWithOptions(s, nil, nil, false)
	for _, kind := range []string{"sessions", "events"} {
		for _, test := range []struct {
			query string
			auth  bool
			code  int
		}{{"", false, 401}, {"?page=1&limit=25", true, 200}, {"?page=0", true, 400}, {"?limit=201", true, 400}, {"?from=200&until=100", true, 400}, {"?from=abc", true, 400}, {"?status=invalid", true, 400}, {"?authorization=invalid", true, 400}, {"?authorization=unlinked", true, 200}} {
			r := httptest.NewRequest("GET", "https://localhost/api/"+kind+test.query, nil)
			if test.auth {
				r.SetBasicAuth("admin", "strong-password-123")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.code {
				t.Fatal(kind, test.query, w.Code, w.Body.String())
			}
		}
	}
}
