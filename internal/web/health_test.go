package web

import (
	"github.com/rkislov/border/internal/store"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHealthProtectionAndExport(t *testing.T) {
	s, err := store.Open("sqlite", filepath.Join(t.TempDir(), "health.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = s.Admin(t.Context(), "admin", "strong-password-123", false); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"active", "stale", "stopped"} {
		if err = s.Exec(t.Context(), "INSERT INTO sessions(nas,session_id,mac,username,status,updated_at) VALUES(?,?,?,?,?,?)", "nas", status, "", "user", status, 1); err != nil {
			t.Fatal(err)
		}
	}
	s.Metrics.Observe("smtp", "error", true, time.Millisecond)
	h := HandlerWithOptions(s, nil, nil, false)
	for _, path := range []string{"/api/health", "/metrics"} {
		for _, auth := range []bool{false, true} {
			r := httptest.NewRequest("GET", "https://localhost"+path, nil)
			if auth {
				r.SetBasicAuth("admin", "strong-password-123")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 401
			if auth {
				want = 200
			}
			if w.Code != want {
				t.Fatalf("%s auth=%v: %d %s", path, auth, w.Code, w.Body.String())
			}
			if auth && path == "/metrics" && !strings.Contains(w.Body.String(), "border_unlinked_sessions 2") {
				t.Fatal(w.Body.String())
			}
			if auth && path == "/metrics" && !strings.Contains(w.Body.String(), `border_failures_total{operation="smtp"} 1`) {
				t.Fatal(w.Body.String())
			}
		}
	}
	a := &app{s: s}
	if got := a.health(t.Context()).UnlinkedSessions; got != 2 {
		t.Fatalf("unlinked active/stale: %d", got)
	}
	if !a.health(t.Context()).DatabaseOK {
		t.Fatal("database not available")
	}
	s.DB.Close()
	if a.health(t.Context()).DatabaseOK {
		t.Fatal("closed database reported healthy")
	}
}
