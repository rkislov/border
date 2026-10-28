package store

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestListing(t *testing.T) {
	targets := map[string]string{"sqlite": filepath.Join(t.TempDir(), "list.db")}
	if d := os.Getenv("BORDER_TEST_POSTGRES"); d != "" {
		targets["pgx"] = d
	}
	for driver, dsn := range targets {
		t.Run(driver, func(t *testing.T) {
			s, err := Open(driver, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer s.DB.Close()
			if err = s.Migrate(t.Context()); err != nil {
				t.Fatal(err)
			}
			defer s.Exec(t.Context(), "DELETE FROM auth_log WHERE source=?", "listing-test")
			defer s.Exec(t.Context(), "DELETE FROM sessions WHERE nas=?", "listing-test")
			for i := 0; i < 235; i++ {
				id := fmt.Sprintf("listing-%03d", i)
				result := "accept"
				if i%2 == 0 {
					result = "reject"
				}
				user := "listing-user"
				if i == 0 {
					user = "listing-literal%_!"
				}
				if err = s.Exec(t.Context(), "INSERT INTO auth_log(id,occurred_at,source,identity,result,reason) VALUES (?,?,?,?,?,?)", id, 100, "listing-test", user, result, "test"); err != nil {
					t.Fatal(err)
				}
				if err = s.Exec(t.Context(), "INSERT INTO sessions(nas,session_id,mac,username,status,updated_at,generation) VALUES (?,?,?,?,?,?,?)", "listing-test", id, "aa:bb:cc:dd:ee:ff", user, "active", 100, id); err != nil {
					t.Fatal(err)
				}
			}
			seen := map[string]bool{}
			for page := 1; page <= 5; page++ {
				p, e := s.SessionsPage(t.Context(), ListFilter{Query: "LISTING", Page: page, Limit: 50})
				if e != nil || p.Total != 235 {
					t.Fatalf("%+v %v", p, e)
				}
				for _, v := range p.Items {
					if seen[v.ID] {
						t.Fatal("duplicate page row")
					}
					seen[v.ID] = true
					if v.Generation == "" {
						t.Fatal("missing action guard")
					}
				}
			}
			if len(seen) != 235 {
				t.Fatal(len(seen))
			}
			p, e := s.EventsPage(t.Context(), ListFilter{Query: "listing", Page: 5, Limit: 50})
			if e != nil || len(p.Items) != 35 || p.Total != 235 {
				t.Fatalf("%+v %v", p, e)
			}
			p, e = s.EventsPage(t.Context(), ListFilter{Query: "listing", Result: "reject", From: 100, Until: 100, Page: 1, Limit: 200})
			if e != nil || p.Total != 118 {
				t.Fatalf("filter %d %v", p.Total, e)
			}
			p, e = s.EventsPage(t.Context(), ListFilter{Query: "%_!", Page: 1, Limit: 50})
			if e != nil || p.Total != 1 {
				t.Fatalf("literal search %d %v", p.Total, e)
			}
			p, e = s.EventsPage(t.Context(), ListFilter{Query: "listing", Page: 999, Limit: 50})
			if e != nil || p.Page != 5 {
				t.Fatal("page clamp", p.Page, e)
			}
			p, e = s.EventsPage(t.Context(), ListFilter{Query: "' OR 1=1 --", Page: 1, Limit: 50})
			if e != nil || p.Total != 0 || p.Items == nil {
				t.Fatal("empty/injection", p, e)
			}
			empty, e := s.SessionsPage(t.Context(), ListFilter{Query: "listing", Status: "stale", Page: 1, Limit: 50})
			if e != nil || empty.Total != 0 {
				t.Fatal("status", e)
			}
			other, e := Open("sqlite", filepath.Join(t.TempDir(), "other.db"))
			if e != nil {
				t.Fatal(e)
			}
			defer other.DB.Close()
			if e = other.Migrate(t.Context()); e != nil {
				t.Fatal(e)
			}
			op, e := other.EventsPage(t.Context(), ListFilter{Page: 1, Limit: 50})
			if e != nil || op.Total != 0 {
				t.Fatal("tenant leakage")
			}
		})
	}
}
