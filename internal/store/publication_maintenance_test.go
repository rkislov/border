package store

import (
	"strings"
	"testing"
	"time"
)

func TestPublicationWindowCalendar(t *testing.T) {
	cfg := PublicationWindowSettings{Enabled: true, Timezone: "Europe/Moscow", MaxDelaySeconds: 3600, Windows: []PublicationWindow{{Days: []int{1}, Start: "22:00", End: "06:00"}}}
	for _, tc := range []struct {
		at      string
		allowed bool
	}{{"2026-11-02T18:59:59Z", false}, {"2026-11-02T19:00:00Z", true}, {"2026-11-03T02:59:59Z", true}, {"2026-11-03T03:00:00Z", false}, {"2026-11-03T19:00:00Z", false}} {
		at, _ := time.Parse(time.RFC3339, tc.at)
		got, e := cfg.Allows(at)
		if e != nil || got != tc.allowed {
			t.Fatal(tc, got, e)
		}
	}
	cfg.Timezone = "America/New_York"
	cfg.Windows = []PublicationWindow{{Days: []int{7}, Start: "01:00", End: "02:00"}}
	for _, raw := range []string{"2026-11-01T05:30:00Z", "2026-11-01T06:30:00Z"} {
		at, _ := time.Parse(time.RFC3339, raw)
		if ok, e := cfg.Allows(at); e != nil || !ok {
			t.Fatal("DST repeated hour", ok, e)
		}
	}
	cfg.Windows = []PublicationWindow{{Days: []int{7}, Start: "00:00", End: "24:00"}}
	at, _ := time.Parse(time.RFC3339, "2026-11-01T23:59:59-05:00")
	if ok, e := cfg.Allows(at); e != nil || !ok {
		t.Fatal(ok, e)
	}
}
func TestPublicationWindowValidation(t *testing.T) {
	valid := PublicationWindowSettings{Enabled: true, Timezone: "UTC", MaxDelaySeconds: 60, Windows: []PublicationWindow{{Days: []int{1}, Start: "00:00", End: "24:00"}}}
	for _, bad := range []PublicationWindowSettings{{Enabled: true, Timezone: "UTC", MaxDelaySeconds: 60}, {Timezone: "Local", MaxDelaySeconds: 60}, {Timezone: "Missing/Zone", MaxDelaySeconds: 60}, {Timezone: "UTC", MaxDelaySeconds: 59}, {Timezone: "UTC", MaxDelaySeconds: 604801}, {Enabled: true, Timezone: "UTC", MaxDelaySeconds: 60, Windows: []PublicationWindow{{Days: []int{8}, Start: "00:00", End: "01:00"}}}, {Enabled: true, Timezone: "UTC", MaxDelaySeconds: 60, Windows: []PublicationWindow{{Days: []int{1}, Start: "+1:00", End: "01:00"}}}} {
		if e := bad.Validate(); e == nil {
			t.Fatal(bad)
		}
	}
	if e := valid.Validate(); e != nil {
		t.Fatal(e)
	}
}
func TestScheduleWaitsForWindowAndExpiresAfterDowntime(t *testing.T) {
	for _, expire := range []bool{false, true} {
		t.Run(map[bool]string{false: "wait then publish", true: "downtime expiry"}[expire], func(t *testing.T) {
			s, review, _ := scheduledFixture(t)
			ctx := t.Context()
			due := time.Now().UTC().AddDate(0, 0, 2)
			due = time.Date(due.Year(), due.Month(), due.Day(), 10, 0, 0, 0, time.UTC)
			day := int(due.Weekday())
			if day == 0 {
				day = 7
			}
			cfg := PublicationWindowSettings{Enabled: true, Timezone: "UTC", MaxDelaySeconds: 3600, Windows: []PublicationWindow{{Days: []int{day}, Start: "10:30", End: "11:00"}}}
			if e := s.SavePublicationWindows(ctx, cfg, "alice"); e != nil {
				t.Fatal(e)
			}
			if _, e := s.SchedulePolicyReview(ctx, review, due.Unix(), "alice"); e != nil {
				t.Fatal(e)
			}
			if e := s.RunPolicySchedules(ctx, due); e != nil {
				t.Fatal(e)
			}
			jobs, _ := s.PolicySchedules(ctx)
			if jobs[0].State != "pending" || jobs[0].Reason != "waiting for maintenance window" {
				t.Fatal(jobs)
			}
			at := due.Add(30 * time.Minute)
			want := "published"
			if expire {
				at = due.Add(time.Hour)
				want = "expired"
			}
			if e := s.RunPolicySchedules(ctx, at); e != nil {
				t.Fatal(e)
			}
			jobs, _ = s.PolicySchedules(ctx)
			if jobs[0].State != want {
				t.Fatal(jobs)
			}
			releases, _ := s.PolicyReleases(ctx)
			if expire && len(releases) > 0 {
				t.Fatal("expired job published")
			}
			if e := s.RunPolicySchedules(ctx, at.Add(time.Hour)); e != nil {
				t.Fatal(e)
			}
			again, _ := s.PolicyReleases(ctx)
			if len(again) != len(releases) {
				t.Fatal("duplicate")
			}
		})
	}
}
func TestMaintenanceSettingsAndManualPublicationGuard(t *testing.T) {
	s, review, due := scheduledFixture(t)
	ctx := t.Context()
	id, e := s.SchedulePolicyReview(ctx, review, due, "alice")
	if e != nil {
		t.Fatal(e)
	}
	cfg := PublicationWindowSettings{Timezone: "UTC", MaxDelaySeconds: 120}
	if e = s.SavePublicationWindows(ctx, cfg, "viewer"); e == nil {
		t.Fatal("viewer settings")
	}
	if e = s.SavePublicationWindows(ctx, cfg, "alice"); e != nil {
		t.Fatal(e)
	}
	if e = s.SavePublicationWindows(ctx, cfg, "alice"); e == nil {
		t.Fatal("stale settings")
	}
	cfg.Revision = 1
	cfg.MaxDelaySeconds = 7200
	if e = s.SavePublicationWindows(ctx, cfg, "alice"); e != nil {
		t.Fatal(e)
	}
	jobs, _ := s.PolicySchedules(ctx)
	if jobs[0].ID != id || jobs[0].ExpiresAt != due+120 {
		t.Fatal("extended old job", jobs)
	}
	if e = s.RunPolicySchedules(ctx, time.Unix(due+120, 0)); e != nil {
		t.Fatal(e)
	}
	jobs, _ = s.PolicySchedules(ctx)
	if jobs[0].State != "expired" {
		t.Fatal(jobs)
	}
	cfg.Revision = 2
	cfg.Enabled = true
	day := int(time.Now().UTC().AddDate(0, 0, 2).Weekday())
	if day == 0 {
		day = 7
	}
	cfg.Windows = []PublicationWindow{{Days: []int{day}, Start: "00:00", End: "24:00"}}
	if e = s.SavePublicationWindows(ctx, cfg, "alice"); e != nil {
		t.Fatal(e)
	}
	if e = s.PublishPolicyDraft(ctx, "group", "staff", 1, "alice"); e == nil || !strings.Contains(e.Error(), "maintenance:") {
		t.Fatal("manual bypass", e)
	}
	refs := []DraftRef{{Kind: "group", PolicyID: "staff", Revision: 1}}
	if e = s.PublishPolicyBatch(ctx, refs, "alice"); e == nil {
		t.Fatal("batch bypass")
	}
	ds, _ := s.PolicyDrafts(ctx)
	if len(ds) != 1 {
		t.Fatal("lost draft")
	}
	other := reviewStore(t)
	v, _ := other.PublicationWindows(ctx)
	if v.Enabled {
		t.Fatal("tenant leak")
	}
}
