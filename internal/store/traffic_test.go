package store

import (
	"testing"
	"time"
)

func TestTrafficSnapshotsOrderingAndGeneration(t *testing.T) {
	s := ruleStore(t)
	ctx := t.Context()
	base := time.Now().Unix() - 1000
	event := AccountingEvent{NAS: "192.0.2.1", ID: "traffic", Kind: "start", At: base, Timed: true}
	apply := func() {
		t.Helper()
		if err := s.ApplyAccounting(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	read := func() Session {
		t.Helper()
		items, err := s.Sessions(ctx)
		if err != nil || len(items) != 1 {
			t.Fatal(items, err)
		}
		return items[0]
	}
	apply()
	if got := read(); got.InputBytes != "" {
		t.Fatal(got)
	}
	event.Kind = "interim"
	event.At = base + 10
	event.Key = "first"
	event.Input = &TrafficCounter{Bytes: 1<<32 + 123, Gigawords: true}
	event.Output = &TrafficCounter{Bytes: 0}
	apply()
	apply()
	got := read()
	if got.InputBytes != "4294967419" || got.OutputBytes != "0" || !got.InputGigawords {
		t.Fatal(got)
	}
	event.At = base + 5
	event.Key = "late"
	event.Input = &TrafficCounter{Bytes: 999999999999, Gigawords: true}
	apply()
	if read().InputBytes != got.InputBytes {
		t.Fatal("late event changed traffic")
	}
	event.At = base + 20
	event.Key = "absent"
	event.Input = nil
	event.Output = nil
	apply()
	if read().InputBytes != got.InputBytes {
		t.Fatal("missing erased traffic")
	}
	event.At = base + 30
	event.Key = "stop"
	event.Kind = "stop"
	event.Input = &TrafficCounter{Bytes: 2}
	event.Output = &TrafficCounter{Bytes: ^uint64(0), Gigawords: true}
	apply()
	got = read()
	if got.Status != "stopped" || got.InputBytes != "4294967419" || got.OutputBytes != "18446744073709551615" || got.TrafficWarning == "" {
		t.Fatal(got)
	}
	event.At = base + 40
	event.Kind = "start"
	event.Key = "new"
	event.Input = nil
	event.Output = nil
	apply()
	got = read()
	if got.InputBytes != "" || got.OutputBytes != "" || got.TrafficWarning != "" {
		t.Fatal("new generation retained counters", got)
	}
}
