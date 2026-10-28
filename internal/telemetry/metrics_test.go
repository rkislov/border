package telemetry

import (
	"sync"
	"testing"
	"time"
)

func TestConcurrentBoundedAndIsolated(t *testing.T) {
	r := New()
	other := New()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				r.Observe("smtp", "error", true, time.Millisecond)
			}
		}()
	}
	wg.Wait()
	r.Observe("private-user", "error", true, 0)
	r.Observe("smtp", "private-error", true, 0)
	s := r.Snapshot()
	if len(s.Operations) != len(names) {
		t.Fatal("unbounded operations")
	}
	for _, o := range s.Operations {
		if o.Name == "smtp" {
			if o.Count != 2000 || o.Failures != 2000 || o.Results["error"] != 2000 {
				t.Fatal(o)
			}
			o.Results["error"] = 1
		}
	}
	for _, o := range r.Snapshot().Operations {
		if o.Name == "smtp" && o.Results["error"] != 2000 {
			t.Fatal("snapshot mutates registry")
		}
	}
	for _, o := range other.Snapshot().Operations {
		if o.Count != 0 {
			t.Fatal("tenant leakage")
		}
	}
}
