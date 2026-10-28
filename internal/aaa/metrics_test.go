package aaa

import (
	"context"
	"github.com/rkislov/border/internal/store"
	"testing"
)

func TestMetricsRoutedToTenant(t *testing.T) {
	root, tenant := database(t), database(t)
	opts := Options{Resolve: func(context.Context, string) (*store.Store, Options, error) { return tenant, Options{}, nil }}
	for _, mac := range []string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"} {
		if _, err := ProcessWithOptions(t.Context(), root, wire(t, request(t, mac)), source(), false, opts); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ProcessWithOptions(t.Context(), root, []byte{0}, source(), false, opts); err == nil {
		t.Fatal("invalid packet accepted")
	}
	for _, o := range root.Metrics.Snapshot().Operations {
		if o.Count != 0 {
			t.Fatal("double counted tenant request", o)
		}
	}
	for _, o := range tenant.Metrics.Snapshot().Operations {
		if o.Name == "radius_auth" && (o.Count != 3 || o.Failures != 1 || o.Results["accept"] != 1 || o.Results["reject"] != 1 || o.Results["drop"] != 1) {
			t.Fatal(o)
		}
	}
}
