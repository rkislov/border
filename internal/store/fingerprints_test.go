package store

import (
	"path/filepath"
	"testing"
)

func TestFingerprintEvidenceAndOUI(t *testing.T) {
	s, err := Open("sqlite", filepath.Join(t.TempDir(), "fp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	ctx := t.Context()
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"001122", "0011223", "001122334"} {
		if err = s.SetOUI(ctx, p, p); err != nil {
			t.Fatal(err)
		}
	}
	f := Fingerprint{MAC: "00:11:22:33:44:55", OS: "manual OS", DHCPOptions: "1,3,6,15", Source: "admin"}
	if err = s.ObserveFingerprint(ctx, f); err != nil {
		t.Fatal(err)
	}
	if err = s.ObserveFingerprint(ctx, Fingerprint{MAC: f.MAC, NAS: "192.0.2.1", Source: "radius", OS: "forged OS"}); err != nil {
		t.Fatal(err)
	}
	list, err := s.Fingerprints(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("%v %v", list, err)
	}
	if list[0].OS != "manual OS" || list[0].OUIManufacturer != "001122334" || list[0].NAS != "192.0.2.1" {
		t.Fatalf("%+v", list[0])
	}
	f.DHCPOptions = "256"
	if s.ObserveFingerprint(ctx, f) == nil {
		t.Fatal("invalid DHCP byte")
	}
	if err = s.SetOUI(ctx, "021122", "local"); err != nil {
		t.Fatal(err)
	}
	if err = s.ObserveFingerprint(ctx, Fingerprint{MAC: "02:11:22:33:44:55", Source: "radius"}); err != nil {
		t.Fatal(err)
	}
	list, err = s.Fingerprints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range list {
		if f.MAC == "02:11:22:33:44:55" && f.OUIManufacturer != "" {
			t.Fatal("inferred manufacturer for randomized address")
		}
	}
}
