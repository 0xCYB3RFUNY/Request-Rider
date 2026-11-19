package active

import (
	"os"
	"testing"
)

func TestCVECatalogCovers1999To2026AndLoadsLocalNucleiIndex(t *testing.T) {
	cat, err := LoadCVECatalog("")
	if err != nil {
		t.Fatalf("LoadCVECatalog: %v", err)
	}
	stats := cat.Stats()
	if stats.MinYear != 1999 || stats.MaxYear < 2026 {
		t.Fatalf("expected catalog span 1999..2026+, got %d..%d", stats.MinYear, stats.MaxYear)
	}
	if _, ok := cat.Lookup("CVE-1999-0738"); !ok {
		t.Fatal("expected CVE-1999-0738 in catalog")
	}
	if _, ok := cat.Lookup("CVE-2026-0545"); !ok {
		t.Fatal("expected CVE-2026-0545 in catalog")
	}

	if _, err := os.Stat("/home/kali/nuclei-templates/cves.json"); err == nil {
		if stats.Total < 4600 {
			t.Fatalf("expected >= 4600 CVEs when local nuclei cves.json is present, got %d", stats.Total)
		}
		t.Logf("[CVE CATALOG] loaded=%d span=%d..%d source=%s", stats.Total, stats.MinYear, stats.MaxYear, stats.CatalogDir)
	}
}
