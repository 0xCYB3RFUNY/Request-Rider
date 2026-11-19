package active

import (
	"testing"
)

func TestGfParamsByCategory(t *testing.T) {
	categories := []string{"ssrf", "rce", "lfi", "ssti", "redirect", "idor", "sqli"}
	for _, cat := range categories {
		params := GfParamsByCategory(cat)
		if len(params) == 0 {
			t.Fatalf("expected parameters for category %q, got 0", cat)
		}
	}

	if GfParamsByCategory("unknown") != nil {
		t.Fatalf("expected nil for unknown category")
	}

	// Test HiddenParams integration with Category
	hp := HiddenParams{Category: "ssrf"}
	names := hp.usableNames()
	if len(names) < 10 {
		t.Fatalf("expected at least 10 usable names from ssrf category, got %d", len(names))
	}

	foundURL := false
	for _, n := range names {
		if n == "url" {
			foundURL = true
			break
		}
	}
	if !foundURL {
		t.Fatalf("expected 'url' in ssrf category names")
	}
}
