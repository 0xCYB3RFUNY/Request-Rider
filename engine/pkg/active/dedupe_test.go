package active

import (
	"strings"
	"testing"
)

func hostRow(module, title, payload, endpoint string) Finding {
	return Finding{
		Module: module, Title: title, Payload: payload, Endpoint: endpoint,
		Severity: SeverityMedium, Tier: TierVerified,
		Evidence: "the endpoint answered for: PROPFIND", CWE: "CWE-16",
		ID:      FindingID(module, Point{URL: endpoint}, payload),
		PoCCurl: "curl '" + endpoint + "'",
	}
}

// A uniform deployment answers the same header/method question on every page.
// The rows are identical apart from the URL and ID; only one should reach the
// report, and the collapse must be visible in a warning.
func TestDedupeHostPropertyFindingsCollapsesIdenticalAnswers(t *testing.T) {
	rows := []Finding{
		hostRow("methods", "WebDAV Enabled (PROPFIND)", "OPTIONS http://h/a", "http://h/a"),
		hostRow("methods", "WebDAV Enabled (PROPFIND)", "OPTIONS http://h/b", "http://h/b"),
		hostRow("methods", "WebDAV Enabled (PROPFIND)", "OPTIONS http://h/c", "http://h/c"),
		hostRow("misconfig", "Missing Security Headers", "", "http://h/a"),
		hostRow("misconfig", "Missing Security Headers", "", "http://h/b"),
	}
	got, collapsed := dedupeHostPropertyFindings(rows)
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(got), got)
	}
	if collapsed != 3 {
		t.Fatalf("collapsed = %d, want 3", collapsed)
	}
	warning := hostPropertyWarning(collapsed)
	if !strings.Contains(warning, "3") || !strings.Contains(warning, "still probed") {
		t.Fatalf("warning = %q, want the count and the probe guarantee", warning)
	}
}

// Two different observations from the same module are not duplicates: a host
// can answer PROPFIND on one path and TRACE on another, and both are real.
func TestDedupeHostPropertyFindingsKeepsDifferentAnswers(t *testing.T) {
	rows := []Finding{
		hostRow("methods", "WebDAV Enabled (PROPFIND)", "OPTIONS http://h/a", "http://h/a"),
		hostRow("methods", "HTTP TRACE Enabled", "TRACE http://h/a", "http://h/a"),
	}
	got, collapsed := dedupeHostPropertyFindings(rows)
	if len(got) != 2 || collapsed != 0 {
		t.Fatalf("got %d rows, collapsed %d, want 2 and 0", len(got), collapsed)
	}
}

// Parameter-level findings are never collapsed, even when two pages happen to
// produce the same title. Their endpoint is part of the finding.
func TestDedupeHostPropertyFindingsLeavesParamModulesAlone(t *testing.T) {
	rows := []Finding{
		hostRow("sqli", "SQL Injection", "title='", "http://h/a"),
		hostRow("sqli", "SQL Injection", "title='", "http://h/b"),
	}
	got, collapsed := dedupeHostPropertyFindings(rows)
	if len(got) != 2 || collapsed != 0 {
		t.Fatalf("got %d rows, collapsed %d, want 2 and 0", len(got), collapsed)
	}
}
