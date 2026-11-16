package main

// Tests for the detail a vulnerable-library finding carries.
//
// The operator asked for it with a report in hand: the exported map of ria.ru
// carried six findings for the very same library and every one of them read the
// same way —
//
//	jquery · 1.12.4 · medium · виправлено в 2.2.0
//	jquery · 1.12.4 · low · виправлено в 2.999.999
//	jquery · 1.12.4 · medium · виправлено в 3.0.0-beta1
//
// Six lines that differ only in a version number and a severity word, and not one
// of them says *what* the vulnerability is. Measured on the operator's two
// exported reports, 2026-10-04: `CWE`, `CVE` and `GHSA` appear zero times in
// both.
//
// Two separate causes, and neither is visible in the other:
//
//  1. The engine dropped the identifiers before the record left Go. The
//     `retirejsVulnerability` struct parses `githubID`, `URL`, `reference` and
//     `info` out of the upstream database and then copies none of them into
//     `retirejsVulnerableLibrary`, so the advisory link and the GitHub advisory
//     id could never reach the report even in principle.
//
//  2. The three fields that *were* copied were serialised with the wrong case.
//     `CVE`, `CWE` and `Summary` carry no json tag, so Go writes `"CVE"`,
//     `"CWE"` and `"Summary"`, and the client reads `entry.cve`, `entry.cwe`
//     and `entry.summary`. Verified against a live engine, not inferred:
//     `POST /proxy/target-js` on ria.ru's `jquery-1.12.4.min.js` answered with
//     `{"CVE": "", "CWE": ["CWE-79"], "Summary": "parseHTML() executes scripts
//     in event handlers", …}` while the export read three `undefined` fields and
//     printed none of them. A summary that is present in the record and missing
//     from the report is the worst of the two, because the data is there.
//
// The tests below are written so that each of the two causes turns one of them
// red on its own.

import (
	"encoding/json"
	"strings"
	"testing"
)

// fixtureJQuery17 carries a version the upstream database has full records for.
var fixtureJQuery17 = []byte("/*! jQuery v1.7.2 */\njQuery.fn.jquery = '1.7.2';\n")

// TestTheRecordCarriesTheAdvisoryIdentifiers is cause 1: the engine kept only a
// name, a version, a severity and a fix version.
func TestTheRecordCarriesTheAdvisoryIdentifiers(t *testing.T) {
	found := retirejsDetect("https://cdn.test/jquery-1.7.2.min.js", "jquery-1.7.2.min.js", fixtureJQuery17)
	if len(found) == 0 {
		t.Fatal("the fixture names jQuery 1.7.2 and nothing was reported")
	}
	// At least one record for a 2009-era release has to carry a GitHub advisory
	// id, and that id is what an analyst pastes into a tracker.
	withGHSA := 0
	withCVE := 0
	withCWE := 0
	withSummary := 0
	for _, entry := range found {
		if strings.TrimSpace(entry.GitHubID) != "" {
			withGHSA++
		}
		if strings.TrimSpace(entry.CVE) != "" {
			withCVE++
		}
		if len(entry.CWE) > 0 {
			withCWE++
		}
		if strings.TrimSpace(entry.Summary) != "" {
			withSummary++
		}
	}
	if withGHSA == 0 {
		t.Errorf("no record carries a GitHub advisory id, so no finding can be looked up: %+v", found[0])
	}
	if withCVE == 0 {
		t.Errorf("no record carries a CVE for a release from 2009: %+v", found[0])
	}
	if withCWE == 0 {
		t.Errorf("no record carries a CWE: %+v", found[0])
	}
	if withSummary == 0 {
		t.Errorf("no record carries a summary: %+v", found[0])
	}
}

// TestTheRecordCarriesSomethingToRead is the same half stated the way the operator
// asked for it: two records for one library must not read identically.
func TestTheRecordCarriesSomethingToRead(t *testing.T) {
	found := retirejsDetect("https://cdn.test/jquery-1.7.2.min.js", "jquery-1.7.2.min.js", fixtureJQuery17)
	seen := map[string]bool{}
	for _, entry := range found {
		line := entry.Library + " · " + entry.Version + " · " + entry.Severity + " · " + entry.Below
		if seen[line] {
			t.Errorf("two findings read identically, so nothing distinguishes them: %q", line)
		}
		seen[line] = true
	}
	if len(found) < 2 {
		t.Fatalf("expected several findings for jQuery 1.7.2, got %d", len(found))
	}
}

// TestTheIdentifiersAreSerialisedInLowercase is cause 2, and it is the one that
// silently costs the summary.
//
// The three fields used to carry no json tag, so the wire form was `"CVE"`,
// `"CWE"` and `"Summary"` while the client read `cve`, `cwe` and `summary`. This
// asserts the wire form itself rather than any client's behaviour, because the
// client is a second file and can be changed without this one noticing.
func TestTheIdentifiersAreSerialisedInLowercase(t *testing.T) {
	found := retirejsDetect("https://cdn.test/jquery-1.7.2.min.js", "jquery-1.7.2.min.js", fixtureJQuery17)
	if len(found) == 0 {
		t.Fatal("the fixture names jQuery 1.7.2 and nothing was reported")
	}
	encoded, err := json.Marshal(found[0])
	if err != nil {
		t.Fatalf("the record does not serialise: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("the serialised record is not an object: %v", err)
	}
	// The keys that carry data are required. `references` is deliberately not
	// among them: it is `omitempty`, and the upstream snapshot populates
	// `identifiers.reference` zero times out of 750 records, so requiring the key
	// would be requiring a field that is empty by construction. `info` is the one
	// that carries links, and it is required here.
	for _, key := range []string{"cve", "cwe", "summary", "github_id", "info"} {
		if _, ok := wire[key]; !ok {
			t.Errorf("the wire form has no %q key, so no client can read it: %s", key, encoded)
		}
	}
	// And the old capitalised spellings must be gone, not merely supplemented:
	// leaving both would mean a client reading the old one keeps seeing nothing
	// and nobody would know which is authoritative.
	for _, key := range []string{"CVE", "CWE", "Summary"} {
		if _, ok := wire[key]; ok {
			t.Errorf("the wire form still carries the capitalised %q key: %s", key, encoded)
		}
	}
}

// TestTheFindingsCarryIdentifiersAnAnalystCanLookUp is the property the operator
// asked for in one assertion: a finding that cannot be named cannot be looked
// up, and a scanner that says "medium" without saying what for is stating a
// mood.
//
// Measured over the vendored database: 77% of records carry a CVE and 80% carry
// a GitHub advisory id, so "some identifier" is the normal case and its absence
// is what has to be noticed.
func TestTheFindingsCarryIdentifiersAnAnalystCanLookUp(t *testing.T) {
	found := retirejsDetect("https://cdn.test/jquery-1.7.2.min.js", "jquery-1.7.2.min.js", fixtureJQuery17)
	named, anonymous := 0, 0
	for _, entry := range found {
		if strings.TrimSpace(entry.CVE) != "" || strings.TrimSpace(entry.GitHubID) != "" {
			named++
		} else {
			anonymous++
		}
	}
	if named == 0 {
		t.Fatalf("no finding names the vulnerability it reports: %+v", found[0])
	}
	// An unnamed finding is allowed — upstream has records without either id —
	// but it has to be rare enough that the report can rely on the name.
	if anonymous*4 > len(found) {
		t.Errorf("%d of %d findings name no CVE and no advisory id, so the report cannot identify them",
			anonymous, len(found))
	}
}

// TestTheSummaryNamesTheProblem pins the one field that turns "medium" into a
// sentence an analyst can act on.
func TestTheSummaryNamesTheProblem(t *testing.T) {
	found := retirejsDetect("https://cdn.test/jquery-1.7.2.min.js", "jquery-1.7.2.min.js", fixtureJQuery17)
	longest := ""
	for _, entry := range found {
		if len(entry.Summary) > len(longest) {
			longest = entry.Summary
		}
	}
	if len(longest) < 20 {
		t.Errorf("the longest summary across %d findings is %q, which names nothing", len(found), longest)
	}
}

// TestTheReferenceLinksAreCarried proves the record points somewhere. An advisory
// id with no link is still a lookup the analyst has to search for; a link is the
// difference between a finding and a task.
//
// Which field carries the link was measured over the whole vendored database
// rather than assumed, and the answer is not the one the struct suggests. Across
// all 750 records: `CVE` 583 (77%), `githubID` 602 (80%), `info` 749 (99%), and
// `identifiers.URL` and `identifiers.reference` **0 (0%)** — the upstream
// snapshot writes every link into `info` and leaves those two empty. So the
// assertion is on "something an analyst can open", which is the property the
// report needs, and not on a field name.
func TestTheReferenceLinksAreCarried(t *testing.T) {
	found := retirejsDetect("https://cdn.test/jquery-1.7.2.min.js", "jquery-1.7.2.min.js", fixtureJQuery17)
	links := 0
	for _, entry := range found {
		if strings.TrimSpace(entry.URL) != "" {
			links++
		}
		for _, reference := range append(append([]string{}, entry.References...), entry.Info...) {
			if strings.Contains(reference, "http") {
				links++
			}
		}
	}
	if links == 0 {
		t.Errorf("no finding carries a link to its advisory: %+v", found[0])
	}
}
