package active

// Tests for the severity/tier model.
//
// The central claim of this file is negative: a module cannot produce a critical
// finding without evidence. That is a property of the type — Spec has no
// Severity field and NewFinding is the only constructor — and these tests are
// what keep it a property rather than a convention. A test that only checked
// the happy path would pass just as happily against the model this file exists
// to replace.

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func testPoint() Point {
	return Point{
		URL: "http://target.test/item", Method: "GET", Param: "id",
		Values: url.Values{"id": {"1"}},
	}
}

func TestSeverityForCapsTierAtItsCeiling(t *testing.T) {
	cases := []struct {
		tier      Tier
		requested Severity
		want      Severity
		wantCap   bool
	}{
		{TierVerified, SeverityCritical, SeverityCritical, false},
		{TierVerified, SeverityHigh, SeverityHigh, false},
		{TierPotential, SeverityCritical, SeverityMedium, true},
		{TierPotential, SeverityHigh, SeverityMedium, true},
		{TierPotential, SeverityLow, SeverityLow, false},
		{TierPublic, SeverityCritical, SeverityInfo, true},
		{TierPublic, SeverityInfo, SeverityInfo, false},
	}
	for _, tc := range cases {
		got, capped := SeverityFor(tc.tier, tc.requested)
		if got != tc.want || capped != tc.wantCap {
			t.Errorf("SeverityFor(%q, %q) = (%q, %v), want (%q, %v)",
				tc.tier, tc.requested, got, capped, tc.want, tc.wantCap)
		}
	}
}

// An unknown tier is refused rather than defaulted. Defaulting would make a
// typo read as "verified" somewhere upstream, and the table's whole purpose is
// that a finding's weight is earned by an explicitly named tier.
func TestSeverityForRefusesUnknownTier(t *testing.T) {
	got, capped := SeverityFor(Tier("verifed"), SeverityCritical)
	if capped {
		t.Fatal("an unknown tier reported itself as capped; it reported a downgrade that never happened")
	}
	if got != SeverityInfo {
		t.Fatalf("SeverityFor(unknown tier) = %q, want %q", got, SeverityInfo)
	}
}

// The rule the file exists to enforce: a potential finding is capped, so the
// detector's claimed severity never reaches the report unearned.
func TestNewFindingCapsUnverifiedSeverity(t *testing.T) {
	finding, capped := NewFinding(Spec{
		Module: "sqli", Title: "Potential SQL Injection (unverified)",
		Claimed: SeverityCritical, Tier: TierPotential, Point: testPoint(),
		Payload: "'", Evidence: "mysql error fingerprint in body",
	})
	if !capped {
		t.Fatal("capped = false, want true for a potential critical")
	}
	if finding.Severity != SeverityMedium {
		t.Fatalf("severity = %q, want %q", finding.Severity, SeverityMedium)
	}
	if finding.Capped != true {
		t.Error("Capped not reported, so the downgrade would be invisible in the report")
	}
}

// No tier but verified may reach critical. This is the whole mechanism, stated
// as an assertion over every combination so a future edit to the table fails
// here rather than in a report somebody trusts.
func TestOnlyVerifiedTierCanReachHighOrCritical(t *testing.T) {
	for _, tier := range []Tier{TierVerified, TierPotential, TierPublic, Tier("nonsense")} {
		for _, claimed := range []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
			finding, _ := NewFinding(Spec{
				Module: "m", Title: "t", Claimed: claimed, Tier: tier, Point: testPoint(),
			})
			if finding.Severity.atLeast(SeverityHigh) && tier != TierVerified {
				t.Errorf("tier %q produced %q, want at most %q unless verified",
					tier, finding.Severity, SeverityMedium)
			}
		}
	}
}

// The reproduction has to be the request the detector sent, rebuilt from the
// same surface and payload. A triager who cannot rerun the exact bytes cannot
// confirm or dismiss the finding, and will close it.
func TestNewFindingCarriesReproducibleCurl(t *testing.T) {
	point := testPoint()
	finding, _ := NewFinding(Spec{
		Module: "sqli", Title: "t", Claimed: SeverityCritical, Tier: TierVerified,
		Point: point, Payload: "' OR '1'='1",
	})
	if !strings.Contains(finding.PoCCurl, "curl") {
		t.Fatalf("PoCCurl = %q, want a runnable command", finding.PoCCurl)
	}
	if !strings.Contains(finding.PoCCurl, "id=") {
		t.Fatalf("PoCCurl = %q, want the probed parameter", finding.PoCCurl)
	}
	if strings.Contains(finding.PoCCurl, "id=1%20OR") {
		t.Fatalf("PoCCurl = %q, want the payload substituted, not the baseline", finding.PoCCurl)
	}
}

// Two runs over the same defect must produce the same ID, so a run-to-run diff
// shows what changed on the target rather than that the scanner reshuffled.
func TestFindingIDIsStableAcrossRuns(t *testing.T) {
	point := testPoint()
	first, _ := NewFinding(Spec{Module: "sqli", Claimed: SeverityHigh, Tier: TierVerified, Point: point, Payload: "'"})
	for i := 0; i < 50; i++ {
		next, _ := NewFinding(Spec{Module: "sqli", Claimed: SeverityHigh, Tier: TierVerified, Point: point, Payload: "'"})
		if next.ID != first.ID {
			t.Fatalf("run %d ID = %q, want %q", i, next.ID, first.ID)
		}
	}
}

// A different defect must get a different ID, or the diff reports a fix that
// did not happen.
func TestFindingIDDiffersAcrossDistinctDefects(t *testing.T) {
	point := testPoint()
	other := testPoint()
	other.URL = "http://target.test/other"

	base, _ := NewFinding(Spec{Module: "sqli", Claimed: SeverityHigh, Tier: TierVerified, Point: point, Payload: "'"})
	ids := map[string]string{}
	ids["same"] = base.ID

	for name, spec := range map[string]Spec{
		"other payload":  {Module: "sqli", Claimed: SeverityHigh, Tier: TierVerified, Point: point, Payload: "\""},
		"other module":   {Module: "xss", Claimed: SeverityHigh, Tier: TierVerified, Point: point, Payload: "'"},
		"other endpoint": {Module: "sqli", Claimed: SeverityHigh, Tier: TierVerified, Point: other, Payload: "'"},
	} {
		finding, _ := NewFinding(spec)
		if finding.ID == base.ID {
			t.Errorf("%s reused the ID of a different defect", name)
		}
		ids[name] = finding.ID
	}
}

// A version-gated finding must say which version it saw, where that came from,
// and that nobody has established whether the target is patched. Those three
// together are the answer to "the scanner saw it, the exploit did not fire".
func TestVersionGatedFindingRecordsSourceAndPatchState(t *testing.T) {
	finding, _ := NewFinding(Spec{
		Module: "sqli", Title: "SQLi on a versioned component",
		Claimed: SeverityCritical, Tier: TierPotential, Point: testPoint(),
		Version: "5.4.12", VersionSource: "banner:Server",
	})
	if !finding.NeedsVersion() {
		t.Fatal("NeedsVersion() = false, want true")
	}
	if finding.Version != "5.4.12" || finding.VersionSource != "banner:Server" {
		t.Fatalf("version = %q from %q, want 5.4.12 from banner:Server",
			finding.Version, finding.VersionSource)
	}
	if finding.PatchState != UnverifiedPatch {
		t.Fatalf("PatchState = %q, want %q", finding.PatchState, UnverifiedPatch)
	}
}

// A finding that does not depend on a version must not carry the field. An
// empty patch_state on every row would drown the rows where it matters.
func TestFindingWithoutVersionOmitsPatchState(t *testing.T) {
	finding, _ := NewFinding(Spec{
		Module: "xss", Claimed: SeverityHigh, Tier: TierVerified, Point: testPoint(),
	})
	if finding.NeedsVersion() {
		t.Fatal("NeedsVersion() = true, want false")
	}
	if finding.PatchState != "" || finding.Version != "" {
		t.Fatalf("patch state = %q, version = %q, want both empty", finding.PatchState, finding.Version)
	}
}

// Severity must never be compared as a string: "critical" sorts before "high"
// lexically, which is the bug that once left unverified findings at the top of
// a report. The test states the divergence rather than assuming it, so it fails
// if someone ever "simplifies" atLeast into a string comparison.
func TestSeverityOrderDiffersFromLexicalOrder(t *testing.T) {
	if !(Severity("critical") < Severity("high")) {
		t.Fatalf("expected the lexical order to differ; if it no longer does, this guard is stale")
	}
	if !SeverityCritical.atLeast(SeverityHigh) {
		t.Error("critical is not at least high")
	}
	if !SeverityHigh.atLeast(SeverityMedium) {
		t.Error("high is not at least medium")
	}
	if SeverityLow.atLeast(SeverityMedium) {
		t.Error("low is at least medium")
	}
	// An unrecognised severity must land at the bottom rather than anywhere
	// else. Ranking it as info is the safe default; ranking it higher would let
	// a typo in a module's severity constant outrank a real finding.
	if Severity("unknown").atLeast(SeverityLow) {
		t.Error("an unrecognised severity outranks low")
	}
}

func TestSortFindingsOrdersBySeverityThenID(t *testing.T) {
	make_ := func(id string, sev Severity) Finding {
		return Finding{ID: id, Severity: sev}
	}
	findings := []Finding{
		make_("ACT-00000002", SeverityLow),
		make_("ACT-00000001", SeverityCritical),
		make_("ACT-00000003", SeverityHigh),
		make_("ACT-00000001", SeverityCritical),
	}
	SortFindings(findings)
	var got []string
	for _, f := range findings {
		got = append(got, f.ID+":"+string(f.Severity))
	}
	want := []string{"ACT-00000001:critical", "ACT-00000001:critical", "ACT-00000003:high", "ACT-00000002:low"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sorted = %v, want %v", got, want)
	}
}

// Two findings of equal severity must come out in the same order every run, or
// a diff between reports shows reordering instead of what changed.
func TestSortFindingsIsDeterministicForEqualSeverity(t *testing.T) {
	build := func() []Finding {
		return []Finding{
			{ID: "ACT-CCCCCCCC", Severity: SeverityHigh},
			{ID: "ACT-AAAAAAAA", Severity: SeverityHigh},
			{ID: "ACT-BBBBBBBB", Severity: SeverityHigh},
		}
	}
	first := build()
	SortFindings(first)
	want := []string{"ACT-AAAAAAAA", "ACT-BBBBBBBB", "ACT-CCCCCCCC"}
	for run := 0; run < 30; run++ {
		next := build()
		SortFindings(next)
		var got []string
		for _, f := range next {
			got = append(got, f.ID)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d = %v, want %v", run, got, want)
		}
	}
}

func TestCountSummarisesSeverityTierAndCaps(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityCritical, Tier: TierVerified},
		{Severity: SeverityMedium, Tier: TierPotential, Capped: true},
		{Severity: SeverityMedium, Tier: TierPotential, Capped: true},
		{Severity: SeverityInfo, Tier: TierPublic, Capped: true},
	}
	counts := Count(findings)
	if counts.Total != 4 {
		t.Errorf("Total = %d, want 4", counts.Total)
	}
	if counts.BySeverity[SeverityCritical] != 1 {
		t.Errorf("critical = %d, want 1", counts.BySeverity[SeverityCritical])
	}
	if counts.ByTier[TierPotential] != 2 || counts.ByTier[TierVerified] != 1 {
		t.Errorf("by tier = %v, want 2 potential and 1 verified", counts.ByTier)
	}
	if counts.Capped != 3 {
		t.Errorf("Capped = %d, want 3", counts.Capped)
	}
}

// "12 findings" and "12 findings, none proven" are different sentences, and the
// operator should not have to subtract to notice which one applies.
func TestTallyNamesProvenAndDowngraded(t *testing.T) {
	counts := Count([]Finding{
		{Severity: SeverityCritical, Tier: TierVerified},
		{Severity: SeverityMedium, Tier: TierPotential, Capped: true},
	})
	line := counts.Tally()
	for _, fragment := range []string{"total 2", "critical 1", "verified 1", "potential 1", "capped 1"} {
		if !strings.Contains(line, fragment) {
			t.Errorf("Tally() = %q, missing %q", line, fragment)
		}
	}
}
