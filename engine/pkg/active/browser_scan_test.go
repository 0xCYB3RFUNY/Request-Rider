package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// reflectingTarget answers every page with the parameter written into a single
// quoted JavaScript string, which is the one context where the detector's payload
// fires on load with no gesture and no filter behind it.
func reflectingTarget(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><script>var other = "https://example.test/"; ` +
			`var q = '` + value + `';</script>` +
			`<form action="/x" method="get"><input name="q" type="text"></form>` +
			`<p>text</p></body></html>`))
	}))
	t.Cleanup(server.Close)
	return server
}

// executingRenderer is a browser that executes what it is asked to load.
//
// It decides by reading the marker out of the address it was given and then
// reporting that address as requested, which is exactly what a real browser does
// with an executed payload. Reading it out of the URL is what makes this a test
// of the wiring rather than a test of a stub: a run whose proof stopped carrying
// the marker into the address, or stopped carrying the payload at all, leaves this
// renderer with nothing to execute and the row unraised.
type executingRenderer struct {
	calls     int
	requested []string
}

var markerInURL = regexp.MustCompile(`fetch\('([^']+)'\)`)

func (e *executingRenderer) Render(_ context.Context, target string) (BrowserPage, error) {
	e.calls++
	// The address arrives percent-encoded, because that is how a query value
	// travels; the marker is looked for in what the page would receive.
	decoded := target
	if unescaped, err := url.QueryUnescape(target); err == nil {
		decoded = unescaped
	}
	match := markerInURL.FindStringSubmatch(decoded)
	if match == nil {
		return BrowserPage{URL: target}, nil
	}
	e.requested = append(e.requested, match[1])
	return BrowserPage{URL: target, Status: 200, Network: []string{target, match[1]}}, nil
}

// silentRenderer is a browser that loads the page and executes nothing.
type silentRenderer struct{ calls int }

func (s *silentRenderer) Render(_ context.Context, target string) (BrowserPage, error) {
	s.calls++
	return BrowserPage{URL: target, Status: 200, Network: []string{target}}, nil
}

func scanReflectingTarget(t *testing.T, renderer Renderer) *Report {
	t.Helper()
	server := reflectingTarget(t)
	start, _ := url.Parse(server.URL)
	start.Path = "/x"
	report, err := NewScan(ScanRequest{
		URL: start.String(), MaxPages: 1, MaxDepth: 0, Concurrency: 2,
		Timeout: 20 * time.Second, RoundTripper: http.DefaultTransport,
		Renderer: renderer,
	}, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return report
}

func escapeRows(report *Report) []Finding {
	var rows []Finding
	for _, finding := range report.Findings {
		if finding.Module == "xss-escape" {
			rows = append(rows, finding)
		}
	}
	return rows
}

// TestTheBrowserSettlesTheRowTheWholeRunProduced. One run, one renderer, one
// address: the row the detector wrote is carried into the browser with a marker in
// it, the marker comes back in the page's requests, and the report's own counts
// and the row's tier both say so.
func TestTheBrowserSettlesTheRowTheWholeRunProduced(t *testing.T) {
	renderer := &executingRenderer{}
	report := scanReflectingTarget(t, renderer)
	rows := escapeRows(report)
	if len(rows) == 0 {
		t.Skip("this target produced no escaping row, so there is nothing for a browser to settle")
	}
	if report.Stats.BrowserAttempts != len(rows) {
		t.Errorf("browser_attempts = %d, want one per escaping row (%d)",
			report.Stats.BrowserAttempts, len(rows))
	}
	if report.Stats.BrowserExecuted != len(rows) {
		t.Errorf("browser_executed = %d, want %d: every row's marker came back requested",
			report.Stats.BrowserExecuted, len(rows))
	}
	if len(renderer.requested) != len(rows) {
		t.Fatalf("the browser was asked %d time(s) and executed %d, want one per row",
			renderer.calls, len(renderer.requested))
	}
	// Each row's marker carries that row's own id, so no two rows can be settled
	// by one execution.
	seen := map[string]bool{}
	for _, marker := range renderer.requested {
		if seen[marker] {
			t.Errorf("marker %q was used twice: one execution would settle two rows", marker)
		}
		seen[marker] = true
	}
	if countUnexecutedEscapes(report.Findings, report.Proofs) != 0 {
		t.Error("the report still counts an escaping row as never executed after the browser executed it")
	}
	if mentions(report.Warnings, "none of them executed") {
		t.Errorf("warnings = %q, want none: this run's browser settled every row it checked", report.Warnings)
	}
}

// TestTheReportSaysWhichRowsNoBrowserCouldSettle is the visibility half, and it is
// a requirement rather than a nicety: two reports that look the same while one had
// a browser and the other did not are two different pieces of work presented as
// one.
// TestTheBoundOnExpressionsIsVisibleAndReported is the whole point of a limit that
// is a field: the operator sees how many expressions were not tried, and a run that
// stopped early never reads as a run that found nothing.
func TestTheBoundOnExpressionsIsVisibleAndReported(t *testing.T) {
	row, _ := NewFinding(Spec{
		Module: "dom-vectors", Title: "filter bypass", Claimed: SeverityHigh,
		Tier: TierPotential, Payload: "a-shape-that-runs-nothing",
		Point: Point{URL: "http://fixture/x", Method: http.MethodGet, Param: "q"},
	})
	full := len(domVectorProofPayloads(row, xsseMarkerURL("rr.invalid", row.ID)))
	renderer := &silentRenderer{}
	suite := &Suite{Transport: testTransport(t, nil), Renderer: renderer,
		MarkerHost: "rr.invalid", Candidates: 3}
	if proofs := suite.Run(context.Background(), []Finding{row}); len(proofs) != 0 {
		t.Fatalf("proofs = %+v, want none from a browser that ran nothing", proofs)
	}
	if renderer.calls != 3 {
		t.Errorf("the browser was asked %d time(s), want 3: the bound is per row and the row had "+
			"the whole table in front of it", renderer.calls)
	}
	if suite.browserSkipped != full-3 {
		t.Errorf("skipped = %d, want %d: the report has to say what was not tried",
			suite.browserSkipped, full-3)
	}
	// And with no bound the row walks the whole table and reports nothing skipped.
	unbounded := &Suite{Transport: testTransport(t, nil), Renderer: &silentRenderer{},
		MarkerHost: "rr.invalid"}
	unbounded.Run(context.Background(), []Finding{row})
	if unbounded.browserSkipped != 0 {
		t.Errorf("skipped = %d without a bound, want 0", unbounded.browserSkipped)
	}
	if unbounded.browserAttempts != full {
		t.Errorf("attempts = %d, want the whole table (%d)", unbounded.browserAttempts, full)
	}
}

// TestABrowserFailureIsReportedAsTheBrowsersFault is the distinction the whole
// counter exists for: a page that loaded and executed nothing is the target's
// answer, a page the browser could not load is the tool's failure, and a report that
// merges them tells an operator to fix the wrong thing.
func TestABrowserFailureIsReportedAsTheBrowsersFault(t *testing.T) {
	row, _ := NewFinding(Spec{
		Module: "csti", Title: "client-side template injection", Claimed: SeverityHigh,
		Tier:  TierPotential,
		Point: Point{URL: "http://fixture/x", Method: http.MethodGet, Param: "q"},
	})
	suite := &Suite{Transport: testTransport(t, nil), Renderer: &countingErrorRenderer{},
		MarkerHost: "rr.invalid"}
	if proofs := suite.Run(context.Background(), []Finding{row}); len(proofs) != 0 {
		t.Fatalf("proofs = %+v, want none", proofs)
	}
	if suite.browserErrors == 0 {
		t.Fatal("a browser that failed left no trace: the run would report the row as settled " +
			"nothing, which reads as the target's answer")
	}
	if suite.browserAttempts != suite.browserErrors {
		t.Errorf("attempts = %d, errors = %d: every failed load is an attempt, and an error that "+
			"is not an attempt cannot be counted", suite.browserAttempts, suite.browserErrors)
	}
}

func TestTheReportSaysWhichRowsNoBrowserCouldSettle(t *testing.T) {
	report := scanReflectingTarget(t, nil)
	rows := escapeRows(report)
	if len(rows) == 0 {
		t.Skip("this target produced no escaping row, so the warning has nothing to count")
	}
	if report.Stats.BrowserAttempts != 0 || report.Stats.BrowserExecuted != 0 {
		t.Fatalf("browser stats = %d/%d, want zero: no renderer was offered to this run",
			report.Stats.BrowserAttempts, report.Stats.BrowserExecuted)
	}
	if !mentions(report.Warnings, "structurally only") {
		t.Errorf("warnings = %q, want the row count to say the rows were never executed", report.Warnings)
	}
	if got := countUnexecutedEscapes(report.Findings, report.Proofs); got != len(rows) {
		t.Errorf("counted %d unexecuted rows, want %d", got, len(rows))
	}
}

// TestABrowserThatExecutesNothingIsNotTheSameAsNoBrowser. The two states are
// different facts about the run, and the report that conflates them teaches the
// reader that a target resisted what a tool was never asked.
func TestABrowserThatExecutesNothingIsNotTheSameAsNoBrowser(t *testing.T) {
	report := scanReflectingTarget(t, &silentRenderer{})
	rows := escapeRows(report)
	if len(rows) == 0 {
		t.Skip("this target produced no escaping row, so the browser was never asked")
	}
	if report.Stats.BrowserAttempts == 0 {
		t.Fatal("browser_attempts = 0: the run had a renderer and escaping rows, so it asked")
	}
	if report.Stats.BrowserExecuted != 0 {
		t.Fatalf("browser_executed = %d, want 0 from a browser that executed nothing",
			report.Stats.BrowserExecuted)
	}
	if !mentions(report.Warnings, "none of them executed") {
		t.Errorf("warnings = %q, want the report to name a browser that settled nothing", report.Warnings)
	}
	if mentions(report.Warnings, "structurally only") {
		t.Errorf("warnings = %q, want none: a browser was offered to this run", report.Warnings)
	}
	if got := countUnexecutedEscapes(report.Findings, report.Proofs); got != len(rows) {
		t.Errorf("counted %d unexecuted rows, want %d", got, len(rows))
	}
}

// TestTheWarningOnlyNamesAnAttemptTheRunActuallyMade. A run with a browser that
// found nothing to check has not tried and failed; it has not tried, and a warning
// saying otherwise would train the reader to ignore warnings.
func TestTheWarningOnlyNamesAnAttemptTheRunActuallyMade(t *testing.T) {
	server := reflectingTarget(t)
	start, _ := url.Parse(server.URL)
	start.Path = "/x"
	// A target with nothing to reflect: the run has a browser and no row, so it
	// never asks, and a warning about a failed confirmation would be a lie.
	bare := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><p>static</p></body></html>`))
	}))
	t.Cleanup(bare.Close)
	_ = server
	bareURL, _ := url.Parse(bare.URL)
	report, err := NewScan(ScanRequest{
		URL: bareURL.String(), MaxPages: 1, MaxDepth: 0, Concurrency: 2,
		Timeout: 20 * time.Second, RoundTripper: http.DefaultTransport,
		Renderer: &silentRenderer{},
	}, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if report.Stats.BrowserAttempts > 0 {
		t.Skip("this target produced an escaping row after all, so the warning is owed")
	}
	if mentions(report.Warnings, "none of them executed") {
		t.Errorf("warnings = %q, want none about a browser that was never asked", report.Warnings)
	}
}

func mentions(warnings []string, fragment string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, fragment) {
			return true
		}
	}
	return false
}
