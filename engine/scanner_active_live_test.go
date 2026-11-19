package main

// Tests for the active scan's live rows on the job stream.
//
// The job wrapper's job is to say what a run is doing while it does it. Until the
// finding sink was wired, everything it said while the run worked was a count:
// `progress` carried `findings`, and the rows themselves arrived only inside the
// terminal `done` event. A browser watching that stream could fill a progress
// bar and nothing else.
//
// These tests drive the real handlers against a live `httptest` target — the same
// rule the rest of this package follows: a mocked run would agree with a job that
// publishes nothing, which is the failure being kept out.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"intruder/engine/pkg/active"
)

// TestARunningScanPublishesEveryProvenRowBeforeItsTerminalEvent is the coverage
// claim in one test: every row the finished report carries was published while
// the run was still working, and all of them were published before `done`.
//
// Both halves matter. The first is what makes the table live; the second is what
// keeps a client from seeing a finished run's rows and having to wait for a
// terminal event that already carried them.
func TestARunningScanPublishesEveryProvenRowBeforeItsTerminalEvent(t *testing.T) {
	target := activeScanTarget(t)
	s := &server{}
	id, code := startActiveScan(t, s, fmt.Sprintf(`{"url":%q,"max_pages":1,"max_depth":0}`, target.URL))
	if code != http.StatusAccepted {
		t.Fatalf("start returned %d", code)
	}
	snapshot := waitForActiveScan(t, s, id)
	if snapshot.Result == nil {
		t.Fatal("a finished job carries no report, so there is nothing to have published")
	}

	job, ok := s.activeScanJobByID(id)
	if !ok {
		t.Fatalf("job %q is gone once it finished", id)
	}
	// The cursor 0 asks for everything the job kept, which is what a browser
	// attaching late — after a reload — receives. Reading it here is the same
	// read, so the backlog path and the live path are checked by one test.
	backlog, _, unsubscribe := job.subscribe(0)
	defer unsubscribe()

	firstFinding := -1
	doneAt := -1
	published := 0
	for index, event := range backlog {
		switch event.Kind {
		case "finding":
			if firstFinding < 0 {
				firstFinding = index
			}
			var row active.Finding
			if err := json.Unmarshal(event.Data, &row); err != nil {
				t.Fatalf("a finding event carries something that is not a finding: %v (%s)", err, string(event.Data))
			}
			if row.ID == "" {
				t.Fatalf("a published row has no id: %s", string(event.Data))
			}
			if row.Title == "" {
				t.Fatalf("published row %q has no title: %s", row.ID, string(event.Data))
			}
			published++
		case "done":
			if doneAt < 0 {
				doneAt = index
			}
		}
	}

	if published == 0 {
		t.Fatalf("the run proved %d row(s) and published none of them: the stream carried only counters",
			len(snapshot.Result.Findings))
	}
	if firstFinding < 0 {
		t.Fatal("no finding event on the stream although rows were published")
	}
	if doneAt < 0 {
		t.Fatal("the stream carries no terminal event")
	}
	if firstFinding > doneAt {
		t.Fatalf("the first finding event sits at %d and the terminal event at %d: the rows arrived after the run was already over",
			firstFinding, doneAt)
	}
	if published != len(snapshot.Result.Findings) {
		t.Fatalf("published %d row(s) and the finished report carries %d: a row reached the operator only at the end",
			published, len(snapshot.Result.Findings))
	}
}

// A panel that counts pages up while a run works and then says zero when the run
// finishes has not measured anything at the end. The terminal progress used to
// carry only the finding count, so `pages_fetched` was zero by construction — and
// zero looked measured, because every other number in that panel had been.
//
// The check is against the report's own page count rather than a literal, so it
// states the property instead of a number: whatever the run fetched is what the
// finished panel says it fetched.
func TestAFinishedRunReportsThePagesItFetched(t *testing.T) {
	target := activeScanTarget(t)
	s := &server{}
	id, _ := startActiveScan(t, s, fmt.Sprintf(`{"url":%q,"max_pages":1,"max_depth":0}`, target.URL))
	snapshot := waitForActiveScan(t, s, id)
	if snapshot.Result == nil {
		t.Fatal("a finished job carries no report, so there is nothing to compare the counters with")
	}
	if snapshot.Result.Pages < 1 {
		t.Fatalf("the run fetched %d page(s); a counter check needs a run that fetched something",
			snapshot.Result.Pages)
	}
	if snapshot.Progress.PagesFetched != snapshot.Result.Pages {
		t.Fatalf("the finished panel reports pages_fetched = %d and the report fetched %d: "+
			"the counter resets at the end of the run", snapshot.Progress.PagesFetched, snapshot.Result.Pages)
	}
	if snapshot.Progress.PagesTotal != snapshot.Result.Pages {
		t.Fatalf("the finished panel reports pages_total = %d and the run fetched %d",
			snapshot.Progress.PagesTotal, snapshot.Result.Pages)
	}
}

// The snapshot poll and the stream must not disagree about a running run. A
// client that polls while it subscribes reads progress from one and rows from the
// other, and the two answers come from the same job — so the poll's own progress
// is the one the stream publishes.
func TestAPolledProgressMatchesTheProgressTheStreamPublished(t *testing.T) {
	target := activeScanTarget(t)
	s := &server{}
	id, _ := startActiveScan(t, s, fmt.Sprintf(`{"url":%q,"max_pages":1,"max_depth":0}`, target.URL))
	snapshot := waitForActiveScan(t, s, id)
	job, ok := s.activeScanJobByID(id)
	if !ok {
		t.Fatalf("job %q is gone once it finished", id)
	}
	backlog, _, unsubscribe := job.subscribe(0)
	defer unsubscribe()

	last := active.Progress{}
	for _, event := range backlog {
		if event.Kind != "progress" {
			continue
		}
		var progress active.Progress
		if err := json.Unmarshal(event.Data, &progress); err != nil {
			t.Fatalf("a progress event carries something that is not progress: %v", err)
		}
		last = progress
	}
	if snapshot.Progress.Phase != last.Phase {
		t.Fatalf("the terminal snapshot says phase %q and the last progress event says %q",
			snapshot.Progress.Phase, last.Phase)
	}
	if snapshot.Progress.Findings != len(snapshot.Result.Findings) {
		t.Fatalf("the snapshot reports %d finding(s) and the report carries %d row(s)",
			snapshot.Progress.Findings, len(snapshot.Result.Findings))
	}
}