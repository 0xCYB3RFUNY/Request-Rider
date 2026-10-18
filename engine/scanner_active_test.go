package main

// Tests for the active-scan job wrapper.
//
// They drive the real handlers against a live `httptest` target rather than a
// mocked scan: the job's whole responsibility is the wiring between HTTP, the
// registry and `pkg/active`, and a mocked scan would leave exactly that wiring
// untested. The target is a local server, so a run makes no request the test
// cannot see and the engine's own source-IP lookup stays off (`lookupSourceIP`
// returns early on a server with no transport, which is what `&server{}` is).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"intruder/engine/pkg/active"
)

// activeScanTarget is a page with one injectable surface and one link, so a run
// has something to harvest without having to crawl a site to find out.
func activeScanTarget(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if id := r.URL.Query().Get("id"); id != "" {
			fmt.Fprintf(w, "<html><body><h1>item %s</h1></body></html>", id)
			return
		}
		fmt.Fprint(w, `<html><body>`+
			`<form action="/item" method="get"><input name="id"></form>`+
			`<a href="/item?id=1">item</a>`+
			`</body></html>`)
	}))
	t.Cleanup(server.Close)
	return server
}

// startActiveScan posts a run the way the gateway does and returns the job id.
func startActiveScan(t *testing.T, s *server, body string) (string, int) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/proxy/scanner/active/jobs", strings.NewReader(body))
	s.scannerActiveScan(recorder, request)
	if recorder.Code != http.StatusAccepted {
		return "", recorder.Code
	}
	var started struct {
		JobID string `json:"job_id"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &started); err != nil {
		t.Fatalf("the start answer is not JSON: %v (%s)", err, recorder.Body.String())
	}
	return started.JobID, recorder.Code
}

// waitForActiveScan blocks until the job reaches a terminal state.
func waitForActiveScan(t *testing.T, s *server, id string) activeScanSnapshot {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		job, ok := s.activeScanJobByID(id)
		if !ok {
			t.Fatalf("job %q disappeared while it was running", id)
		}
		if job.finished() {
			return job.snapshot()
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("job %q did not finish within the deadline", id)
	return activeScanSnapshot{}
}

// A finished run must be readable afterwards, with the report attached. A run
// that only reported progress would leave the browser with a number and no
// evidence, which is the one thing a scanner must not do.
func TestAFinishedActiveScanKeepsItsReport(t *testing.T) {
	target := activeScanTarget(t)
	s := &server{}
	id, code := startActiveScan(t, s, fmt.Sprintf(`{"url":%q,"max_pages":1,"max_depth":0}`, target.URL))
	if code != http.StatusAccepted {
		t.Fatalf("start returned %d", code)
	}
	if id == "" {
		t.Fatal("start returned no job_id")
	}
	snapshot := waitForActiveScan(t, s, id)
	if snapshot.State != activeJobCompleted {
		t.Fatalf("state = %q, want %q (error %q)", snapshot.State, activeJobCompleted, snapshot.Error)
	}
	if snapshot.Result == nil {
		t.Fatal("a completed job carries no report")
	}
	if !strings.HasPrefix(snapshot.Result.Target, target.URL) {
		t.Fatalf("report target = %q, want the requested %q", snapshot.Result.Target, target.URL)
	}
	if snapshot.Progress.PointsTotal < 0 {
		t.Fatalf("a finished run reports points_total = %d; -1 means the run ended without a total", snapshot.Progress.PointsTotal)
	}
}

// The stream has to report the run as it happens, not replay it once at the
// end: the terminal event carries the report, and progress events precede it.
func TestTheActiveScanStreamReportsProgressAndThenTheReport(t *testing.T) {
	target := activeScanTarget(t)
	s := &server{}
	id, _ := startActiveScan(t, s, fmt.Sprintf(`{"url":%q,"max_pages":1,"max_depth":0}`, target.URL))
	waitForActiveScan(t, s, id)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/proxy/scanner/active/jobs/"+id+"/stream", nil)
	s.scannerActiveJobStatus(recorder, request)
	body := recorder.Body.String()

	if recorder.Code != http.StatusOK {
		t.Fatalf("stream returned %d", recorder.Code)
	}
	if !strings.Contains(body, "event: progress") {
		t.Fatalf("the stream carried no progress event:\n%s", body)
	}
	if !strings.Contains(body, "event: done") {
		t.Fatalf("the stream never ended with a done event:\n%s", body)
	}
	if strings.Index(body, "event: progress") > strings.Index(body, "event: done") {
		t.Fatal("a progress event arrived after the terminal one")
	}
	if !strings.Contains(body, `"job_id":"`+id+`"`) {
		t.Fatalf("the terminal event does not name the job:\n%s", body)
	}
}

// A browser that reloads resumes from the last id it saw. Replaying the whole
// run would duplicate rows, so the cursor has to be honoured.
func TestReconnectingToTheActiveScanStreamSkipsEventsAlreadySeen(t *testing.T) {
	job := &activeScanJob{id: "active-1", waiters: map[chan struct{}]struct{}{}}
	job.publish("progress", active.Progress{Phase: "crawling"})
	job.publish("progress", active.Progress{Phase: "probing"})
	job.publish("done", map[string]string{"job_id": job.id})

	if got := len(job.eventsSince(0)); got != 3 {
		t.Fatalf("eventsSince(0) returned %d events, want 3", got)
	}
	if got := len(job.eventsSince(2)); got != 1 {
		t.Fatalf("eventsSince(2) returned %d events, want only the last one", got)
	}
	if first := job.eventsSince(2)[0]; first.ID != 3 {
		t.Fatalf("the first unread event has id %d, want 3", first.ID)
	}
}

// A terminal state must not become readable before the run has settled.
//
// This is the invariant the stream's exit condition and the poll both depend on:
// `finished()` is what tells a stream it may stop, and a state of "completed"
// without a report is the one answer a scanner must never give. It is asserted
// here on the two calls themselves rather than on a running scan, because a race
// observed through a live run is not a test — it passes or fails by timing, and a
// test that survives the regression it exists for is worse than no test.
func TestATerminalStateIsNotReadableBeforeTheRunSettles(t *testing.T) {
	job := &activeScanJob{id: "active-1", waiters: map[chan struct{}]struct{}{}}

	job.setState(activeJobCompleted)
	if job.finished() {
		t.Fatal("a job read as finished while its report had not been published yet")
	}

	job.publish("done", activeScanSnapshot{ID: job.id, State: activeJobCompleted})
	job.settle()
	if !job.finished() {
		t.Fatal("a settled terminal job does not read as finished")
	}

	// A cancelled run settles without a report, because there is nothing to
	// deliver. It must still end a stream rather than leave it waiting.
	cancelled := &activeScanJob{id: "active-2", waiters: map[chan struct{}]struct{}{}}
	cancelled.setState(activeJobCancelled)
	if cancelled.finished() {
		t.Fatal("a cancelled job read as finished before it settled")
	}
	cancelled.settle()
	if !cancelled.finished() {
		t.Fatal("a cancelled job that settled still reads as running")
	}
}

// The terminal event has to carry the report, not only say the run ended.
func TestTheTerminalEventCarriesTheReport(t *testing.T) {
	job := &activeScanJob{id: "active-1", waiters: map[chan struct{}]struct{}{}}
	report := &active.Report{Target: "http://target.test/", Findings: []active.Finding{{ID: "VXR-1"}}}
	job.publish("done", activeScanSnapshot{ID: job.id, State: activeJobCompleted, Result: report})

	events := job.eventsSince(0)
	if len(events) != 1 || events[0].Kind != "done" {
		t.Fatalf("expected one done event, got %+v", events)
	}
	var payload activeScanSnapshot
	if err := json.Unmarshal(events[0].Data, &payload); err != nil {
		t.Fatalf("the terminal event is not decodable: %v", err)
	}
	if payload.Result == nil || len(payload.Result.Findings) != 1 {
		t.Fatalf("the terminal event carries no findings: %s", events[0].Data)
	}
}

// Cancel has to stop a run that is still working, and a second cancel has to
// say so rather than reporting a stop that never happened.
func TestCancellingARunningActiveScanStopsItOnlyOnce(t *testing.T) {
	release := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form action="/item" method="get"><input name="id"></form></body></html>`)
	}))
	defer target.Close()
	defer close(release)

	s := &server{}
	id, _ := startActiveScan(t, s, fmt.Sprintf(`{"url":%q,"max_pages":1,"max_depth":0}`, target.URL))

	if !s.cancelActiveScanJob(id) {
		t.Fatal("cancelling a queued run reported that there was nothing to stop")
	}
	if s.cancelActiveScanJob(id) {
		t.Fatal("a second cancel reported a stop that did not happen")
	}
	snapshot := waitForActiveScan(t, s, id)
	if snapshot.State != activeJobCancelled {
		t.Fatalf("state = %q, want %q", snapshot.State, activeJobCancelled)
	}
}

// A target that is not an absolute http URL is refused before a job exists,
// because a job that can never succeed is worse than a 400 that names why.
func TestTheActiveScanRefusesATargetThatIsNotAbsolute(t *testing.T) {
	for _, body := range []string{`{"url":"/relative"}`, `{"url":"ftp://example.test/"}`, `{"url":""}`} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/proxy/scanner/active/jobs", strings.NewReader(body))
		(&server{}).scannerActiveScan(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("body %s returned %d, want 400", body, recorder.Code)
		}
	}
}

// An unknown identifier is a 404 that says so. Reporting it as "running" would
// leave a panel spinning against a job that no longer exists.
func TestAnUnknownActiveScanJobIsNotFound(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/proxy/scanner/active/jobs/active-404", nil)
	(&server{}).scannerActiveJobStatus(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "UNKNOWN_JOB") {
		t.Fatalf("the 404 does not name its reason: %s", recorder.Body.String())
	}
}

// The finished-run window is the project's, not a private timer: a finished
// scan is released by the same sweep as every other job, and a running one is
// never released whatever its age.
func TestTheSharedRetentionSweepReleasesOnlyFinishedActiveScans(t *testing.T) {
	now := time.Now()
	finished := &activeScanJob{id: "active-old", waiters: map[chan struct{}]struct{}{}}
	finished.setState(activeJobCompleted)
	finished.mu.Lock()
	finished.finishedAt = now.Add(-2 * defaultFinishedJobRetention)
	finished.report = &active.Report{Target: "http://target.test/"}
	finished.mu.Unlock()

	running := &activeScanJob{id: "active-running", waiters: map[chan struct{}]struct{}{}}
	running.setState(activeJobRunning)

	s := &server{activeScans: map[string]*activeScanJob{
		finished.id: finished, running.id: running,
	}}
	s.sweepFinishedJobs(now)

	if _, ok := s.activeScans[finished.id]; ok {
		t.Fatal("a finished scan older than the window survived the sweep")
	}
	if _, ok := s.activeScans[running.id]; !ok {
		t.Fatal("the sweep released a running scan")
	}
	// The evidence goes with the job: a released job that kept its report would
	// be the leak the sweep exists to prevent.
	finished.mu.RLock()
	defer finished.mu.RUnlock()
	if finished.report != nil {
		t.Fatal("a released scan still holds its report")
	}
}

// A queued run must report an unknown total, not a zero. "0 of 0 pages" reads
// as a finished run with nothing to report.
func TestAQueuedActiveScanReportsNoTotalsRatherThanZero(t *testing.T) {
	job, err := (&server{}).startActiveScanJob(context.Background(), activeScanInput{URL: "http://127.0.0.1:1/"})
	if err != nil {
		t.Fatalf("a run that cannot connect must still start: %v", err)
	}
	defer (&server{}).cancelActiveScanJob(job.id)
	snapshot := job.snapshot()
	if snapshot.Progress.PagesTotal != -1 || snapshot.Progress.PointsTotal != -1 {
		t.Fatalf("a queued run reported totals %d/%d, want -1/-1",
			snapshot.Progress.PagesTotal, snapshot.Progress.PointsTotal)
	}
}
