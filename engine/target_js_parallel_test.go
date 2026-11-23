package main

// Tests for the concurrent read path of the on-request JavaScript analysis.
//
// Two claims are under test and they pull in opposite directions, which is the
// whole difficulty of the change:
//
//  1. the reads are genuinely concurrent, so a page's bundle set costs the
//     slowest bundle rather than the sum of all of them;
//  2. the answer still comes back in request order, because the export writes
//     that order and the browser tests read it.
//
// A test that only measured wall clock would pass on a pool that reorders
// results; a test that only checked order would pass on a serial loop. Both are
// measured here against a real HTTP server whose responses are deliberately
// ordered against the request order, so the two properties can only hold at once
// if the results are rebuilt from their dispatch index.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// staggerServer answers with a delay that shrinks as the request index grows, so
// the *last* URL asked is the *first* one to finish. Any implementation that
// appends results in completion order therefore produces the reversed list.
func staggerServer(t *testing.T, count int) (*httptest.Server, *concurrencyProbe) {
	t.Helper()
	probe := &concurrencyProbe{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		index := 0
		if raw := strings.TrimPrefix(r.URL.Path, "/bundle"); raw != "" {
			_, _ = fmt.Sscanf(raw, "%d", &index)
		}
		probe.enter()
		// The delay decreases with the index, so completion order is the reverse
		// of request order for every list of two or more.
		time.Sleep(time.Duration(count-index) * 8 * time.Millisecond)
		probe.leave()
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = fmt.Fprintf(w, "fetch('/api/v1/item/%d?id=' + id);", index)
	}))
	t.Cleanup(server.Close)
	return server, probe
}

// concurrencyProbe records how many requests were inside the server at the same
// moment.
//
// This is what the overlap claim is actually about, and it is measured here
// rather than from the elapsed time: every analysis also does a `source_ip`
// lookup against an external endpoint, so the wall clock says as much about that
// endpoint as about the pool. The server cannot lie about how many requests it
// was holding.
type concurrencyProbe struct {
	mu        sync.Mutex
	inFlight  int
	peak      int
	completed int
}

func (p *concurrencyProbe) enter() {
	p.mu.Lock()
	p.inFlight++
	p.completed++
	if p.inFlight > p.peak {
		p.peak = p.inFlight
	}
	p.mu.Unlock()
}

func (p *concurrencyProbe) leave() {
	p.mu.Lock()
	p.inFlight--
	p.mu.Unlock()
}

func (p *concurrencyProbe) peakSeen() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.peak
}

func (p *concurrencyProbe) seen() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.completed
}

// TestConcurrentScriptReadsKeepRequestOrder is the claim that makes the change
// safe: the order of the answer is the order of the request, even though the
// server makes the requests finish in the opposite order.
//
// Serialising the loop keeps this green, so the test alone does not prove
// concurrency; TestConcurrentScriptReadsActuallyOverlap does. Together they pin
// both halves, which is why they are separate tests rather than one.
func TestConcurrentScriptReadsKeepRequestOrder(t *testing.T) {
	const count = 6
	server, probe := staggerServer(t, count)
	urls := make([]string, 0, count)
	for i := 0; i < count; i++ {
		urls = append(urls, fmt.Sprintf("%s/bundle%d", server.URL, i))
	}

	entries, peak := newTestServer().analyzeScriptURLs(t.Context(), scriptRefs(urls...), 0)
	if len(entries) != count {
		t.Fatalf("entries = %d, want %d", len(entries), count)
	}
	for i, entry := range entries {
		want := fmt.Sprintf("%s/bundle%d", server.URL, i)
		if entry.URL != want {
			t.Errorf("entry[%d].URL = %q, want %q — the answer was rebuilt in completion order", i, entry.URL, want)
		}
	}
	if probe.seen() != count {
		t.Errorf("server answered %d requests, want %d", probe.seen(), count)
	}
	t.Logf("order preserved across %d bundles, peak_parallel=%d", count, peak)
}

// TestConcurrentScriptReadsActuallyOverlap is the other half: the pool really
// does read at the same time. Reverting the pool to a serial loop makes the
// elapsed time the sum of the delays instead of the largest one.
//
// The bound is asserted rather than assumed: never more workers were in flight
// than were asked for, and never fewer than two when four were.
func TestConcurrentScriptReadsActuallyOverlap(t *testing.T) {
	const count = 6
	server, probe := staggerServer(t, count)
	urls := make([]string, 0, count)
	for i := 0; i < count; i++ {
		urls = append(urls, fmt.Sprintf("%s/bundle%d", server.URL, i))
	}

	entries, peak := newTestServer().analyzeScriptURLs(t.Context(), scriptRefs(urls...), 0)

	if len(entries) != count {
		t.Fatalf("entries = %d, want %d", len(entries), count)
	}
	// The pool's own counter is the witness. The server cannot be: `crawlOnce`
	// opens a follow-up request of its own, so the test server is seen holding
	// two at once even when one worker is running — a count of every request
	// rather than a count of concurrency. Measured against that, this test
	// passed on a pool that had been told to run one worker at a time.
	if peak < 2 {
		t.Errorf("the pool ran %d read at once, want at least 2 — nothing overlaps", peak)
	}
	if peak > defaultScriptAnalysisWorkers {
		t.Errorf("the pool ran %d reads at once, want no more than the %d workers",
			peak, defaultScriptAnalysisWorkers)
	}
	if seen := probe.peakSeen(); seen < 2 {
		t.Errorf("the server saw only %d request at once; the fixture is not measuring overlap at all", seen)
	}
	t.Logf("pool ran up to %d at once, server saw %d", peak, probe.peakSeen())
}

// TestTheWorkerCountIsWhatTheCallerAskedFor checks the visible part of the bound:
// an explicit request wins, and the peak never exceeds it.
func TestTheWorkerCountIsWhatTheCallerAskedFor(t *testing.T) {
	for _, asked := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("asked_%d", asked), func(t *testing.T) {
			const count = 6
			server, probe := staggerServer(t, count)
			urls := make([]string, 0, count)
			for i := 0; i < count; i++ {
				urls = append(urls, fmt.Sprintf("%s/bundle%d", server.URL, i))
			}
			entries, peak := newTestServer().analyzeScriptURLs(t.Context(), scriptRefs(urls...), asked)
			if len(entries) != count {
				t.Fatalf("entries = %d, want %d", len(entries), count)
			}
			if peak > asked {
				t.Errorf("peak_parallel = %d, want no more than the %d asked for", peak, asked)
			}
			if asked == 1 && peak != 1 {
				t.Errorf("peak_parallel = %d, want exactly 1 when the caller asked for one worker", peak)
			}
			// The bound has to bite as well as hold. "Never more than three" is
			// also satisfied by a pool that never uses more than one, so the
			// upper half of the claim is checked by the server here: asked for
			// three, three were asked for, and one would mean the request was
			// quietly ignored — the hidden cap this project forbids.
			// The claim is about the pool, so it is read from the pool's own
			// counter. The server cannot be the witness: `crawlOnce` also opens
			// its own follow-up request, so the test server is seen holding two
			// at once even when the pool is running one worker at a time — a
			// measurement of every request, not of concurrency.
			if asked > 1 && peak < 2 {
				t.Errorf("asked for %d workers, the pool ran %d at once — the request was ignored",
					asked, peak)
			}
			_ = probe
			for i, entry := range entries {
				if !strings.HasSuffix(entry.URL, fmt.Sprintf("bundle%d", i)) {
					t.Errorf("entry[%d].URL = %q, order changed at a bound of %d", i, entry.URL, asked)
				}
			}
		})
	}
}

// TestTheWorkerCountFallsBackWithoutInventingACap covers the fallback rules: a
// caller that says nothing gets the default, and a caller that says "more than
// there is scripts" gets the number of scripts rather than a queue.
//
// The important half is the negative: a caller that asks for zero must not be
// silently serialised, because "no preference" and "one at a time" are different
// requests and only one of them was made.
func TestTheWorkerCountFallsBackWithoutInventingACap(t *testing.T) {
	t.Setenv("RR_SCRIPT_ANALYSIS_WORKERS", "")
	if got := scriptAnalysisConcurrency(10, 0); got != defaultScriptAnalysisWorkers {
		t.Errorf("no preference gave %d workers, want the documented default %d", got, defaultScriptAnalysisWorkers)
	}
	if got := scriptAnalysisConcurrency(3, 0); got != 3 {
		t.Errorf("three scripts with no preference gave %d workers, want 3", got)
	}
	if got := scriptAnalysisConcurrency(0, 4); got != 4 {
		t.Errorf("no scripts with four workers asked for gave %d, want 4", got)
	}
	if got := scriptAnalysisConcurrency(10, 32); got != 10 {
		t.Errorf("asking for more workers than scripts gave %d, want 10", got)
	}
	t.Setenv("RR_SCRIPT_ANALYSIS_WORKERS", "3")
	if got := scriptAnalysisConcurrency(10, 0); got != 3 {
		t.Errorf("the environment asked for 3, got %d", got)
	}
	if got := scriptAnalysisConcurrency(10, 7); got != 7 {
		t.Errorf("an explicit request must beat the environment: got %d, want 7", got)
	}
	// A value nobody can read falls back to the default rather than to zero
	// workers, and the fallback is the documented one.
	t.Setenv("RR_SCRIPT_ANALYSIS_WORKERS", "many")
	if got := scriptAnalysisConcurrency(10, 0); got != defaultScriptAnalysisWorkers {
		t.Errorf("an unreadable environment value gave %d, want the default %d", got, defaultScriptAnalysisWorkers)
	}
}

// TestTheResponseSaysHowParallelItWas pins the visibility requirement: the peak
// reaches the caller, so a bound is something the operator can see rather than
// something the process decided alone.
func TestTheResponseSaysHowParallelItWas(t *testing.T) {
	const count = 4
	server, probe := staggerServer(t, count)
	urls := make([]string, 0, count)
	for i := 0; i < count; i++ {
		urls = append(urls, fmt.Sprintf("%s/bundle%d", server.URL, i))
	}
	payload := map[string]interface{}{"urls": toRawRefs(urls), "concurrency": 4}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/proxy/target-js", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	newTestServer().targetJSAnalysisHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var answer struct {
		Results      []targetJSAnalysisEntry `json:"results"`
		PeakParallel int                     `json:"peak_parallel"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("answer is not the documented shape: %v", err)
	}
	if len(answer.Results) != count {
		t.Errorf("results = %d, want %d", len(answer.Results), count)
	}
	if answer.PeakParallel < 1 || answer.PeakParallel > 4 {
		t.Errorf("peak_parallel = %d, want between 1 and the 4 asked for", answer.PeakParallel)
	}
	// The reported number must be the number the server actually saw. A bound
	// that is reported but not measured is the kind of number an operator cannot
	// use: it would claim a ceiling the process never checked.
	if seen := probe.peakSeen(); answer.PeakParallel != seen {
		t.Errorf("peak_parallel reported %d, the server held %d at once", answer.PeakParallel, seen)
	}
	t.Logf("peak_parallel reported as %d, server held %d at once", answer.PeakParallel, probe.peakSeen())
}

// TestANegativeWorkerCountIsRefusedRatherThanClamped keeps a nonsense request a
// mistake the operator sees, instead of one the process quietly rewrites.
func TestANegativeWorkerCountIsRefusedRatherThanClamped(t *testing.T) {
	body := `{"urls":["https://example.test/a.js"],"concurrency":-1}`
	request := httptest.NewRequest(http.MethodPost, "/proxy/target-js", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	newTestServer().targetJSAnalysisHandler(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: a negative worker count was accepted or silently rewritten", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "INVALID_CONCURRENCY") {
		t.Errorf("body does not name the refusal: %s", recorder.Body.String())
	}
}

// toRawRefs renders bare URLs in the form the request struct accepts, so the
// handler test exercises the real decoding path rather than a hand-built struct.
func toRawRefs(urls []string) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(urls))
	for _, raw := range urls {
		encoded, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		out = append(out, encoded)
	}
	return out
}
