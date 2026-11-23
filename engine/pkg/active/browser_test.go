package active

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// workerStub is the browser worker's `/target` protocol, served in-process.
//
// It exists so the *client's* half is testable: the shape of the answer, the
// terminal states, and the two ways a wait can end without an answer. What the
// browser then does to a page is not stubbed here — see
// `TestTheBrowserWorkerExecutesTheProofPayload` and
// `TestReDoSReportsATimeoutOnTheLongShape`'s sibling for the live runs, because
// a stub cannot tell an executed script from a reflected one and pretending
// otherwise is how a proof becomes a decoration.
type workerStub struct {
	// statuses is the sequence a polled job reports, one per poll. The last
	// entry repeats, so a test that polls more often than it planned still ends.
	statuses []string
	polls    int
	// network is what the finished job reports the page requested.
	network []string
	// started receives the config the client posted.
	started map[string]any
	// failPost makes the POST itself fail with this status.
	failPost int
	// missingStatus answers the poll without a status at all.
	missingStatus bool
	lastJobID     string
	server        *httptest.Server
}

func newWorkerStub(t *testing.T) *workerStub {
	t.Helper()
	stub := &workerStub{statuses: []string{"completed"}}
	mux := http.NewServeMux()
	mux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		if stub.failPost != 0 {
			w.WriteHeader(stub.failPost)
			_, _ = w.Write([]byte(`{"error":"worker is not accepting jobs"}`))
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&stub.started)
		stub.lastJobID = "job-1"
		stub.write(w, "running")
	})
	mux.HandleFunc("/target/", func(w http.ResponseWriter, r *http.Request) {
		stub.polls++
		status := "completed"
		if stub.missingStatus {
			stub.writeBare(w, map[string]any{"job_id": "job-1"})
			return
		}
		if stub.polls <= len(stub.statuses) {
			status = stub.statuses[stub.polls-1]
		}
		stub.write(w, status)
	})
	stub.server = httptest.NewServer(mux)
	t.Cleanup(stub.server.Close)
	return stub
}

func (s *workerStub) write(w http.ResponseWriter, status string) {
	body := map[string]any{
		"job_id": "job-1",
		"status": status,
		"pages": []any{map[string]any{
			"url":     "http://fixture/x",
			"status":  200,
			"network": s.requestList(),
		}},
	}
	if status == "failed" {
		body["error"] = "browser did not start\nsecond line the reader must not see"
	}
	s.writeBare(w, body)
}

func (s *workerStub) writeBare(w http.ResponseWriter, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func (s *workerStub) requestList() []any {
	out := make([]any, 0, len(s.network))
	for _, url := range s.network {
		out = append(out, map[string]any{"url": url, "method": "GET"})
	}
	return out
}

// TestTheRendererReadsTheWorkersOwnAnswer is the client half: a job is posted,
// polled until it reports a terminal status, and the page's requests come back
// in the worker's order.
func TestTheRendererReadsTheWorkersOwnAnswer(t *testing.T) {
	stub := newWorkerStub(t)
	stub.statuses = []string{"running", "running", "completed"}
	stub.network = []string{"http://fixture/x", "http://rr.invalid/rrxe/abc"}
	renderer := &WorkerRenderer{BaseURL: stub.server.URL, PollInterval: time.Millisecond}
	page, err := renderer.Render(context.Background(), "http://fixture/x?q=1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if page.Status != 200 {
		t.Errorf("status = %d, want 200", page.Status)
	}
	if !page.Requested("http://rr.invalid/rrxe/abc") {
		t.Errorf("network = %v, want the marker request among them", page.Network)
	}
	// The proof has to load the page the operator named, and only that page: a
	// renderer that let the target steer where the browser goes is a renderer an
	// attacker aims.
	if started, _ := stub.started["url"].(string); started != "http://fixture/x?q=1" {
		t.Errorf("worker was sent %q, want the requested url", started)
	}
	// A marker is a URL this run chose, so a match must be exact. A page that
	// merely echoes the payload into a link is the reflection the detector
	// already reports, and accepting it here would report the same evidence twice
	// and call the second one execution.
	if page.Requested("http://fixture/x?q=1") {
		t.Error("a substring match counted as execution: the page itself was accepted as the marker")
	}
}

// TestTheRendererAsksTheWorkerForOnePageAndNoInteraction pins the config the
// proof sends, because it is the difference between a proof and a crawl.
func TestTheRendererAsksTheWorkerForOnePageAndNoInteraction(t *testing.T) {
	stub := newWorkerStub(t)
	renderer := &WorkerRenderer{BaseURL: stub.server.URL, PollInterval: time.Millisecond,
		NavigationTimeout: 7 * time.Second}
	if _, err := renderer.Render(context.Background(), "http://fixture/x"); err != nil {
		t.Fatalf("render: %v", err)
	}
	for name, want := range map[string]any{
		"max_pages":             float64(1),
		"max_depth":             float64(0),
		"auto_interact":         false,
		"anti_detect":           false,
		"navigation_timeout_ms": float64(7000),
	} {
		if got := stub.started[name]; got != want {
			t.Errorf("config[%q] = %v, want %v", name, got, want)
		}
	}
	if _, ok := stub.started["actions"]; !ok {
		t.Error("config carries no actions key: a proof must not drive the page")
	}
}

// TestTheRendererNamesTheWaysAJobCanEndWithoutAnAnswer. A renderer that reports a
// failure as a loaded page turns a dead browser into a silent non-proof, and one
// that polls a snapshot it does not understand until the timeout turns a version
// mismatch into a three-minute wait.
func TestTheRendererNamesTheWaysAJobCanEndWithoutAnAnswer(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*workerStub)
		want  string
	}{
		{"failed job", func(s *workerStub) { s.statuses = []string{"failed"} },
			"browser did not start"},
		{"cancelled job", func(s *workerStub) { s.statuses = []string{"cancelled"} },
			"cancelled"},
		{"statusless snapshot", func(s *workerStub) { s.missingStatus = true },
			"reported no status"},
		{"post refused", func(s *workerStub) { s.failPost = http.StatusServiceUnavailable },
			"worker is not accepting jobs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newWorkerStub(t)
			tc.setup(stub)
			renderer := &WorkerRenderer{BaseURL: stub.server.URL, PollInterval: time.Millisecond}
			if _, err := renderer.Render(context.Background(), "http://fixture/x"); err == nil {
				t.Fatal("render returned no error for a job that never produced a page")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name %q", err, tc.want)
			}
		})
	}
}

// TestTheRendererStopsWhenTheCallerGaveUp. A confirmation that outlives its
// cancellation keeps a browser alive for the rest of the run and holds the report
// open behind a job nobody is waiting for.
func TestTheRendererStopsWhenTheCallerGaveUp(t *testing.T) {
	stub := newWorkerStub(t)
	stub.statuses = []string{"running", "running", "running", "running", "running"}
	ctx, cancel := context.WithCancel(context.Background())
	renderer := &WorkerRenderer{BaseURL: stub.server.URL, PollInterval: 5 * time.Millisecond}
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	done := make(chan error, 1)
	go func() {
		_, err := renderer.Render(ctx, "http://fixture/x")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("render returned a page for a job that was still running when the caller gave up")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("render kept polling after its context was cancelled")
	}
}

// TestTheRendererRefusesToGuessItsOwnTimeouts. A zero here is a missing value,
// and the documented defaults are what make it a value rather than a zero
// deadline.
func TestTheRendererRefusesToGuessItsOwnTimeouts(t *testing.T) {
	renderer := &WorkerRenderer{}
	if got := renderer.navigationTimeout(); got != DefaultWorkerNavigationTimeout {
		t.Errorf("navigation timeout = %s, want the documented default %s",
			got, DefaultWorkerNavigationTimeout)
	}
	if got := renderer.pollInterval(); got != DefaultWorkerPollInterval {
		t.Errorf("poll interval = %s, want the documented default %s", got, DefaultWorkerPollInterval)
	}
	if got := renderer.jobTimeout(); got != DefaultWorkerJobTimeout {
		t.Errorf("job timeout = %s, want the documented default %s", got, DefaultWorkerJobTimeout)
	}
	if renderer.client() == nil {
		t.Error("a renderer with no client built none")
	}
	if _, err := (&WorkerRenderer{}).Render(context.Background(), "http://fixture/x"); err == nil {
		t.Error("a renderer with no worker url loaded a page: an unset base must be an error, not a default")
	}
}
