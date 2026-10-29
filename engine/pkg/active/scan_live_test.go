package active

// Tests for the finding sink — the run's live edge.
//
// The behaviour under test is a promise about *when* a row is available: a
// watcher must see a proven row while the run is still working, not in one batch
// after it returned. Everything else here follows from that promise being real.
//
// The target is the package's own vulnerable fixture rather than a mock: a mock
// transport would agree with a run that never probed anything, and the claim
// being measured is that a row exists before the run ends.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// liveRun drives one real scan against the fixture and records what the sink saw.
//
// The two counters it returns are the measurement: `early` is how many rows
// arrived while the run was still working, and `announced` is everything the
// sink received at all. A run that announced only at the end would have
// `early == 0`, which is exactly the defect these tests exist to keep out.
func liveRun(t *testing.T) (early int, announced []Finding) {
	t.Helper()
	server := httptest.NewServer(vulnerableFixture(t))
	defer server.Close()

	start, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse fixture url: %v", err)
	}
	start.Path = "/form"

	var mu sync.Mutex
	var returned atomic.Bool
	var earlyCount int
	var seen []Finding

	scan := NewScan(ScanRequest{
		URL:              start.String(),
		MaxPages:         10,
		MaxDepth:         1,
		Concurrency:      1,
		Timeout:          5 * time.Second,
		InterestingPaths: []string{},
		Params:           []string{"debug"},
		PathWordlist:     []string{"/.env"},
		RoundTripper:     http.DefaultTransport,
		FindingSink: func(row Finding) {
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, row)
			if !returned.Load() {
				earlyCount++
			}
		},
	}, nil)

	report, runErr := scan.Run(context.Background())
	// The flag flips the instant `Run` hands the report over. Anything the sink
	// counted before this line was counted by a run that had not finished.
	returned.Store(true)
	if runErr != nil {
		t.Fatalf("scan failed: %v", runErr)
	}
	if len(report.Findings) == 0 {
		t.Fatalf("the fixture proved nothing, so a test about live rows would pass on an empty run")
	}
	mu.Lock()
	defer mu.Unlock()
	return earlyCount, seen
}

// A row that only appears after the run returned is not a live row. The whole
// point of the sink is that a caller can render something while the work is
// still happening, and a caller that waits for the end needs no sink at all — it
// reads the report.
func TestTheSinkSeesRowsWhileTheRunIsStillWorking(t *testing.T) {
	early, announced := liveRun(t)
	if early == 0 {
		t.Fatalf("the sink received %d row(s) and none of them before the run returned: "+
			"every row was delivered at the end, which is the behaviour the sink exists to remove", len(announced))
	}
	if early < len(announced) {
		t.Logf("note: %d of %d row(s) arrived before the run returned; the rest came from the "+
			"stages that finish last (correlating, proving)", early, len(announced))
	}
}

// The sink is a reader of the run, not a second source of rows. A row it shows
// that the report does not carry would be a claim with no evidence behind it,
// and a browser would render it as a finding.
func TestEveryRowTheSinkSeesIsARowTheReportCarries(t *testing.T) {
	server := httptest.NewServer(vulnerableFixture(t))
	defer server.Close()

	start, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse fixture url: %v", err)
	}
	start.Path = "/form"

	var mu sync.Mutex
	var announced []Finding
	scan := NewScan(ScanRequest{
		URL:              start.String(),
		MaxPages:         10,
		MaxDepth:         1,
		Concurrency:      2,
		Timeout:          5 * time.Second,
		InterestingPaths: []string{},
		Params:           []string{"debug"},
		PathWordlist:     []string{"/.env"},
		RoundTripper:     http.DefaultTransport,
		FindingSink: func(row Finding) {
			mu.Lock()
			defer mu.Unlock()
			announced = append(announced, row)
		},
	}, nil)
	report, runErr := scan.Run(context.Background())
	if runErr != nil {
		t.Fatalf("scan failed: %v", runErr)
	}

	inReport := make(map[string]bool, len(report.Findings))
	for _, row := range report.Findings {
		inReport[row.ID] = true
	}
	mu.Lock()
	defer mu.Unlock()
	if len(announced) == 0 {
		t.Fatal("the sink received nothing while the report carries rows")
	}
	for _, row := range announced {
		if row.ID == "" {
			t.Fatalf("a row reached the sink without an id: %+v", row)
		}
		if !inReport[row.ID] {
			t.Fatalf("the sink delivered row %q (%s) and the finished report does not carry it",
				row.ID, row.Title)
		}
	}
}

// A run nobody watches must behave exactly as it did before the sink existed:
// a nil sink is not a special case, it is the ordinary one. The run still probes,
// still proves and still returns its report — it simply has nobody to tell.
func TestARunWithNoSinkStillProducesItsReport(t *testing.T) {
	server := httptest.NewServer(vulnerableFixture(t))
	defer server.Close()

	start, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse fixture url: %v", err)
	}
	start.Path = "/form"

	scan := NewScan(ScanRequest{
		URL:              start.String(),
		MaxPages:         10,
		MaxDepth:         1,
		Concurrency:      1,
		Timeout:          5 * time.Second,
		InterestingPaths: []string{},
		Params:           []string{"debug"},
		PathWordlist:     []string{"/.env"},
		RoundTripper:     http.DefaultTransport,
	}, nil)
	report, runErr := scan.Run(context.Background())
	if runErr != nil {
		t.Fatalf("scan failed: %v", runErr)
	}
	if len(report.Findings) == 0 {
		t.Fatal("a run with no sink produced no findings; the sink changed the run rather than only its observer")
	}
}
