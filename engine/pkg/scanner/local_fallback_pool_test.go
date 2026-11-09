package scanner

// The second runner used to walk its rows one at a time, and one row's cost is a
// full request plus, for a document that names an OAST address, a ten-second wait
// for a callback. Those waits stacked: measured on `http/exposures` (704 files)
// against a local target on 2026-10-07, nuclei itself reached 100 % in 31 s and
// the pass then took 164 s for 25 rows, so the same folder and binary that took
// 32.9 s in a terminal took 195.8 s through the browser.
//
// These tests hold two things at once: the pool is real (the target sees more
// than one request in flight), and it changed nothing about the verdicts (every
// row still ends in the state the serial pass produced, in upload order, with the
// same counters). The fixture is a live `httptest` server for the same reason the
// rest of this file's tests use one — a mocked transport would agree with any
// runner at all.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// concurrencyFixture serves the marker every generated document looks for and
// records the most requests it ever had in flight at the same moment.
func concurrencyFixture() (*httptest.Server, *int64, *int64) {
	var inFlight int64
	var peak int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt64(&inFlight, 1)
		for {
			seen := atomic.LoadInt64(&peak)
			if current <= seen || atomic.CompareAndSwapInt64(&peak, seen, current) {
				break
			}
		}
		// The window is what makes the peak meaningful: a request that returns
		// instantly could serialise by accident and read as a pool.
		time.Sleep(40 * time.Millisecond)
		atomic.AddInt64(&inFlight, -1)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<title>Adminer</title>"))
	}))
	return server, &peak, &inFlight
}

func markerDocument(id string) string {
	return fmt.Sprintf(`id: %s
info:
  name: %s
  author: requestrider
  severity: info
  tags: fuzz
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "Adminer"
`, id, id)
}

// stageFallbackFolder writes `count` documents and returns them in upload order.
func stageFallbackFolder(t *testing.T, count int) []StagedFile {
	t.Helper()
	root := t.TempDir()
	inputs := make([]StagedFile, 0, count)
	for index := 0; index < count; index++ {
		relative := filepath.Join("panels", fmt.Sprintf("doc-%03d.yaml", index))
		staged := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(staged), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(staged, []byte(markerDocument(fmt.Sprintf("doc-%03d", index))), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		inputs = append(inputs, StagedFile{
			UploadName: filepath.Base(relative), RelativePath: relative, StagedPath: staged,
		})
	}
	return inputs
}

func TestTheLocalFallbackRunsItsRowsConcurrently(t *testing.T) {
	target, peak, _ := concurrencyFixture()
	defer target.Close()
	inputs := stageFallbackFolder(t, 12)
	run := &NucleiRun{Templates: make([]TemplateResult, 0, len(inputs))}
	for _, file := range inputs {
		run.Templates = append(run.Templates, TemplateResult{
			Name: file.UploadName, Path: file.RelativePath,
			Status: TemplateUncompiled, Reason: "the binary compiled no template out of this document",
		})
	}

	stats := map[string]int{}
	performed := applyLocalFallback(context.Background(), run, inputs, target.URL, http.DefaultTransport, stats)

	if performed != len(inputs) {
		t.Fatalf("performed = %d, want %d: the pool must not skip a row the serial pass would have run",
			performed, len(inputs))
	}
	if observed := atomic.LoadInt64(peak); observed < 2 {
		t.Fatalf("the target never saw more than %d request in flight, so this pass is still serial "+
			"and the stacked per-row waits are still there", observed)
	}
	if stats[localRunnerRefusalRewrite] != 0 {
		t.Errorf("%s = %d, want 0: a runner that performed the document refused nothing",
			localRunnerRefusalRewrite, stats[localRunnerRefusalRewrite])
	}
	if stats[localRunnerFindingRewrite] != len(inputs) {
		t.Errorf("%s = %d, want %d: every document matched and the binary missed every one",
			localRunnerFindingRewrite, stats[localRunnerFindingRewrite], len(inputs))
	}
	for index, row := range run.Templates {
		if row.Status != TemplateMatched {
			t.Fatalf("row %d status = %q, want %q", index, row.Status, TemplateMatched)
		}
		if row.PerformedBy != performedByLocalRunner {
			t.Errorf("row %d performed_by = %q, want %q", index, row.PerformedBy, performedByLocalRunner)
		}
		if row.Path != inputs[index].RelativePath {
			t.Fatalf("row %d path = %q, want %q: the pool must not reorder the report",
				index, row.Path, inputs[index].RelativePath)
		}
		if len(row.Findings) != 1 {
			t.Errorf("row %d has %d findings, want 1", index, len(row.Findings))
		}
	}
}

// A cancelled route must still stop the pass rather than turn into a verdict, and
// the pool must not resurrect work the serial pass would have skipped.
func TestTheLocalFallbackStopsOnACancelledContext(t *testing.T) {
	target, _, _ := concurrencyFixture()
	defer target.Close()
	inputs := stageFallbackFolder(t, 4)
	run := &NucleiRun{Templates: make([]TemplateResult, 0, len(inputs))}
	for _, file := range inputs {
		run.Templates = append(run.Templates, TemplateResult{
			Name: file.UploadName, Path: file.RelativePath, Status: TemplateUncompiled,
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	performed := applyLocalFallback(ctx, run, inputs, target.URL, http.DefaultTransport, nil)
	if performed != 0 {
		t.Fatalf("performed = %d on a cancelled context, want 0", performed)
	}
	for index, row := range run.Templates {
		if row.Status == TemplateMatched {
			t.Fatalf("row %d became a verdict on a cancelled run", index)
		}
		if !strings.Contains(strings.ToLower(row.Reason), "cancel") {
			t.Fatalf("row %d reason = %q, want it to name the cancellation", index, row.Reason)
		}
	}
}
