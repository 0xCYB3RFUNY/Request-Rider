package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseNucleiStatsLine(t *testing.T) {
	line := "[0:01:07] | Templates: 316 | Hosts: 1 | RPS: 42 | Matched: 12 | Errors: 1 | Requests: 1840/2010 (91%)"
	progress, ok := ParseNucleiStatsLine(line)
	if !ok {
		t.Fatal("a real stats line was not recognised")
	}
	if progress.Templates != 316 || progress.Hosts != 1 || progress.RPS != 42 {
		t.Fatalf("counters = %#v", progress)
	}
	if progress.Matched != 12 || progress.Errors != 1 {
		t.Fatalf("matched/errors = %#v", progress)
	}
	if progress.RequestsDone != 1840 || progress.RequestsTotal != 2010 {
		t.Fatalf("requests = %#v", progress)
	}
	if progress.Percent < 91.5 || progress.Percent > 91.6 {
		t.Fatalf("percent = %v, want ~91.5", progress.Percent)
	}
	if progress.ElapsedSeconds != 67 {
		t.Fatalf("elapsed = %v, want 67", progress.ElapsedSeconds)
	}
	if progress.Phase != "running" {
		t.Fatalf("phase = %q", progress.Phase)
	}
}

func TestParseNucleiJSONStatsLine(t *testing.T) {
	// In JSONL mode Nuclei emits machine-readable stats on the same stream as
	// the findings, so both shapes have to be told apart.
	line := `{"duration":"0:01:07","errors":"26","hosts":"1","matched":"12","percent":"91","requests":"1840","rps":"42","startedAt":"2026-09-25T17:03:47Z","templates":"316","total":"2010"}`
	progress, ok := ParseNucleiStatsLine(line)
	if !ok {
		t.Fatal("a real JSON stats line was not recognised")
	}
	if progress.Templates != 316 || progress.RequestsDone != 1840 || progress.RequestsTotal != 2010 {
		t.Fatalf("counters = %#v", progress)
	}
	if progress.Matched != 12 || progress.Errors != 26 || progress.RPS != 42 || progress.Hosts != 1 {
		t.Fatalf("counters = %#v", progress)
	}
	if progress.Percent != 91 {
		t.Fatalf("percent = %v, want 91 from the reported figure", progress.Percent)
	}
	if progress.ElapsedSeconds != 67 {
		t.Fatalf("elapsed = %v, want 67", progress.ElapsedSeconds)
	}

	// A finding is JSON too, and must never be read as progress.
	finding := `{"template-id":"x","template-path":"/t/a.yaml","info":{"name":"A","severity":"high"},"host":"h","matched-at":"u","matcher-status":true}`
	if _, ok := ParseNucleiStatsLine(finding); ok {
		t.Fatal("a finding was treated as a stats line")
	}
}

func TestParseNucleiStatsLineIgnoresNoise(t *testing.T) {
	// Log lines, the banner and errors must not be mistaken for progress.
	for _, line := range []string{
		"",
		"     __     _",
		"   ____  __  _______/ /__  (_)",
		"[INF] [0:00:00] Using Nuclei Engine Version: v3.11.1",
		"[ERR] Could not run nuclei: no templates provided for scan",
		"[WRN] cause=\"no template author field provided\" tag=invalid_template",
		"invalid value \"bogus\" for flag -pt",
		"[INF] Scan completed in 1.2s. No results found.",
	} {
		if _, ok := ParseNucleiStatsLine(line); ok {
			t.Fatalf("%q was treated as a progress line", line)
		}
	}
}

func TestNucleiOutputCollectsLinesAndKeepsStats(t *testing.T) {
	var stats []NucleiProgress
	stream := newNucleiOutput(func(line string) {
		if update, ok := ParseNucleiStatsLine(line); ok {
			stats = append(stats, update)
		}
	})
	// A stats line can be split across writes, exactly as a pipe delivers it.
	parts := []string{
		"[INF] Starting scan\n[0:00:0",
		"1] | Templates: 41 | Hosts: 1 | RPS: 23 | Matched: 0 | Errors: 0 | Requests: 29/60 (48%)\n",
		"[ERR] something went wrong\n",
	}
	for _, part := range parts {
		if _, err := stream.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	if len(stats) != 1 {
		t.Fatalf("parsed %d stats lines, want 1: %#v", len(stats), stats)
	}
	if stats[0].RequestsDone != 29 || stats[0].RequestsTotal != 60 {
		t.Fatalf("split line parsed wrong: %#v", stats[0])
	}
	text := stream.Text()
	if text == "" || !contains(text, "something went wrong") {
		t.Fatalf("diagnostics lost: %q", text)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// statsBinary emits progress lines on stderr, then a match, then finishes. The
// reported template path is read from the staged directory so the finding is
// attributed to the uploaded file.
func statsBinary(t *testing.T) {
	t.Helper()
	stub := filepath.Join(t.TempDir(), "nuclei-stats.sh")
	script := "#!/bin/sh\n" +
		"out=''\ntemplates=''\nprev=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		"echo '[INF] [0:00:00] Using Nuclei Engine Version: v3.11.1' >&2\n" +
		// The real binary emits JSON stats in JSONL mode; the pipe form is
		// covered by the parser unit tests.
		"echo '{\"duration\":\"0:00:01\",\"errors\":\"0\",\"hosts\":\"1\",\"matched\":\"0\",\"percent\":\"48\",\"requests\":\"29\",\"rps\":\"23\",\"templates\":\"41\",\"total\":\"60\"}' >&2\n" +
		"echo '[0:00:02] | Templates: 41 | Hosts: 1 | RPS: 18 | Matched: 1 | Errors: 0 | Requests: 60/60 (100%)' >&2\n" +
		"sleep 0.4\n" +
		"printf '%s\\n' '{\"template-id\":\"stats-hit\",\"template-path\":\"'\"$templates\"'/a.yaml\",\"info\":{\"name\":\"Stats Hit\",\"author\":[\"rr\"],\"severity\":\"high\"},\"host\":\"http://target.test\",\"matched-at\":\"http://target.test/a\"}' > \"$out\"\n" +
		"exit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)
}

func TestNucleiJobReportsProgressAndResult(t *testing.T) {
	statsBinary(t)
	uploadID, _, _, err := StageNucleiUpload("", chunkFiles("a"))
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	job, err := StartNucleiJob(context.Background(), uploadID, NucleiRequest{URL: "http://target.test/"}, nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	snapshot := job.Wait()
	if snapshot.State != JobCompleted {
		t.Fatalf("state = %q error = %v", snapshot.State, snapshot.Error)
	}
	if snapshot.Progress.Templates != 41 || snapshot.Progress.RequestsTotal != 60 {
		t.Fatalf("final progress = %#v", snapshot.Progress)
	}
	if snapshot.Progress.Percent != 100 {
		t.Fatalf("percent = %v, want 100 on completion", snapshot.Progress.Percent)
	}
	if snapshot.Result == nil || len(snapshot.Result.Templates) != 1 {
		t.Fatalf("result = %#v", snapshot.Result)
	}
	if snapshot.Result.Templates[0].Status != TemplateMatched {
		t.Fatalf("template = %#v", snapshot.Result.Templates[0])
	}
	// A finished job is addressable for polling.
	if _, ok := NucleiJobSnapshot(job.ID); !ok {
		t.Fatal("a finished job cannot be polled")
	}
}

func TestNucleiJobCancelStopsTheRun(t *testing.T) {
	slow := filepath.Join(t.TempDir(), "nuclei-slow.sh")
	script := "#!/bin/sh\n" +
		"echo '[0:00:01] | Templates: 1 | Hosts: 1 | RPS: 1 | Matched: 0 | Errors: 0 | Requests: 1/10 (10%)' >&2\n" +
		"sleep 20\n"
	if err := os.WriteFile(slow, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RR_NUCLEI_BINARY", slow)
	uploadID, _, _, err := StageNucleiUpload("", chunkFiles("a"))
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	job, err := StartNucleiJob(context.Background(), uploadID, NucleiRequest{URL: "http://target.test/"}, nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	// Wait until the binary has reported progress, then cancel.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if job.Progress().RequestsDone == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !CancelNucleiJob(job.ID) {
		t.Fatal("cancel reported the job as unknown")
	}
	snapshot := job.Wait()
	if snapshot.State != JobCancelled {
		t.Fatalf("state = %q error = %v", snapshot.State, snapshot.Error)
	}
	if CancelNucleiJob(job.ID) {
		t.Fatal("a cancelled job accepted a second cancel")
	}
}

func TestNucleiJobRejectsUnknownUpload(t *testing.T) {
	if _, err := StartNucleiJob(context.Background(), "nope", NucleiRequest{URL: "http://target.test/"}, nil); err == nil {
		t.Fatal("an unknown upload id started a job")
	}
}
