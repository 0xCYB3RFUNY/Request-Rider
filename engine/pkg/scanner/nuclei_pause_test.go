package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// slowCountingBinary reports progress forever, one line per tick, so a test can
// watch a run being frozen and continued. Each tick appends to the counter file
// named by MARKER, which is how the test observes that the binary really was
// stopped and not merely reported as stopped.
func slowCountingBinary(t *testing.T) string {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "ticks")
	stub := filepath.Join(t.TempDir(), "nuclei-pause.sh")
	script := "#!/bin/sh\n" +
		"out=''\nprev=''\n" +
		"for arg in \"$@\"; do if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi; prev=\"$arg\"; done\n" +
		"i=0\n" +
		"while [ $i -lt 200 ]; do\n" +
		"  i=$((i+1))\n" +
		"  echo tick >> \"$MARKER\"\n" +
		"  echo '{\"duration\":\"0:00:0'$i'\",\"errors\":\"0\",\"hosts\":\"1\",\"matched\":\"0\",\"percent\":\"'\"$i\"'\",\"requests\":\"'\"$i\"'\",\"rps\":\"1\",\"templates\":\"1\",\"total\":\"200\"}' >&2\n" +
		"  sleep 0.05\n" +
		"done\n" +
		"exit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MARKER", marker)
	t.Setenv("RR_NUCLEI_BINARY", stub)
	return marker
}

func tickCount(t *testing.T, marker string) int {
	t.Helper()
	body, err := os.ReadFile(marker)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatal(err)
	}
	return strings.Count(string(body), "tick")
}

func startPausingJob(t *testing.T) *NucleiJob {
	t.Helper()
	uploadID, _, _, err := StageNucleiUpload("", chunkFiles("a"))
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	job, err := StartNucleiJob(context.Background(), uploadID, NucleiRequest{URL: "http://target.test/"}, nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	return job
}

func waitForRequests(t *testing.T, job *NucleiJob, minimum int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if job.Progress().RequestsDone >= minimum {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the job never reported %d requests (progress: %#v)", minimum, job.Progress())
}

func TestNucleiJobPauseFreezesTheScanAndResumeContinuesIt(t *testing.T) {
	marker := slowCountingBinary(t)
	job := startPausingJob(t)
	waitForRequests(t, job, 3)

	if err := PauseNucleiJob(job.ID); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if state := job.Snapshot().State; state != JobPaused {
		t.Fatalf("state = %q, want paused", state)
	}
	if job.Progress().Phase != JobPaused {
		t.Fatalf("progress phase = %q, want paused", job.Progress().Phase)
	}
	// The point of a pause is that the binary stops doing work. Counting the
	// file the stub appends to proves the process itself was frozen, not just
	// that the API reported a paused state.
	time.Sleep(120 * time.Millisecond)
	before := tickCount(t, marker)
	time.Sleep(400 * time.Millisecond)
	after := tickCount(t, marker)
	if after != before {
		t.Fatalf("the binary kept working while paused: %d ticks before, %d after", before, after)
	}
	if after == 0 {
		t.Fatal("the stub never reported a tick, so the pause proves nothing")
	}
	// A paused run is still in flight, so it has no result and cannot be swept.
	if job.Snapshot().Result != nil {
		t.Fatal("a paused run reported a result")
	}
	CancelNucleiJob(job.ID)
	job.Wait()
}

func TestNucleiJobResumeContinuesTheSameRun(t *testing.T) {
	marker := slowCountingBinary(t)
	job := startPausingJob(t)
	waitForRequests(t, job, 3)

	if err := PauseNucleiJob(job.ID); err != nil {
		t.Fatalf("pause: %v", err)
	}
	pausedAt := tickCount(t, marker)
	if err := ResumeNucleiJob(job.ID); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if state := job.Snapshot().State; state != JobRunning {
		t.Fatalf("state = %q, want running", state)
	}
	// The same process picks up where it stopped, so the tick count has to grow
	// again from the point the pause froze it at.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if tickCount(t, marker) > pausedAt {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the binary did not continue after the resume: %d ticks, was %d", tickCount(t, marker), pausedAt)
}

func TestNucleiJobPauseRejectsWrongStates(t *testing.T) {
	marker := slowCountingBinary(t)
	job := startPausingJob(t)
	waitForRequests(t, job, 2)

	// Pausing twice is not an error, it just means the run is already paused.
	if err := PauseNucleiJob(job.ID); err != nil {
		t.Fatalf("first pause: %v", err)
	}
	if err := PauseNucleiJob(job.ID); err != nil {
		t.Fatalf("a second pause reported an error: %v", err)
	}
	if err := ResumeNucleiJob(job.ID); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if err := ResumeNucleiJob(job.ID); err != ErrNotPaused {
		t.Fatalf("resuming a running scan returned %v, want ErrNotPaused", err)
	}
	// A job that never started has no binary to stop.
	if err := PauseNucleiJob("no-such-job"); err == nil {
		t.Fatal("an unknown job accepted a pause")
	}
	if err := ResumeNucleiJob("no-such-job"); err == nil {
		t.Fatal("an unknown job accepted a resume")
	}
	CancelNucleiJob(job.ID)
	job.Wait()
	if err := PauseNucleiJob(job.ID); err != ErrNotPausable {
		t.Fatalf("pausing a finished scan returned %v, want ErrNotPausable", err)
	}
	_ = marker
}

func TestNucleiJobCancelWorksWhilePaused(t *testing.T) {
	marker := slowCountingBinary(t)
	job := startPausingJob(t)
	waitForRequests(t, job, 2)
	if err := PauseNucleiJob(job.ID); err != nil {
		t.Fatalf("pause: %v", err)
	}
	// A stopped process would never observe the cancellation, so cancelling has
	// to continue it first.
	if !CancelNucleiJob(job.ID) {
		t.Fatal("a paused job rejected cancellation")
	}
	started := time.Now()
	snapshot := job.Wait()
	if time.Since(started) > 5*time.Second {
		t.Fatal("cancelling a paused scan did not take effect promptly")
	}
	if snapshot.State != JobCancelled {
		t.Fatalf("state = %q, want cancelled", snapshot.State)
	}
	if tickCount(t, marker) == 0 {
		t.Fatal("the stub never reported a tick")
	}
}
