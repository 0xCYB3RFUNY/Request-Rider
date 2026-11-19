package main

import (
	"testing"
	"time"
)

// The elapsed counter used to be recomputed only when the transform reported
// something. A long archive index reports nothing until it is finished — one of
// them held the panel on 1/130 for fourteen minutes — so the one field that
// would have kept counting was the one field nothing recomputed, and a slow run
// was indistinguishable from a stuck one.
func TestElapsedCounterMovesWithoutAProgressReport(t *testing.T) {
	job := &osintJob{
		ID:        "osint-heartbeat",
		Transform: "wayback_urls",
		CreatedAt: time.Now().Add(-3 * time.Second),
		done:      make(chan struct{}),
	}
	job.setPhase(osintJobRunning)
	// Started the way a running job starts it. Nothing else in this test
	// touches the counter, so if the heartbeat is not what moves it, the
	// assertion below fails — which is the point: the test goes red if the
	// heartbeat is removed, and green only while it is there.
	job.startHeartbeat(osintJobHeartbeat)
	t.Cleanup(func() { job.heartbeatOnce.Do(func() { close(job.heartbeatStop) }) })

	// One tick has to have happened before the counter holds anything at all:
	// nothing else writes it, which is the defect this test exists for.
	time.Sleep(osintJobHeartbeat + 60*time.Millisecond)
	first := job.Snapshot().Progress.ElapsedMS
	if first < 2500 {
		t.Fatalf("elapsed started at %d ms, want the three seconds since creation", first)
	}
	time.Sleep(320 * time.Millisecond)
	second := job.Snapshot().Progress.ElapsedMS
	if second <= first {
		t.Fatalf("elapsed stood still at %d ms while the job reported nothing", second)
	}
}

// A job that is over must not keep a heartbeat alive, and a finished job must
// not keep counting: a counter that climbs after the result is in is a counter
// that lies.
func TestElapsedCounterStopsWhenTheJobIsOver(t *testing.T) {
	job := &osintJob{
		ID:            "osint-heartbeat-done",
		Transform:     "wayback_urls",
		CreatedAt:     time.Now().Add(-time.Second),
		done:          make(chan struct{}),
		heartbeatStop: make(chan struct{}),
	}
	job.setPhase(osintJobCompleted)
	if job.refreshElapsed() {
		t.Fatal("a finished job still accepted an elapsed refresh")
	}
	before := job.Snapshot().Progress.ElapsedMS
	time.Sleep(120 * time.Millisecond)
	if job.Snapshot().Progress.ElapsedMS != before {
		t.Fatal("a finished job's elapsed counter kept moving")
	}
}
