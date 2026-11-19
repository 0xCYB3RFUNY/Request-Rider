package main

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// The sweeper has to be exactly two things at once: it must never release a job
// the browser is still reading, and it must eventually release every finished
// one. Both halves are tested, because either alone is a plausible wrong answer.

func newRetentionTestServer() *server {
	return &server{
		attacks:       map[uint64]*attack{},
		targetMaps:    map[uint64]*targetMap{},
		oastListeners: map[uint64]*oastListener{},
		bursts:        map[uint64]*repeaterBurst{},
		lastByteJobs:  map[uint64]*lastByteJob{},
	}
}

func TestSweeperKeepsEverythingThatIsNotOldEnough(t *testing.T) {
	server := newRetentionTestServer()
	now := time.Now()

	// A running job has no finish time and must never be swept, however long the
	// sweep has been running.
	running := &attack{status: "running"}
	justFinished := &attack{status: "completed", finishedAt: now.Add(-time.Minute)}
	// A terminal job with no recorded time is left alone too: a path that never
	// recorded one is unknown, and dropping live evidence on a guess is worse than
	// holding memory a little longer.
	unknownAge := &attack{status: "completed"}
	server.attacks[1] = running
	server.attacks[2] = justFinished
	server.attacks[3] = unknownAge

	crawl := &targetMap{status: "running"}
	server.targetMaps[10] = crawl
	listener := &oastListener{status: "running"}
	server.oastListeners[20] = listener
	burst := &repeaterBurst{status: "running"}
	server.bursts[30] = burst
	byte := &lastByteJob{status: "running"}
	server.lastByteJobs[40] = byte

	server.sweepFinishedJobs(now)

	if len(server.attacks) != 3 {
		t.Fatalf("attacks = %d, want the running and the two young jobs kept", len(server.attacks))
	}
	if len(server.targetMaps) != 1 || len(server.oastListeners) != 1 {
		t.Fatalf("a running job was released: crawls=%d listeners=%d", len(server.targetMaps), len(server.oastListeners))
	}
	if len(server.bursts) != 1 || len(server.lastByteJobs) != 1 {
		t.Fatalf("a running job was released: bursts=%d last-byte=%d", len(server.bursts), len(server.lastByteJobs))
	}
}

func TestSweeperReleasesEveryFinishedJobKind(t *testing.T) {
	server := newRetentionTestServer()
	now := time.Now()
	old := now.Add(-2 * time.Hour)

	server.attacks[1] = &attack{status: "completed", finishedAt: old, results: []map[string]interface{}{{"payload": "kept"}}}
	server.attacks[2] = &attack{status: "cancelled", finishedAt: old, results: []map[string]interface{}{{"payload": "kept"}}}
	server.targetMaps[3] = &targetMap{status: "completed", finishedAt: old, pages: []map[string]interface{}{{"url": "x"}}}
	server.oastListeners[4] = &oastListener{status: "completed", finishedAt: old, events: []map[string]interface{}{{"event": "x"}}}
	server.bursts[5] = &repeaterBurst{status: "completed", finishedAt: old, results: []map[string]interface{}{{"payload": "x"}}}
	server.lastByteJobs[6] = &lastByteJob{status: "completed", finishedAt: old, results: []map[string]interface{}{{"payload": "x"}}}

	server.sweepFinishedJobs(now)

	if len(server.attacks) != 0 {
		t.Fatalf("finished attacks were kept: %d", len(server.attacks))
	}
	if len(server.targetMaps) != 0 {
		t.Fatalf("finished crawls were kept: %d", len(server.targetMaps))
	}
	if len(server.oastListeners) != 0 {
		t.Fatalf("finished listeners were kept: %d", len(server.oastListeners))
	}
	if len(server.bursts) != 0 {
		t.Fatalf("finished bursts were kept: %d", len(server.bursts))
	}
	if len(server.lastByteJobs) != 0 {
		t.Fatalf("finished last-byte jobs were kept: %d", len(server.lastByteJobs))
	}
}

func TestFinishedJobRetentionIsOverridableAndNeverCapped(t *testing.T) {
	if got := finishedJobRetention(); got != defaultFinishedJobRetention {
		t.Fatalf("default retention = %v, want %v", got, defaultFinishedJobRetention)
	}
	t.Setenv("RR_FINISHED_JOB_RETENTION_MINUTES", "5")
	if got := finishedJobRetention(); got != 5*time.Minute {
		t.Fatalf("retention = %v, want 5m", got)
	}
	// Not capped: an operator who wants the results for the life of the process
	// says so, and is believed.
	t.Setenv("RR_FINISHED_JOB_RETENTION_MINUTES", "100000")
	if got := finishedJobRetention(); got != 100000*time.Minute {
		t.Fatalf("retention = %v, want the full value the operator asked for", got)
	}
	// A typo falls back to the documented default rather than releasing early.
	for _, value := range []string{"soon", "0", "-3"} {
		t.Setenv("RR_FINISHED_JOB_RETENTION_MINUTES", value)
		if got := finishedJobRetention(); got != defaultFinishedJobRetention {
			t.Fatalf("retention for %q = %v, want the documented default", value, got)
		}
	}
}

func TestTerminalStatusCoversEveryFinishedState(t *testing.T) {
	for _, status := range []string{"completed", "cancelled", "failed", "error", "interrupted"} {
		if !terminalStatus(status) {
			t.Fatalf("%q is a finished state but would never be released", status)
		}
	}
	// A state that is still live must never be released, whatever it is called.
	for _, status := range []string{"", "running", "pending", "paused"} {
		if terminalStatus(status) {
			t.Fatalf("%q was treated as finished and could be swept out from under the browser", status)
		}
	}
}

// The sweeper runs on a timer, so a sweep that panicked would take the process
// down. A panic in a background goroutine is a crash, not a failed request, and
// this is the only place that would ever happen.
func TestSweepIsSafeUnderConcurrentJobCreation(t *testing.T) {
	server := newRetentionTestServer()
	var writers sync.WaitGroup
	var sweeper sync.WaitGroup
	stop := make(chan struct{})

	// Jobs arriving while the sweep runs must be either seen or missed, never
	// half-removed, and a young job must survive regardless of which side wins.
	for writer := 0; writer < 4; writer++ {
		writers.Add(1)
		go func(base uint64) {
			defer writers.Done()
			for id := base; id < base+200; id++ {
				server.attacksMu.Lock()
				server.attacks[id] = &attack{status: "completed", finishedAt: time.Now()}
				server.attacksMu.Unlock()
			}
		}(uint64(writer) * 1000)
	}
	sweeper.Add(1)
	go func() {
		defer sweeper.Done()
		for {
			select {
			case <-stop:
				return
			default:
				server.sweepFinishedJobs(time.Now())
			}
		}
	}()
	writers.Wait()
	close(stop)
	sweeper.Wait()

	// Every job that was created is young, so the sweep may not have removed any
	// of them yet; what matters is that the maps are intact and readable.
	server.attacksMu.Lock()
	total := len(server.attacks)
	server.attacksMu.Unlock()
	if total != 800 {
		t.Fatalf("attacks = %d, want the 800 that were created", total)
	}
}

// Releasing an attack has to take its spill file with it. Closing the file is not
// enough: the file would stay in the process temp directory with no job left to
// reach it, and nothing else ever removes these. That is the memory leak moved to
// the disk, not fixed.
func TestSweeperRemovesTheAttackSpillFile(t *testing.T) {
	server := newRetentionTestServer()
	store, err := newIntruderResultStore(555000111)
	if err != nil {
		t.Skipf("spill store unavailable in this environment: %v", err)
	}
	storePath := store.path
	job := &attack{
		status:     "completed",
		finishedAt: time.Now().Add(-2 * time.Hour),
		store:      store,
	}
	server.attacks[1] = job

	server.sweepFinishedJobs(time.Now())

	if len(server.attacks) != 0 {
		t.Fatalf("the finished attack was kept: %d", len(server.attacks))
	}
	if _, err := os.Stat(storePath); !os.IsNotExist(err) {
		t.Fatalf("the spill file survived the sweep at %s: %v", storePath, err)
	}
}

// Close and Remove mean different things, and a run that is still readable must
// not lose its evidence: the UI resumes polling after a reload.
func TestClosingAStoreKeepsItsEvidence(t *testing.T) {
	store, err := newIntruderResultStore(555000222)
	if err != nil {
		t.Skipf("spill store unavailable in this environment: %v", err)
	}
	defer os.Remove(store.path)
	if err := store.Append(map[string]interface{}{"payload": "kept"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	store.Close()
	if _, err := os.Stat(store.path); err != nil {
		t.Fatalf("Close deleted the evidence at %s: %v", store.path, err)
	}
	results, err := store.Read(0)
	if err != nil || len(results) != 1 {
		t.Fatalf("a closed store lost its results: %#v, %v", results, err)
	}
}

// The stop was documented as idempotent while the code could panic on a second
// call from two goroutines at once. Shutdown paths can run more than once, so the
// property has to be real rather than promised.
func TestStoppingTheSweeperTwiceDoesNotPanic(t *testing.T) {
	engine := &server{sweeper: &finishedJobSweeper{stop: make(chan struct{})}}
	engine.stopFinishedJobSweeper()
	engine.stopFinishedJobSweeper()
	// Concurrent callers are the case the comment promised to survive, so it is
	// the case the test has to make.
	var group sync.WaitGroup
	for caller := 0; caller < 8; caller++ {
		group.Add(1)
		go func() {
			defer group.Done()
			engine.stopFinishedJobSweeper()
		}()
	}
	group.Wait()
	// A server that never started a sweeper must not panic either.
	(&server{}).stopFinishedJobSweeper()
}

// The spill path is where "no evidence is ever lost" is most likely to be a lie:
// a full disk or a quota error hits a run that has already produced findings, and
// closing the store used to make every one of them unreadable. Read now reopens a
// closed store by path, so the findings a failed run already wrote survive it.
func TestASpillFailureKeepsTheFindingsAlreadyWritten(t *testing.T) {
	store, err := newIntruderResultStore(555000333)
	if err != nil {
		t.Skipf("spill store unavailable in this environment: %v", err)
	}
	defer os.Remove(store.path)
	for index := 0; index < 5; index++ {
		if err := store.Append(map[string]interface{}{"payload": fmt.Sprintf("p%d", index)}); err != nil {
			t.Fatalf("append %d: %v", index, err)
		}
	}

	// This is what the run does when an append fails mid-flight.
	store.Close()

	results, err := store.Read(0)
	if err != nil {
		t.Fatalf("a closed store lost the evidence it already wrote: %v", err)
	}
	if len(results) != 5 {
		t.Fatalf("results = %d, want all 5 findings that were written before the failure", len(results))
	}
	// Incremental polling has to keep working too, since that is how the browser
	// reads a long run.
	rest, err := store.Read(3)
	if err != nil || len(rest) != 2 {
		t.Fatalf("incremental read after a failure returned %d results: %v", len(rest), err)
	}
	// A store that was actually released says so, instead of pretending to be
	// empty: an empty result and a released one mean different things to the UI.
	store.Remove()
	if _, err := store.Read(0); err == nil {
		t.Fatal("a released store still answered a read")
	}
}
