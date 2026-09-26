package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Job phases reported to the browser for an OSINT transform. They match the
// phases the nuclei scanner jobs already use, so one control vocabulary serves
// both background tools.
const (
	osintJobQueued    = "queued"
	osintJobRunning   = "running"
	osintJobPaused    = "paused"
	osintJobCompleted = "completed"
	osintJobFailed    = "failed"
	osintJobCancelled = "cancelled"
)

// osintJobProgress is the live state of one transform. The counters are real
// names collected so far, never an estimate from the UI.
//
// CollectsNames states whether this run collects names at all. Without it the
// names counter is a structural zero for every other transform, and a panel that
// shows "0 names" during a reverse DNS lookup reports a number the run was
// never going to move.
type osintJobProgress struct {
	Phase         string  `json:"phase"`
	Names         int     `json:"names"`
	Relations     int     `json:"relations"`
	Indexes       int     `json:"indexes"`
	IndexesTotal  int     `json:"indexes_total"`
	ElapsedMS     int64   `json:"elapsed_ms"`
	CurrentIndex  string  `json:"current_index,omitempty"`
	Partial       float64 `json:"partial_percent"`
	CollectsNames bool    `json:"collects_names"`
}

// osintJob is one transform running in the background.
//
// A transform is HTTP streaming rather than a child process, so pausing it
// cannot freeze a process: it suspends the collector between names and lets
// every in-flight request finish. The names already collected stay collected,
// which is what makes a pause different from a cancel.
type osintJob struct {
	ID        string
	Transform string
	Value     string
	CreatedAt time.Time

	mutex    sync.Mutex
	progress osintJobProgress
	result   *osintTransformResult
	err      error
	cancel   context.CancelFunc
	done     chan struct{}
	gate     *pauseGate
	// collector is the transform's progress sink, kept so a cancel can tell
	// the collector to stop rather than only cancelling the context.
	collector *transformCollector
	cleanup   func()
}

// Snapshot is the JSON shape returned for one job poll.
type osintJobSnapshot struct {
	ID       string                `json:"id"`
	State    string                `json:"state"`
	Progress osintJobProgress      `json:"progress"`
	Result   *osintTransformResult `json:"result,omitempty"`
	Error    string                `json:"error,omitempty"`
	Reason   string                `json:"reason,omitempty"`
}

// Snapshot returns the pollable state of the job.
func (job *osintJob) Snapshot() osintJobSnapshot {
	job.mutex.Lock()
	defer job.mutex.Unlock()
	snapshot := osintJobSnapshot{
		ID:       job.ID,
		State:    job.progress.Phase,
		Progress: job.progress,
		Result:   job.result,
	}
	if job.err != nil {
		snapshot.Error = job.err.Error()
		if job.progress.Phase == osintJobCancelled {
			snapshot.Reason = "ROUTE_CHANGED"
		}
	}
	return snapshot
}

// pauseGate suspends a running transform between collected names. It is the
// cooperative counterpart of the SIGSTOP pause the nuclei scanner uses for its
// child process: there is no process to freeze here, so the collector waits
// while the transform keeps its collected names and its open connections.
//
// The gate is a channel rather than a condition variable, because a paused
// transform must still end when its context is cancelled. A cond var only
// wakes on a broadcast, so a paused transform cancelled by a route switch would
// wait for a resume that never comes.
type pauseGate struct {
	mutex sync.Mutex
	// paused blocks the collector, and release is closed to let it pass.
	paused  bool
	release chan struct{}
}

func newPauseGate() *pauseGate {
	return &pauseGate{}
}

// pause suspends the collector at its next checkpoint.
func (gate *pauseGate) pause() {
	gate.mutex.Lock()
	defer gate.mutex.Unlock()
	if gate.paused {
		return
	}
	gate.paused = true
	gate.release = make(chan struct{})
}

// resume lets a paused collector continue. It is safe to call on a running or
// already released gate, because a cancel and a finish both resume it.
func (gate *pauseGate) resume() {
	gate.mutex.Lock()
	defer gate.mutex.Unlock()
	if !gate.paused {
		return
	}
	gate.paused = false
	close(gate.release)
	gate.release = nil
}

func (gate *pauseGate) isPaused() bool {
	gate.mutex.Lock()
	defer gate.mutex.Unlock()
	return gate.paused
}

// checkpoint blocks while the transform is paused. The context is part of the
// wait, so a paused transform stays cancellable and a route switch still ends
// it instead of leaving it suspended forever.
func (gate *pauseGate) checkpoint(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	gate.mutex.Lock()
	release := gate.release
	paused := gate.paused
	gate.mutex.Unlock()
	if !paused {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-release:
		// Being released is not the same as being allowed to continue: the
		// context may have been cancelled while the collector waited.
		return ctx.Err()
	}
}

// osintJobStore keeps running transforms addressable by id.
type osintJobStore struct {
	mutex sync.Mutex
	jobs  map[string]*osintJob
}

var osintJobs = &osintJobStore{jobs: map[string]*osintJob{}}

func (store *osintJobStore) add(job *osintJob) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.jobs[job.ID] = job
}

func (store *osintJobStore) get(id string) (*osintJob, bool) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	job, ok := store.jobs[id]
	return job, ok
}

// sweepFinished removes transforms that finished long enough ago for every
// poll to have observed them, so a finished run cannot accumulate in memory.
func (store *osintJobStore) sweepFinished(ttl time.Duration) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	for id, job := range store.jobs {
		job.mutex.Lock()
		phase := job.progress.Phase
		job.mutex.Unlock()
		if phase == osintJobQueued || phase == osintJobRunning || phase == osintJobPaused {
			continue
		}
		if time.Since(job.CreatedAt) > ttl {
			delete(store.jobs, id)
		}
	}
}

// startOSINTJob runs one transform in the background so the browser can watch
// it, pause it and cancel it instead of waiting on one blocking request. The
// job is bound to the route generation rather than to the request context, so
// it outlives the request that started it while a route switch still cancels
// it. The lease release is what makes that possible.
func (s *server) startOSINTJob(parent context.Context, input osintTransformInput, leaseRelease func()) *osintJob {
	id := fmt.Sprintf("osint-%d", atomic.AddUint64(&s.osintJobSequence, 1))
	osintJobs.sweepFinished(30 * time.Minute)
	runCtx, cancel := context.WithCancel(parent)
	indexTotal := s.certificateQueryTotal(input)
	job := &osintJob{
		ID:        id,
		Transform: input.Transform,
		Value:     input.Value,
		CreatedAt: time.Now(),
		progress: osintJobProgress{
			Phase:         osintJobQueued,
			IndexesTotal:  indexTotal,
			CollectsNames: input.Transform == subdomainTransform,
		},
		cancel:  cancel,
		done:    make(chan struct{}),
		gate:    newPauseGate(),
		cleanup: leaseRelease,
	}
	osintJobs.add(job)
	job.mutex.Lock()
	job.collector = &transformCollector{
		engine:   s,
		job:      job,
		indexes:  indexTotal,
		ctx:      runCtx,
		stop:     make(chan struct{}),
		progress: func(update transformProgress) { job.setProgress(update) },
	}
	collector := job.collector
	job.mutex.Unlock()
	go s.runOSINTJob(runCtx, job, collector, input)
	return job
}

// certificateQueryTotal reports how many index queries one run will make, so the
// progress panel counts the queries the run really performs: the certificate
// indexes multiplied by the zone chain the input resolves to. A transform that
// queries no certificate index reports none, so the panel never shows a counter
// for indexes the run will not ask.
func (s *server) certificateQueryTotal(input osintTransformInput) int {
	if input.Transform != subdomainTransform {
		return 0
	}
	zones := certificateQueryZones(input.Value)
	if len(zones) == 0 {
		return 0
	}
	return len(s.certificateIndexChain(input.Value)) * len(zones)
}

func (s *server) runOSINTJob(ctx context.Context, job *osintJob, collector *transformCollector, input osintTransformInput) {
	job.setPhase(osintJobRunning)
	result, err := s.runOSINTTransformWithCollector(ctx, input, collector)
	collector.close()
	switch {
	// A cancelled transform reports cancelled whatever it managed to collect
	// on the way out. Reporting the partial result as completed would be a
	// success-shaped answer to a request that was stopped.
	case ctx.Err() != nil, collector.cancelled():
		job.finish(osintJobCancelled, nil, err)
	case err == nil:
		job.finish(osintJobCompleted, &result, nil)
	default:
		job.finish(osintJobFailed, nil, err)
	}
}

func (job *osintJob) setPhase(phase string) {
	job.mutex.Lock()
	job.progress.Phase = phase
	job.mutex.Unlock()
}

func (job *osintJob) setProgress(update transformProgress) {
	job.mutex.Lock()
	job.progress.Names = update.Names
	job.progress.Relations = update.Relations
	job.progress.Indexes = update.Indexes
	job.progress.IndexesTotal = update.IndexesTotal
	job.progress.CurrentIndex = update.CurrentIndex
	job.progress.Partial = update.Partial
	job.progress.ElapsedMS = time.Since(job.CreatedAt).Milliseconds()
	// A checkpoint that arrived while the job is paused must not report it as
	// running again.
	if job.progress.Phase == osintJobRunning && job.gate.isPaused() {
		job.progress.Phase = osintJobPaused
	}
	job.mutex.Unlock()
}

func (job *osintJob) finish(phase string, result *osintTransformResult, err error) {
	job.mutex.Lock()
	job.progress.Phase = phase
	job.progress.ElapsedMS = time.Since(job.CreatedAt).Milliseconds()
	job.result = result
	job.err = err
	job.mutex.Unlock()
	// A paused collector must be released before the job can be collected, or
	// it would wait for a resume that no longer exists.
	job.gate.resume()
	if job.cleanup != nil {
		job.cleanup()
	}
	close(job.done)
}

// osintJobSnapshot returns the pollable state of one transform.
func osintJobSnapshotFor(id string) (osintJobSnapshot, bool) {
	job, ok := osintJobs.get(strings.TrimSpace(id))
	if !ok {
		return osintJobSnapshot{}, false
	}
	return job.Snapshot(), true
}

// cancelOSINTJob stops a running transform. It reports false when the job is
// unknown or already finished, so a second cancel is not silently accepted.
func cancelOSINTJob(id string) bool {
	job, ok := osintJobs.get(strings.TrimSpace(id))
	if !ok {
		return false
	}
	job.mutex.Lock()
	phase := job.progress.Phase
	job.mutex.Unlock()
	if !osintJobActive(phase) {
		return false
	}
	// A paused collector waits on the gate, so cancelling has to release it
	// first: a stopped collector would never observe the cancellation.
	job.gate.resume()
	job.mutex.Lock()
	collector := job.collector
	job.mutex.Unlock()
	// The collector records the cancel explicitly, so a transform that runs to
	// the end while being cancelled is still reported as cancelled.
	collector.requestStop()
	job.cancel()
	return true
}

// pauseOSINTJob suspends a running transform. Pausing a transform that is
// already paused, or that has not started collecting yet, is not an error: the
// phase it is already in is the phase it stays in.
func pauseOSINTJob(id string) error {
	job, ok := osintJobs.get(strings.TrimSpace(id))
	if !ok {
		return fmt.Errorf("transform %q is unknown or already collected", id)
	}
	job.mutex.Lock()
	phase := job.progress.Phase
	job.mutex.Unlock()
	if !osintJobActive(phase) {
		return fmt.Errorf("transform %q is %s and can no longer be paused", id, phase)
	}
	job.gate.pause()
	job.mutex.Lock()
	job.progress.Phase = osintJobPaused
	job.mutex.Unlock()
	return nil
}

// resumeOSINTJob continues a paused transform.
func resumeOSINTJob(id string) error {
	job, ok := osintJobs.get(strings.TrimSpace(id))
	if !ok {
		return fmt.Errorf("transform %q is unknown or already collected", id)
	}
	job.mutex.Lock()
	phase := job.progress.Phase
	job.mutex.Unlock()
	if phase != osintJobPaused {
		return fmt.Errorf("transform %q is %s and is not paused", id, phase)
	}
	job.mutex.Lock()
	job.progress.Phase = osintJobRunning
	job.mutex.Unlock()
	job.gate.resume()
	return nil
}

func osintJobActive(phase string) bool {
	return phase == osintJobQueued || phase == osintJobRunning || phase == osintJobPaused
}
