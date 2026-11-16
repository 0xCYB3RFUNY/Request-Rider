package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Job phases reported to the browser.
const (
	JobQueued    = "queued"
	JobRunning   = "running"
	JobPaused    = "paused"
	JobCompleted = "completed"
	JobFailed    = "failed"
	JobCancelled = "cancelled"
)

// NucleiJob is one asynchronous template run with live progress.
type NucleiJob struct {
	ID        string
	CreatedAt time.Time

	mutex    sync.Mutex
	progress NucleiProgress
	run      *NucleiRun
	err      error
	cancel   context.CancelFunc
	done     chan struct{}
	// process is the running binary, kept so the run can be paused and
	// resumed. It is nil until the binary has actually started.
	process *os.Process
	paused  bool
	// staged is the uploaded file set, used to attribute live records to the
	// file that produced them.
	staged []StagedFile
	// resolve maps a path the binary reported back to a staged file. A planned run
	// loads templates from per-batch directories, so the JSONL path is not the
	// staged one and attribution has to go through the plan.
	resolve func(string) (StagedFile, bool)
	// events is the live stream the browser follows while the scan runs.
	eventsMutex sync.Mutex
	events      []TemplateEvent
	eventCursor int
	waiters     map[chan struct{}]struct{}
	// cleanup removes the staged upload directory once the run is over.
	cleanup func()
}

// Progress returns the current state of the job.
func (j *NucleiJob) Progress() NucleiProgress {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	progress := j.progress
	progress.ElapsedSeconds = time.Since(j.CreatedAt).Seconds()
	return progress
}

func (j *NucleiJob) setProgress(update NucleiProgress) {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	j.setProgressLocked(update)
}

// setProgressLocked stores a stats update. The caller must hold the mutex.
func (j *NucleiJob) setProgressLocked(update NucleiProgress) {
	// A stats line that was already in the pipe when the run was paused must
	// not report the job as running again.
	if j.paused {
		update.Phase = JobPaused
	}
	j.progress = update
}

func (j *NucleiJob) finish(phase string, run *NucleiRun, err error) {
	j.mutex.Lock()
	// Keep the counters from the last stats line: only the phase and the
	// completion percentage change here.
	j.progress.Phase = phase
	j.progress.ElapsedSeconds = time.Since(j.CreatedAt).Seconds()
	if phase == JobCompleted {
		// The process exits between two stats ticks, so the last line can lag
		// behind the run. A finished scan that reported 100% next to a partial
		// request count would be self-contradictory, so the totals the binary
		// itself reached are carried over from the report.
		if j.progress.RequestsTotal > 0 {
			j.progress.RequestsDone = j.progress.RequestsTotal
		}
		if j.progress.Percent < 100 {
			j.progress.Percent = 100
		}
	}
	j.paused = false
	j.run = run
	j.err = err
	j.mutex.Unlock()
	// The final event carries the authoritative report, so a client that only
	// follows the stream still ends up with every file and the full diagnostics.
	final := TemplateEvent{Kind: EventDiagnostic, State: phase, Result: j.resultPayload()}
	if err != nil {
		final.Reason = err.Error()
	}
	j.appendEvent(final)
	if j.cleanup != nil {
		j.cleanup()
	}
	close(j.done)
}

// resultPayload renders the finished report for the stream and the poll
// endpoint, so both carry exactly the same evidence.
func (j *NucleiJob) resultPayload() map[string]interface{} {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	if j.run == nil {
		return nil
	}
	return map[string]interface{}{
		"url":       j.run.Stats["url"],
		"findings":  j.run.Findings,
		"templates": j.run.Templates,
		"stats":     j.run.Stats,
	}
}

// Snapshot is the JSON shape returned for a job poll.
type Snapshot struct {
	ID       string         `json:"id"`
	State    string         `json:"state"`
	Progress NucleiProgress `json:"progress"`
	Result   *NucleiRun     `json:"result,omitempty"`
	Error    string         `json:"error,omitempty"`
	Reason   string         `json:"reason,omitempty"`
}

// Snapshot returns the pollable state of the job.
func (j *NucleiJob) Snapshot() Snapshot {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	snapshot := Snapshot{ID: j.ID, State: j.progress.Phase, Progress: j.progress, Result: j.run}
	if j.err != nil {
		snapshot.Error = j.err.Error()
		if strings.Contains(j.err.Error(), "context canceled") || strings.Contains(j.err.Error(), "operation was canceled") {
			snapshot.State = JobCancelled
			snapshot.Reason = "ROUTE_CHANGED"
		}
	}
	return snapshot
}

// Wait blocks until the job finishes and then returns its snapshot.
func (j *NucleiJob) Wait() Snapshot {
	<-j.done
	return j.Snapshot()
}

// jobStore keeps running jobs addressable by id.
type jobStore struct {
	mutex sync.Mutex
	jobs  map[string]*NucleiJob
}

var nucleiJobs = &jobStore{jobs: map[string]*NucleiJob{}}

func (s *jobStore) add(job *NucleiJob) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.jobs[job.ID] = job
}

func (s *jobStore) get(id string) (*NucleiJob, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	job, ok := s.jobs[id]
	return job, ok
}

func (s *jobStore) drop(id string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.jobs, id)
}

// sweepFinished removes jobs that finished long enough ago for every poll to
// have observed them, so a finished scan cannot accumulate in memory.
func (s *jobStore) sweepFinished(ttl time.Duration) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for id, job := range s.jobs {
		// The phase is written by the job's own goroutine from every stats line
		// the binary produces, so it is read under the job's lock. Holding only
		// the store lock does not help: the two locks guard different fields, and
		// the store lock is not the one the writer takes.
		job.mutex.Lock()
		phase := job.progress.Phase
		job.mutex.Unlock()
		if phase == JobQueued || phase == JobRunning || phase == JobPaused {
			continue
		}
		if time.Since(job.CreatedAt) > ttl {
			delete(s.jobs, id)
		}
	}
}

// StartNucleiJob runs a staged upload in the background and reports live
// progress. The staged directory and the caller's route lease are released when
// the run ends, whether it finished, failed or was cancelled. Passing a lease
// release is what allows the job to outlive the HTTP request that started it.
func StartNucleiJob(parent context.Context, uploadID string, request NucleiRequest, leaseRelease func()) (*NucleiJob, error) {
	session, ok := uploads.Take(strings.TrimSpace(uploadID))
	if !ok {
		if leaseRelease != nil {
			leaseRelease()
		}
		return nil, fmt.Errorf("upload %q is unknown or already consumed", uploadID)
	}
	return startNucleiJob(parent, session.Dir, session.Staged, request, func() {
		os.RemoveAll(session.Dir)
		if leaseRelease != nil {
			leaseRelease()
		}
	})
}

// StartNucleiTemplateDirJob runs a template folder named on disk as a background
// job, the folder counterpart of `StartNucleiJob`.
//
// It is a job and not a blocking call for the same reason the upload run is one:
// a folder is thousands of documents and the browser follows live progress and
// streams per-template events, neither of which a single blocking request can
// deliver. The difference is ownership — an upload is a staged session this
// package consumes and deletes, while a folder is the operator's own directory,
// so this one is read in place and only the mirror beside it is removed.
func StartNucleiTemplateDirJob(parent context.Context, dir string, request NucleiRequest, leaseRelease func()) (*NucleiJob, error) {
	resolved, err := ResolveTemplateDir(dir)
	if err != nil {
		if leaseRelease != nil {
			leaseRelease()
		}
		return nil, err
	}
	root, cleanupRoot, err := templateMirrorRoot(resolved)
	if err != nil {
		if leaseRelease != nil {
			leaseRelease()
		}
		return nil, err
	}
	staged, err := stageTemplateDirInto(root, resolved)
	if err != nil {
		cleanupRoot()
		if leaseRelease != nil {
			leaseRelease()
		}
		return nil, err
	}
	return startNucleiJob(parent, root, staged, request, func() {
		cleanupRoot()
		if leaseRelease != nil {
			leaseRelease()
		}
	})
}

// startNucleiJob is the shared body of the two entry points: it registers the
// job, wires the callbacks that stream progress and results, and runs the plan
// on its own goroutine. `dir` is the root the plan stages batches under and
// `cleanup` releases whatever that root is — a staged upload or a folder mirror.
func startNucleiJob(parent context.Context, dir string, staged []StagedFile, request NucleiRequest, cleanup func()) (*NucleiJob, error) {
	filtered, err := filterStagedTemplatesByCategory(staged, request.CategoryPath)
	if err != nil {
		cleanup()
		return nil, err
	}
	staged = filtered
	id, err := newUploadID()
	if err != nil {
		cleanup()
		return nil, err
	}
	nucleiJobs.sweepFinished(30 * time.Minute)
	runCtx, cancel := context.WithCancel(parent)
	job := &NucleiJob{
		ID:        id,
		CreatedAt: time.Now(),
		progress:  NewNucleiProgress(JobQueued),
		cancel:    cancel,
		done:      make(chan struct{}),
		staged:    staged,
		waiters:   map[chan struct{}]struct{}{},
		cleanup:   cleanup,
	}
	nucleiJobs.add(job)

	request.OnStats = func(update NucleiProgress) {
		job.mutex.Lock()
		// Keep the authoritative elapsed value from the job clock so the timer
		// advances even between stats lines.
		update.ElapsedSeconds = time.Since(job.CreatedAt).Seconds()
		job.setProgressLocked(update)
		snapshot := update
		job.mutex.Unlock()
		// Progress is streamed as well as polled, so the browser needs no
		// polling request to follow a long scan.
		progress := snapshot
		job.appendEvent(TemplateEvent{Kind: EventProgress, Progress: &progress})
	}
	request.OnProcess = job.watchProcess
	// Tailing the report is what makes results appear while nuclei still works.
	request.OnOutput = func(path string) { go job.watchOutput(path) }
	request.OnPlan = func(plan *NucleiPlan) {
		job.mutex.Lock()
		job.resolve = plan.Resolve
		job.mutex.Unlock()
	}
	go func() {
		run, runErr := RunNucleiDir(runCtx, dir, staged, request)
		switch {
		case runErr == nil:
			job.finish(JobCompleted, &run, nil)
		case runCtx.Err() != nil, isContextError(runErr):
			job.finish(JobCancelled, nil, runErr)
		default:
			job.finish(JobFailed, nil, runErr)
		}
	}()
	return job, nil
}

// CancelNucleiJob stops a running job. It reports false when the job is
// unknown or already finished, so a second cancel is not silently accepted.
func CancelNucleiJob(id string) bool {
	job, ok := nucleiJobs.get(strings.TrimSpace(id))
	if !ok {
		return false
	}
	job.mutex.Lock()
	phase := job.progress.Phase
	jobActiveNow := jobActive(phase)
	// A stopped process does not react to the context until it is continued, so
	// cancelling a paused run has to hand the signal over first. resumeLocked
	// documents that the caller must hold the job mutex, and that is not
	// formality: the stats goroutine reads the same `paused` flag from
	// setProgressLocked to decide whether a line in the pipe still describes a
	// paused run. Releasing the lock between the two decisions let a stats line
	// read the flag mid-update, which is the one case the flag exists for.
	if jobActiveNow {
		job.resumeLocked()
	}
	job.mutex.Unlock()
	if !jobActiveNow {
		return false
	}
	job.cancel()
	return true
}

// NucleiJobSnapshot returns the pollable state of a job.
func NucleiJobSnapshot(id string) (Snapshot, bool) {
	job, ok := nucleiJobs.get(strings.TrimSpace(id))
	if !ok {
		return Snapshot{}, false
	}
	return job.Snapshot(), true
}

func isContextError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "context canceled")
}
