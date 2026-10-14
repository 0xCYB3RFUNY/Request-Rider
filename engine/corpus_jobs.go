package main

// The corpus job endpoints.
//
// The corpus run was one blocking request. Measured on a live `.ru` target through
// the browser: 361 seconds and then `NetworkError when attempting to fetch
// resource` — a run of 5792 requests does not fit in one browser connection, and
// the ceiling that failed it was invisible to the operator. That is the project's
// own contract for long scans written down (`Часть V`, «Поведение Scanner»): a long
// run is a background job with an id, polled while it runs, and the final report
// is authoritative. This file is that shape for the corpus.
//
// Nothing here bounds a run. The job lives until the process exits or the operator
// asks for it to be dropped; `max_checks` stays an operator choice the UI does not
// set by default.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"intruder/engine/pkg/scanner"
)

// corpusJob is one running or finished corpus enumeration.
type corpusJob struct {
	mu sync.Mutex

	ID      string
	Target  string
	Started time.Time

	state    string // "running", "completed", "failed", "cancelled"
	progress scanner.CorpusProgress
	findings []scanner.CorpusFinding
	result   scanner.CorpusRunResult
	stats    scanner.CorpusStats
	err      string

	cancel context.CancelFunc

	// Subscribers see progress and findings as they happen, so the operator
	// watches the run instead of waiting for its verdict. A corpus run is
	// thousands of requests; with polling alone nothing appeared on screen until
	// the last one answered, which is indistinguishable from a hung scan.
	subsMu  sync.Mutex
	subs    map[int]*corpusSubscriber
	nextSub int
	seq     int
}

// corpusEvent is one server-sent frame: a monotonic id so a reconnecting browser
// can tell what it already has, a kind the browser dispatches on, and the payload.
type corpusEvent struct {
	ID      int                    `json:"id"`
	Kind    string                 `json:"kind"`
	Payload map[string]interface{} `json:"payload"`
}

// corpusSubscriber is one listener's ordered queue and the goroutine that drains
// it into the channel the stream reads.
//
// It replaces a fixed 64-slot channel, and the reason is measured rather than
// preferred. That channel dropped any frame it could not hand over immediately,
// `select` with a `default:`, and the comment above it claimed the stream would
// notice the loss and reconnect so the browser could re-read the snapshot. It
// could not: a dropped frame never entered the channel, so `send` in
// `streamCorpusJob` had nothing to fail on — it only reports a socket write error
// — and the listener stayed attached for the rest of the run holding a table the
// progress counter had already run past. The operator's report is exactly that
// shape: the header read five findings and the table held one row.
//
// Losing a frame is only acceptable for a frame whose loss loses nothing, and a
// progress frame is one: it is a snapshot, so the next one supersedes it. A
// finding is evidence and the terminal frame is the whole report, so neither is
// ever dropped here. Both are appended unconditionally.
type corpusSubscriber struct {
	mu     sync.Mutex
	cond   *sync.Cond
	queue  []corpusEvent
	closed bool
	once   sync.Once
	output chan corpusEvent
}

func newCorpusSubscriber() *corpusSubscriber {
	subscriber := &corpusSubscriber{output: make(chan corpusEvent)}
	subscriber.cond = sync.NewCond(&subscriber.mu)
	go subscriber.forward()
	return subscriber
}

// forward drains the queue into the output channel.
//
// The lock is released before the send, so a listener that stopped reading holds
// the goroutine without holding the publisher: a run never stalls behind a tab
// that went to sleep. That is what the fixed-size channel's `default:` was there
// to guarantee, and it is kept — by moving the wait off the publisher instead of
// by discarding what the publisher was asked to send.
func (subscriber *corpusSubscriber) forward() {
	defer close(subscriber.output)
	for {
		subscriber.mu.Lock()
		for len(subscriber.queue) == 0 && !subscriber.closed {
			subscriber.cond.Wait()
		}
		if len(subscriber.queue) == 0 {
			subscriber.mu.Unlock()
			return
		}
		event := subscriber.queue[0]
		subscriber.queue = subscriber.queue[1:]
		subscriber.mu.Unlock()
		subscriber.output <- event
	}
}

// enqueue appends a frame, coalescing progress with the progress already waiting.
//
// Coalescing is what keeps the queue bounded without discarding evidence: at most
// one progress frame is ever pending, because only the newest one says anything a
// reader has not already been told, while every finding and the terminal frame are
// appended as they arrive. The backlog therefore grows with the findings the run
// actually produced — which the job already holds in `j.findings` — and not with
// the thousands of progress frames a long run emits.
func (subscriber *corpusSubscriber) enqueue(event corpusEvent) {
	subscriber.mu.Lock()
	defer subscriber.mu.Unlock()
	if subscriber.closed {
		return
	}
	if event.Kind == "progress" {
		for index := range subscriber.queue {
			if subscriber.queue[index].Kind == "progress" {
				subscriber.queue = append(subscriber.queue[:index], subscriber.queue[index+1:]...)
				break
			}
		}
	}
	subscriber.queue = append(subscriber.queue, event)
	subscriber.cond.Signal()
}

func (subscriber *corpusSubscriber) close() {
	subscriber.once.Do(func() {
		subscriber.mu.Lock()
		subscriber.closed = true
		subscriber.mu.Unlock()
		subscriber.cond.Broadcast()
	})
}

// queued reports how many frames are waiting to be handed over. It exists so a
// test can measure the backlog the run really leaves behind, which is the number
// the dropped-frame version could not report: a dropped frame left no trace.
func (subscriber *corpusSubscriber) queued() int {
	subscriber.mu.Lock()
	defer subscriber.mu.Unlock()
	return len(subscriber.queue)
}

// subscribe attaches a listener and returns the channel plus its detach
// function. A detached listener stops receiving and its channel is closed;
// publishing after a detach is a no-op rather than a panic.
func (j *corpusJob) subscribe() (<-chan corpusEvent, func()) {
	subscriber := newCorpusSubscriber()
	j.subsMu.Lock()
	if j.subs == nil {
		j.subs = map[int]*corpusSubscriber{}
	}
	id := j.nextSub
	j.nextSub++
	j.subs[id] = subscriber
	j.subsMu.Unlock()
	return subscriber.output, func() {
		j.subsMu.Lock()
		existing, ok := j.subs[id]
		delete(j.subs, id)
		j.subsMu.Unlock()
		if ok {
			existing.close()
		}
	}
}

// publish hands an event to every listener without waiting for one to read it.
//
// The send never blocks. A listener is a browser on a socket that can stop reading
// at any moment, and a run must not stall because one tab went to sleep; what it
// may lose is decided per kind inside `enqueue`, not here, where every kind looks
// the same and the only available choice is to throw one away.
func (j *corpusJob) publish(kind string, payload map[string]interface{}) {
	j.subsMu.Lock()
	j.seq++
	event := corpusEvent{ID: j.seq, Kind: kind, Payload: payload}
	for _, subscriber := range j.subs {
		subscriber.enqueue(event)
	}
	j.subsMu.Unlock()
}

// progressPayload is the progress numbers a listener is sent. It is read under
// the same lock as `snapshot`, so a frame never carries a counter read while a
// worker was still changing it.
func (j *corpusJob) progressPayload() map[string]interface{} {
	j.mu.Lock()
	defer j.mu.Unlock()
	return map[string]interface{}{
		"requests_done":  j.progress.Done,
		"requests_total": j.progress.Total,
		"checks":         j.progress.Checks,
		"findings":       j.progress.Findings,
		// -1 means the total is not known yet, and the panel shows an
		// indeterminate bar. A number there would be a guess.
		"percent":    j.progress.Percent,
		"skipped":    j.progress.Skipped,
		"truncated":  j.result.Truncated,
		"elapsed_ms": time.Since(j.Started).Milliseconds(),
		"state":      j.state,
	}
}

// snapshot returns the job as it is right now. A caller never sees a half-written
// finding slice or a counter read while a worker was still changing it.
func (j *corpusJob) snapshot() map[string]interface{} {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.snapshotLocked()
}

// snapshotLocked is `snapshot` for a caller that already holds the lock.
//
// It exists because `run` finishes by building its terminal frame while it holds
// the lock. Calling `snapshot` there re-entered a `sync.Mutex`, which deadlocks a
// process on itself — measured, not theoretical: every corpus job finished by
// wedging `run`, and because the browser polls the same job the handler goroutines
// piled up behind the locked mutex until the engine stopped answering `/health`
// (`engine unavailable: timed out` from Django, HTTP 502).
func (j *corpusJob) snapshotLocked() map[string]interface{} {
	report := map[string]interface{}{
		"job_id":  j.ID,
		"url":     j.Target,
		"state":   j.state,
		"started": j.Started.UTC().Format(time.RFC3339),
		"progress": map[string]interface{}{
			"requests_done":  j.progress.Done,
			"requests_total": j.progress.Total,
			"checks":         j.progress.Checks,
			"findings":       j.progress.Findings,
			// -1 means the total is not known yet, and the panel shows an
			// indeterminate bar. A number there would be a guess.
			"percent": j.progress.Percent,
			// Rows whose request never came back. Sent as its own number because the
			// gap between it and the corpus size is a fact about the target, not a
			// number the reader is left to subtract.
			"skipped":    j.progress.Skipped,
			"truncated":  j.result.Truncated,
			"elapsed_ms": time.Since(j.Started).Milliseconds(),
		},
	}
	if j.state == "failed" {
		report["error"] = j.err
	}
	if j.state == "completed" {
		report["findings"] = j.findings
		report["finding_count"] = len(j.findings)
		report["requests"] = j.result.Requests
		report["checks"] = j.result.Checks
		report["stats"] = j.stats
		report["duration_ms"] = j.result.Duration.Milliseconds()
		report["truncated"] = j.result.Truncated
	}
	return report
}

// scannerCorpusJobs starts a run and reports on it.
//
// `POST` starts and answers immediately with a job id; `GET /<id>` reports. The
// immediate answer is the whole point: the browser's connection is no longer part
// of how long a scan may take.
func (s *server) scannerCorpusJobs(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/proxy/scanner/corpus/jobs":
		s.startCorpusJob(w, r)
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/stream"):
		s.streamCorpusJob(w, r)
	case r.Method == http.MethodGet:
		s.reportCorpusJob(w, r)
	case r.Method == http.MethodDelete:
		s.cancelCorpusJob(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			fmt.Errorf("method %s not allowed", r.Method))
	}
}

func (s *server) startCorpusJob(w http.ResponseWriter, r *http.Request) {
	var input scannerCorpusRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	parsed, err := url.Parse(strings.TrimSpace(input.URL))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_URL",
			fmt.Errorf("url must be an absolute http or https URL"))
		return
	}
	if input.Concurrency < 0 || input.MaxChecks < 0 || input.TimeoutMS < 0 || input.DelayMS < 0 {
		writeError(w, http.StatusBadRequest, "INVALID_BOUND",
			fmt.Errorf("concurrency, max_checks, timeout_ms and delay_ms must not be negative"))
		return
	}

	// , not : the second ties the
	// context to the request, and a request context is cancelled the moment the
	// response is written. A job built on it is born already cancelled — measured:
	// every start answered \cancelled\ with zero requests sent.
	_, routeContext, release := s.bindBackgroundRouteContext(r.Context())
	transport, err := s.toolRouteTransport(input.toolRunRoute)
	if err != nil {
		release()
		writeError(w, http.StatusBadRequest, "INVALID_TOOL_PROXY", err)
		return
	}
	job := &corpusJob{
		ID:      newCorpusJobID(),
		Target:  parsed.String(),
		Started: time.Now(),
		state:   "running",
	}
	jobCtx, cancel := context.WithCancel(routeContext)
	job.cancel = cancel

	if s.corpusJobs == nil {
		s.corpusJobs = map[string]*corpusJob{}
	}
	s.corpusJobsMu.Lock()
	s.corpusJobs[job.ID] = job
	s.corpusJobsMu.Unlock()

	go func() {
		defer release()
		defer cancel()
		job.run(jobCtx, input, transport)
	}()

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"job_id": job.ID,
		"url":    job.Target,
		"state":  job.state,
	})
}

// run performs the enumeration and records everything a status call can report.
//
// The canceller set at start stays as it is. It used to be replaced here with a
// no-op "the run owns it now", and that made `Cancel` a control that did nothing:
// by the time an operator pressed it, the job's `cancel` was the empty function
// and the run continued to its end. Measured 2026-10-10 — a job cancelled 25 s
// into a 2500-check run was still `running` 32 s later, at every poll.
func (j *corpusJob) run(ctx context.Context, input scannerCorpusRequest, transport http.RoundTripper) {
	findings := make([]scanner.CorpusFinding, 0, 256)
	emit := sync.Mutex{}

	result, err := scanner.RunCorpus(ctx, scanner.CorpusRunRequest{
		Target:       j.Target,
		Tags:         input.Tags,
		MaxChecks:    input.MaxChecks,
		Concurrency:  input.Concurrency,
		Timeout:      time.Duration(input.TimeoutMS) * time.Millisecond,
		Delay:        time.Duration(input.DelayMS) * time.Millisecond,
		RoundTripper: transport,
		OnProgress: func(progress scanner.CorpusProgress) {
			j.mu.Lock()
			j.progress = progress
			j.mu.Unlock()
			j.publish("progress", j.progressPayload())
		},
		OnFinding: func(finding scanner.CorpusFinding) {
			emit.Lock()
			findings = append(findings, finding)
			emit.Unlock()
			// The finding goes out as it arrives, not at the end. A row the
			// operator can read while the run continues is the whole difference
			// between watching a scan and waiting for one.
			if data, err := json.Marshal(finding); err == nil {
				var payload map[string]interface{}
				if json.Unmarshal(data, &payload) == nil {
					j.publish("finding", payload)
				}
			}
		},
	})

	j.mu.Lock()
	j.findings = findings
	j.result = result
	j.stats = result.Stats
	j.progress.Checks = int64(result.Checks)
	j.progress.Findings = int64(result.Findings)
	j.progress.Done = int64(result.Requests)
	j.progress.Total = int64(result.Requests)
	if j.progress.Total > 0 {
		j.progress.Percent = 100
	}
	switch {
	case ctx.Err() != nil:
		j.state = "cancelled"
	case err != nil:
		j.state = "failed"
		j.err = err.Error()
	default:
		j.state = "completed"
	}
	// The terminal frame is the whole authoritative report, built under the same
	// lock the status endpoint uses. It is published after the lock is released:
	// `publish` takes the subscriber lock, and holding the job lock across a
	// fan-out would let one slow listener block the next status call.
	final := j.snapshotLocked()
	j.mu.Unlock()

	j.publish("done", final)
}

// corpusStreamKeepalive is how often the stream speaks when the run itself is
// quiet. A corpus run has no natural heartbeat — a slow target is not a dead job
// — and a stream that only wrote bytes on real progress was indistinguishable
// from a hung one.
const corpusStreamKeepalive = 15 * time.Second

// streamCorpusJob pushes progress and findings to the browser while the run
// continues, and ends with one authoritative frame.
//
// The first frame is the job as it stands, not the next event to happen. A
// browser that connects late, or reconnects after a dropped connection, therefore
// starts from the truth rather than from whatever arrives next — and `Last-Event-ID`
// stays meaningful without a replay buffer.
func (s *server) streamCorpusJob(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/proxy/scanner/corpus/jobs/"), "/stream")
	job := s.corpusJob(id)
	if job == nil {
		writeError(w, http.StatusNotFound, "UNKNOWN_JOB", fmt.Errorf("no corpus job %q", id))
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "STREAM_UNSUPPORTED",
			fmt.Errorf("streaming is not supported by this connection"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	events, detach := job.subscribe()
	defer detach()

	// Frame ids are drawn from the same counter the fan-out uses, so an id on the
	// wire names a real position in this job's event history.
	send := func(kind string, payload map[string]interface{}) bool {
		data, err := json.Marshal(payload)
		if err != nil {
			return true
		}
		job.subsMu.Lock()
		job.seq++
		frame := job.seq
		job.subsMu.Unlock()
		if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", frame, kind, data); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	current := job.snapshot()
	if !send("snapshot", current) {
		return
	}
	// A job that finished before the browser connected has nothing left to push:
	// the snapshot already carries its verdict.
	switch current["state"] {
	case "completed", "failed", "cancelled":
		send("done", current)
		return
	}

	ticker := time.NewTicker(corpusStreamKeepalive)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case event, open := <-events:
			if !open {
				return
			}
			if !send(event.Kind, event.Payload) {
				return
			}
			if event.Kind == "done" {
				return
			}
		case <-ticker.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *server) reportCorpusJob(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/proxy/scanner/corpus/jobs/")
	job := s.corpusJob(id)
	if job == nil {
		writeError(w, http.StatusNotFound, "UNKNOWN_JOB", fmt.Errorf("no corpus job %q", id))
		return
	}
	writeJSON(w, http.StatusOK, job.snapshot())
}

// cancelCorpusJob stops a running job. An operator who pointed the scanner at the
// wrong target should not have to restart the process to stop it.
func (s *server) cancelCorpusJob(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/proxy/scanner/corpus/jobs/")
	job := s.corpusJob(id)
	if job == nil {
		writeError(w, http.StatusNotFound, "UNKNOWN_JOB", fmt.Errorf("no corpus job %q", id))
		return
	}
	job.mu.Lock()
	cancel := job.cancel
	running := job.state == "running"
	job.mu.Unlock()
	if running && cancel != nil {
		cancel()
	}
	writeJSON(w, http.StatusOK, job.snapshot())
}

func (s *server) corpusJob(id string) *corpusJob {
	s.corpusJobsMu.Lock()
	defer s.corpusJobsMu.Unlock()
	return s.corpusJobs[id]
}

// newCorpusJobID names a job. Time alone would collide between two runs started in
// the same second, which is exactly what an operator comparing two scans does.
var corpusJobSequence atomic.Uint64

func newCorpusJobID() string {
	return fmt.Sprintf("corpus-%d-%d", time.Now().UnixNano(), corpusJobSequence.Add(1))
}
