package main

// The active scanner as a background job.
//
// The scan itself is `pkg/active`: it crawls, harvests surfaces, runs the
// detectors, correlates chains and attaches proofs, and it reports progress
// through a callback this file supplies. What lives here is only the part a
// browser needs and the package deliberately does not have — an identifier, a
// state a poll can read, a cancel handle, and a stream of events that survives
// the request that started the run.
//
// It is deliberately the same shape as the Nuclei job rather than a second idea
// of what a job is: `queued`/`running` and the three terminal states come from
// the same vocabulary `terminalStatus` already recognises, the stream writes the
// same `id:`/`event:`/`data:` frame, and the retention sweep that releases a
// finished run is the one in `job_retention.go` instead of a private timer.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"intruder/engine/pkg/active"
	"intruder/engine/pkg/runstate"
)

// Active scan job states.
//
// The three terminal values are the ones `terminalStatus` in job_retention.go
// already treats as finished, which is what makes the shared sweeper able to
// release this job without knowing that a second kind of job exists.
const (
	activeJobQueued    = "queued"
	activeJobRunning   = "running"
	activeJobPaused    = "paused"
	activeJobCompleted = "completed"
	activeJobCancelled = "cancelled"
	activeJobFailed    = "failed"
)

// activeScanInput is one run's request body.
//
// Every bound here is a number the operator sent. Zero means "no bound" for the
// crawl limits and "the default" for the transport ones, and none of them is
// clamped: a run is limited by cancel or by the network, not by this struct.
type activeScanInput struct {
	URL             string `json:"url"`
	MaxPages        int    `json:"max_pages"`
	MaxDepth        int    `json:"max_depth"`
	SameOrigin      *bool  `json:"same_origin"`
	Concurrency     int    `json:"concurrency"`
	FollowRedirects bool   `json:"follow_redirects"`
	DelayMS         int    `json:"delay_ms"`
	// BlindDelayMS is how long a blind technique may hold a target's
	// connection. Zero means the engine's documented default; there is no ceiling
	// on the value, and the field is absent when the browser did not send it.
	BlindDelayMS     int `json:"blind_delay_ms"`
	TimeoutMS        int `json:"timeout_ms"`
	FailurePause     int `json:"failure_pause"`
	RecordedFailures int `json:"recorded_failures"`
	// Params is the hidden-parameter wordlist: one parameter name per entry, the
	// names the application's own JavaScript binds. It has no default, and the
	// field rather than a detector default is what makes that visible: an empty
	// list is a run that did not ask for those probes, not a run that asked and
	// found nothing.
	Params []string `json:"params,omitempty"`
	// PathWordlist is the operator's dictionary for the path probe, one path per
	// entry. No default either, because this project already probes a short fixed
	// list of its own and a second default would fire the same requests twice.
	PathWordlist []string `json:"path_wordlist,omitempty"`
	toolRunRoute
}

// activeScanEvent is one line of the job's stream.
//
// The cursor is monotonic per job, so a reconnecting client can ask for
// everything after the last id it saw and neither lose a line nor see one
// twice. `Data` stays raw so the handler does not have to know what a progress
// update contains.
type activeScanEvent struct {
	ID   uint64          `json:"id"`
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data"`
}

// activeScanJob is one run in flight or finished.
type activeScanJob struct {
	id           string
	cancel       context.CancelFunc
	release      func()
	gate         *runstate.Gate
	ledger       *runstate.Ledger
	outbound     http.RoundTripper
	probeTimeout time.Duration

	mu       sync.RWMutex
	state    string
	progress active.Progress
	report   *active.Report
	sourceIP string
	failure  string
	// cursor is the last event's identifier. It only ever grows, which is what
	// makes `eventsSince` able to answer a reconnect without repeating or
	// dropping a line.
	cursor     uint64
	events     []activeScanEvent
	waiters    map[chan struct{}]struct{}
	finishedAt time.Time
	// settled means the run has published what it is going to publish.
	//
	// It is separate from the state because "completed" and "here is the report"
	// are two facts, and a reader holding only the first is worse off than one
	// holding neither: a poll would report completed with no findings, and a
	// stream would decide the job was finished and end without ever delivering
	// the run. So a terminal state does not read as finished until the run has
	// settled, whichever of the two happened first. That is what makes the
	// guarantee structural rather than a convention about the order of two calls.
	settled bool
}

// activeScanSnapshot is what a poll reads. It is a copy: a caller must not be
// able to reach into a running job through the pointer it was handed.
type activeScanSnapshot struct {
	ID         string              `json:"job_id"`
	State      string              `json:"state"`
	Progress   active.Progress     `json:"progress"`
	Result     *active.Report      `json:"result,omitempty"`
	SourceIP   string              `json:"source_ip,omitempty"`
	Error      string              `json:"error,omitempty"`
	Checkpoint runstate.Checkpoint `json:"checkpoint"`
}

// report builds the poll answer, including the finished report only once there
// is one. A run that failed still carries its partial report, because a scan
// that proved four things before the fifth page timed out has still proven four
// things.
func (j *activeScanJob) snapshot() activeScanSnapshot {
	j.mu.RLock()
	state := j.state
	progress := j.progress
	report := j.report
	sourceIP := j.sourceIP
	failure := j.failure
	gate := j.gate
	ledger := j.ledger
	j.mu.RUnlock()

	var checkpoint runstate.Checkpoint
	if gate != nil {
		checkpoint = gate.Checkpoint(0)
	} else if ledger != nil {
		checkpoint = ledger.LedgerCheckpoint(0)
	}
	if state == activeJobRunning && checkpoint.Paused {
		state = activeJobPaused
	}
	return activeScanSnapshot{
		ID:         j.id,
		State:      state,
		Progress:   progress,
		Result:     report,
		SourceIP:   sourceIP,
		Error:      failure,
		Checkpoint: checkpoint,
	}
}

// publish appends an event and wakes every stream waiting for one.
//
// The append happens under the lock so the cursor stays ordered; the wake-ups
// happen after it so a waiter that wakes cannot read a half-written slice.
func (j *activeScanJob) publish(kind string, payload interface{}) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return
	}
	j.mu.Lock()
	j.cursor++
	j.events = append(j.events, activeScanEvent{ID: j.cursor, Kind: kind, Data: encoded})
	waiters := make([]chan struct{}, 0, len(j.waiters))
	for waiter := range j.waiters {
		waiters = append(waiters, waiter)
	}
	j.mu.Unlock()
	for _, waiter := range waiters {
		select {
		case waiter <- struct{}{}:
		default:
		}
	}
}

// eventsSince returns everything after a cursor, which is how a reconnecting
// client is answered without replaying the whole run.
func (j *activeScanJob) eventsSince(cursor uint64) []activeScanEvent {
	j.mu.RLock()
	defer j.mu.RUnlock()
	out := make([]activeScanEvent, 0, len(j.events))
	for _, event := range j.events {
		if event.ID > cursor {
			out = append(out, event)
		}
	}
	return out
}

// subscribe registers a wake-up channel and returns the backlog plus a function
// that removes it. The caller must call the returned function, or the job keeps
// a channel for a stream that is gone.
func (j *activeScanJob) subscribe(cursor uint64) ([]activeScanEvent, chan struct{}, func()) {
	waiter := make(chan struct{}, 1)
	j.mu.Lock()
	j.waiters[waiter] = struct{}{}
	backlog := make([]activeScanEvent, 0, len(j.events))
	for _, event := range j.events {
		if event.ID > cursor {
			backlog = append(backlog, event)
		}
	}
	j.mu.Unlock()
	return backlog, waiter, func() {
		j.mu.Lock()
		delete(j.waiters, waiter)
		j.mu.Unlock()
	}
}

// finished reports whether the job reached a terminal state *and* published
// everything it was going to publish.
func (j *activeScanJob) finished() bool {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return terminalStatus(j.state) && j.settled
}

// settle records that the run has nothing further to send.
//
// A cancel calls it without a report, because a stopped run has no report to
// deliver; a finished run calls it after its terminal event has been published.
func (j *activeScanJob) settle() {
	j.mu.Lock()
	j.settled = true
	j.mu.Unlock()
}

// setState records a new state and, for a terminal one, the time it happened.
// The sweeper reads that time, so a job that is never stamped is never released
// and a live run cannot be swept out from under the browser.
func (j *activeScanJob) setState(state string) {
	j.mu.Lock()
	j.state = state
	if terminalStatus(state) {
		j.finishedAt = time.Now()
	}
	j.mu.Unlock()
}

// register stores the job so it can be polled and streamed.
func (s *server) registerActiveScanJob(job *activeScanJob) {
	s.activeScansMu.Lock()
	if s.activeScans == nil {
		s.activeScans = map[string]*activeScanJob{}
	}
	s.activeScans[job.id] = job
	s.activeScansMu.Unlock()
}

// activeScanJobByID returns the job, or false when it is unknown or already
// collected. The caller says which of the two it is in the message.
func (s *server) activeScanJobByID(id string) (*activeScanJob, bool) {
	s.activeScansMu.RLock()
	defer s.activeScansMu.RUnlock()
	job, ok := s.activeScans[id]
	return job, ok
}

// nextActiveScanID produces a readable identifier.
//
// It is derived from the sequence rather than from a counter that could repeat
// after a restart, and a collision is not fatal: the check below retries with the
// next value rather than overwriting a run that is still readable.
func (s *server) nextActiveScanID() string {
	for {
		s.activeScansMu.Lock()
		s.activeScanSequence++
		candidate := fmt.Sprintf("active-%d", s.activeScanSequence)
		_, taken := s.activeScans[candidate]
		s.activeScansMu.Unlock()
		if !taken {
			return candidate
		}
	}
}

// startActiveScanJob begins a run and returns immediately with its identifier.
//
// The run is bound to the route generation rather than to the request context,
// so it survives the response that started it and is still cancelled by
// `Apply route`. The transport uses the selected route and records directly in
// the shared Store when the gateway named a capture context.
func (s *server) startActiveScanJob(parent context.Context, input activeScanInput) (*activeScanJob, error) {
	target := strings.TrimSpace(input.URL)
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("url must be an absolute http or https URL")
	}
	transport, err := s.toolRouteTransport(input.toolRunRoute)
	if err != nil {
		return nil, err
	}

	_, routeContext, release := s.bindBackgroundRouteContext(parent)
	runContext, cancel := context.WithCancel(routeContext)

	ledger := runstate.NewLedger(runstate.ResolveRecordedFailures(input.RecordedFailures))
	gate := runstate.NewGate(ledger, runstate.ResolveFailurePause(input.FailurePause))
	probeTimeout := time.Duration(input.TimeoutMS) * time.Millisecond

	request := active.ScanRequest{
		URL:             parsed.String(),
		MaxPages:        input.MaxPages,
		MaxDepth:        input.MaxDepth,
		SameOrigin:      input.SameOrigin,
		Concurrency:     input.Concurrency,
		FollowRedirects: input.FollowRedirects,
		Delay:           time.Duration(input.DelayMS) * time.Millisecond,
		BlindDelay:      time.Duration(input.BlindDelayMS) * time.Millisecond,
		Timeout:         probeTimeout,
		// The two operator-supplied wordlists. They are fields on the run rather
		// than detector defaults, so a run without them spends nothing on those
		// detectors and the report still says the detectors were in the set.
		Params:       input.Params,
		PathWordlist: input.PathWordlist,
		RoundTripper: transport,
		Gate:         gate,
		Ledger:       ledger,
		// The browser, when one was configured. Nil is a real state and not a
		// silent downgrade: the run then proves what a response body can prove and
		// its report says the escaping rows were never executed.
		Renderer:          activeBrowserRenderer(),
		BrowserCandidates: activeBrowserCandidates(),
	}

	job := &activeScanJob{
		id:           s.nextActiveScanID(),
		cancel:       cancel,
		release:      release,
		gate:         gate,
		ledger:       ledger,
		outbound:     transport,
		probeTimeout: probeTimeout,
		state:        activeJobQueued,
		waiters:      map[chan struct{}]struct{}{},
		// A queued run reports an unknown total rather than a false zero, so a
		// panel can show an indeterminate bar instead of "0% done".
		progress: active.Progress{Phase: activeJobQueued, PagesTotal: -1, PointsTotal: -1},
	}
	gate.Observe(func(paused bool, reason string, dropped int) {
		job.mu.Lock()
		if paused && job.state == activeJobRunning {
			job.state = activeJobPaused
		} else if !paused && job.state == activeJobPaused {
			job.state = activeJobRunning
		}
		job.mu.Unlock()
		if paused {
			job.publish("paused", job.snapshot())
		} else {
			job.publish("resumed", job.snapshot())
		}
	})
	// Every row the run proves is published the moment it is proved, not held
	// until the terminal event. That is the difference between a browser whose
	// findings table fills while the run works and one that watches a counter
	// rise for several minutes and then receives everything at once — and the
	// counter was the only live thing on screen, which is why "282 findings" said
	// nothing about what had been found.
	//
	// The event carries the row and shares the cursor with the progress events,
	// so a client that reconnects asks for the last id it saw and neither loses
	// a row nor receives one twice. The row published here is the row as its
	// detector proved it: a proof may raise its tier before the run ends, and the
	// terminal report — which carries those upgrades — replaces whatever a client
	// rendered from these.
	request.FindingSink = func(row active.Finding) {
		job.publish("finding", row)
	}
	s.registerActiveScanJob(job)

	go func() {
		defer release()
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				failureMsg := fmt.Sprintf("panic: %v", r)
				final := active.Progress{Phase: activeJobFailed, Error: failureMsg}
				job.mu.Lock()
				job.progress = final
				job.failure = failureMsg
				sourceIP := job.sourceIP
				job.mu.Unlock()
				job.publish("done", activeScanSnapshot{
					ID:       job.id,
					State:    activeJobFailed,
					Progress: final,
					SourceIP: sourceIP,
					Error:    failureMsg,
				})
				job.setState(activeJobFailed)
				job.settle()
			}
		}()
		job.setState(activeJobRunning)
		// The lookup is started on the run's own route context, so the reported
		// source_ip is the address the run's own requests leave from rather than
		// one inherited from the browser's route.
		job.mu.Lock()
		job.sourceIP = s.ensureSourceIP(routeContext)
		job.mu.Unlock()

		scan := active.NewScan(request, func(progress active.Progress) {
			job.mu.Lock()
			job.progress = progress
			job.mu.Unlock()
			job.publish("progress", progress)
		})
		report, runErr := scan.Run(runContext)

		finalState := activeJobCompleted
		failure := ""
		switch {
		case runContext.Err() != nil:
			finalState = activeJobCancelled
		case runErr != nil:
			finalState = activeJobFailed
			failure = runErr.Error()
		}
		final := active.Progress{Phase: finalState, Findings: findingCount(report)}
		// The run's own counters are carried into the terminal progress.
		//
		// They used to be dropped here, and the panel read the number straight
		// from this struct: a scan that reported "Pages 34" for minutes while it
		// worked reported "Pages 0" the moment it finished. A counter that resets
		// to zero at the end is worse than no counter, because the zero looks
		// measured — and it is the panel's last word, the line an operator reads
		// after copying the result out.
		if report != nil {
			final.PagesFetched = report.Pages
			final.PagesTotal = report.Pages
			if len(report.Points) > 0 {
				final.PointsTested = len(report.Points)
				final.PointsTotal = len(report.Points)
			}
		}

		job.mu.Lock()
		job.report = report
		job.progress = final
		job.failure = failure
		sourceIP := job.sourceIP
		job.mu.Unlock()

		var doneCheckpoint runstate.Checkpoint
		if job.gate != nil {
			doneCheckpoint = job.gate.Checkpoint(0)
		} else if job.ledger != nil {
			doneCheckpoint = job.ledger.LedgerCheckpoint(0)
		}

		// The terminal event is published before the state becomes terminal, and
		// the order is the point. A stream decides it is done by asking whether
		// the job is finished and has nothing left to send; a poll decides it is
		// done by the state alone. With the state first, a client arriving in that
		// window would read "completed" with no report, and a stream would end
		// without ever delivering the run it came for.
		job.publish("done", activeScanSnapshot{
			ID:         job.id,
			State:      finalState,
			Progress:   final,
			Result:     report,
			SourceIP:   sourceIP,
			Error:      failure,
			Checkpoint: doneCheckpoint,
		})
		job.setState(finalState)
		job.settle()
	}()

	return job, nil
}

// findingCount is the running total a progress panel shows. A nil report is a
// run that failed before producing one, and it has no findings rather than an
// unknown number of them.
func findingCount(report *active.Report) int {
	if report == nil {
		return 0
	}
	return len(report.Findings)
}

// cancelActiveScanJob stops a running scan.
//
// It reports false when the job is unknown or already finished, so the caller can
// answer "already collected" instead of pretending it stopped something.
// activeBrowserRenderer builds the renderer a run uses to settle its escaping
// rows in a real browser, and returns nil when no worker was configured.
//
// It has no default URL on purpose. The worker is a separate service on its own
// port, and a run that quietly reached for a port nothing was listening on would
// pay a confirmation timeout for every escaping row to learn the same thing once
// — a cost paid in the operator's time and reported as nothing. So the URL is
// stated, and a run without it has no renderer and says so in its report.
//
// This is the worker's own service and its own protocol, not a second browser
// stack: the same process Target's browser-driven mode drives.
func activeBrowserRenderer() active.Renderer {
	base := strings.TrimSpace(os.Getenv("RR_ACTIVE_BROWSER_URL"))
	if base == "" {
		return nil
	}
	renderer := &active.WorkerRenderer{
		BaseURL: base,
	}
	// The navigation deadline is the operator's when they state one: the worker
	// applies it to the page, so a page that hangs ends on this number rather
	// than on a library default nobody in this project chose.
	if raw := strings.TrimSpace(os.Getenv("RR_ACTIVE_BROWSER_NAV_TIMEOUT_MS")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			renderer.NavigationTimeout = time.Duration(parsed) * time.Millisecond
		}
	}
	return renderer
}

// activeBrowserCandidates reads the per-row bound on executed expressions.
//
// Zero — the default — means every expression, and a negative or unreadable value is
// zero too rather than a guess: the field exists so an operator can pay less, never
// so a run can quietly try fewer than it says.
func activeBrowserCandidates() int {
	raw := strings.TrimSpace(os.Getenv("RR_ACTIVE_BROWSER_CANDIDATES"))
	if raw == "" {
		return 0
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < 0 {
		return 0
	}
	return parsed
}

func (s *server) cancelActiveScanJob(id string) bool {
	job, ok := s.activeScanJobByID(id)
	if !ok {
		return false
	}
	if job.finished() {
		return false
	}
	if job.gate != nil {
		job.gate.Resume()
	}
	job.cancel()
	// The state is set here rather than only in the run goroutine because a
	// cancel that lands between two probes would otherwise leave a poll
	// reporting "running" until the current request finished. It settles as well: a
	// stopped run has no report to deliver, so a stream waiting for one would
	// otherwise wait for an event that is never coming.
	job.setState(activeJobCancelled)
	job.settle()
	return true
}

// scannerActiveScan starts an asynchronous active scan.
//
// A run outlives the request that started it, so it is a job: the browser gets
// an identifier and polls or streams it, instead of holding one connection open
// for a scan that can take minutes.
func (s *server) scannerActiveScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	var input activeScanInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
		return
	}
	if strings.TrimSpace(input.URL) == "" {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_URL", fmt.Errorf("url is required"))
		return
	}
	job, err := s.startActiveScanJob(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_TARGET_URL", err)
		return
	}
	// The run is already going by the time this line executes, so the answer is
	// read through the snapshot rather than off the fields: reading them directly
	// is an unsynchronised read of a goroutine that is already writing them, and
	// `-race` says so.
	started := job.snapshot()
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"job_id": started.ID, "state": started.State, "progress": started.Progress,
		"checkpoint": started.Checkpoint,
	})
}

// scannerActiveJobStatus polls a run and applies its control actions.
//
// The trailing segment decides what the request means: "/stream" subscribes,
// "/cancel", "/pause", "/resume", "/resend" act on the run, and anything else is a poll.
func (s *server) scannerActiveJobStatus(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.URL.Path, "/proxy/scanner/active/jobs/")
	if strings.HasSuffix(raw, "/stream") {
		s.scannerActiveJobStream(w, r)
		return
	}
	if idx := strings.IndexByte(raw, '/'); idx != -1 {
		id := raw[:idx]
		action := raw[idx+1:]
		s.scannerActiveJobAction(w, r, id, action)
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	job, ok := s.activeScanJobByID(raw)
	if !ok {
		writeError(w, http.StatusNotFound, "UNKNOWN_JOB", fmt.Errorf("job %q is unknown or already collected", raw))
		return
	}
	writeJSON(w, http.StatusOK, job.snapshot())
}

type resendOutcome struct {
	Method     string `json:"method"`
	URL        string `json:"url"`
	Status     int    `json:"status,omitempty"`
	Class      string `json:"class,omitempty"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

type resendReport struct {
	Requested    int             `json:"requested"`
	Resent       int             `json:"resent"`
	Answered     int             `json:"answered"`
	StillFailing int             `json:"still_failing"`
	Outcomes     []resendOutcome `json:"outcomes"`
}

func drainLedgerForResend(ledger *runstate.Ledger, limit int) []runstate.Failure {
	if ledger == nil {
		return nil
	}
	all := ledger.Take()
	if limit > 0 && len(all) > limit {
		rest := all[limit:]
		all = all[:limit]
		for _, f := range rest {
			ledger.Record(f)
		}
	}
	return all
}

func executeResendBatch(ctx context.Context, batch []runstate.Failure, outbound http.RoundTripper, timeout time.Duration, ledger *runstate.Ledger) resendReport {
	if outbound == nil {
		outbound = http.DefaultTransport
	}
	if timeout <= 0 {
		timeout = active.DefaultTimeout
	}
	report := resendReport{
		Requested: len(batch),
		Outcomes:  make([]resendOutcome, 0, len(batch)),
	}
	for _, item := range batch {
		method := strings.TrimSpace(item.Method)
		if method == "" {
			method = http.MethodGet
		}
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(reqCtx, method, item.URL, nil)
		if err != nil {
			cancel()
			class := runstate.ClassifyTransportError(err)
			if ledger != nil {
				ledger.Record(runstate.Failure{Method: method, URL: item.URL, Class: class, Error: err.Error()})
			}
			report.StillFailing++
			report.Outcomes = append(report.Outcomes, resendOutcome{
				Method: method, URL: item.URL, Class: class, Error: err.Error(),
			})
			continue
		}
		report.Resent++
		started := time.Now()
		resp, err := outbound.RoundTrip(req)
		elapsed := time.Since(started).Milliseconds()
		if err != nil {
			cancel()
			class := runstate.ClassifyTransportError(err)
			if class == runstate.ClassCanceled && item.Class != "" {
				class = item.Class
			}
			if ledger != nil {
				ledger.Record(runstate.Failure{Method: method, URL: item.URL, Class: class, Error: err.Error(), DurationMS: elapsed})
			}
			report.StillFailing++
			report.Outcomes = append(report.Outcomes, resendOutcome{
				Method: method, URL: item.URL, Class: class, Error: err.Error(), DurationMS: elapsed,
			})
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		cancel()
		if ledger != nil {
			ledger.Success(item.URL)
		}
		report.Answered++
		report.Outcomes = append(report.Outcomes, resendOutcome{
			Method: method, URL: item.URL, Status: resp.StatusCode, DurationMS: elapsed,
		})
	}
	return report
}

// scannerActiveJobAction handles cancel, pause, resume, and resend on a running scan.
func (s *server) scannerActiveJobAction(w http.ResponseWriter, r *http.Request, id, action string) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", fmt.Errorf("method %s not allowed", r.Method))
		return
	}
	switch action {
	case "cancel", "pause", "resume", "resend":
	default:
		writeError(w, http.StatusBadRequest, "INVALID_JOB_ACTION", fmt.Errorf("unknown job action %q", action))
		return
	}
	if action == "cancel" {
		if !s.cancelActiveScanJob(id) {
			writeError(w, http.StatusNotFound, "UNKNOWN_JOB", fmt.Errorf("job %q is unknown or already finished", id))
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"job_id": id, "state": activeJobCancelled})
		return
	}
	job, ok := s.activeScanJobByID(id)
	if !ok || job.finished() {
		writeError(w, http.StatusNotFound, "UNKNOWN_JOB", fmt.Errorf("job %q is unknown or already finished", id))
		return
	}
	var payload struct {
		Reason string `json:"reason"`
		Limit  int    `json:"limit"`
	}
	if r.Body != nil {
		rawBody, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if trimmed := strings.TrimSpace(string(rawBody)); trimmed != "" {
			if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
				writeError(w, http.StatusBadRequest, "INVALID_JSON", err)
				return
			}
		}
	}
	switch action {
	case "pause":
		reason := strings.TrimSpace(payload.Reason)
		if reason == "" {
			reason = "paused by operator"
		}
		if job.gate != nil {
			job.gate.Pause(reason)
		}
		job.setState(activeJobPaused)
		snap := job.snapshot()
		writeJSON(w, http.StatusOK, snap)
	case "resume":
		if job.gate != nil {
			job.gate.Resume()
		}
		job.setState(activeJobRunning)
		snap := job.snapshot()
		writeJSON(w, http.StatusOK, snap)
	case "resend":
		if payload.Limit < 0 {
			writeError(w, http.StatusBadRequest, "INVALID_RESEND", fmt.Errorf("limit must not be negative"))
			return
		}
		batch := drainLedgerForResend(job.ledger, payload.Limit)
		report := executeResendBatch(r.Context(), batch, job.outbound, job.probeTimeout, job.ledger)
		snap := job.snapshot()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"job_id":     id,
			"state":      snap.State,
			"reason":     payload.Reason,
			"resend":     report,
			"checkpoint": snap.Checkpoint,
		})
	}
}

// scannerActiveJobStream follows a running scan.
//
// Progress arrives while the run works instead of appearing all at once at the
// end, and the terminal event carries the finished report.
func (s *server) scannerActiveJobStream(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/proxy/scanner/active/jobs/"), "/stream")
	job, ok := s.activeScanJobByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, "UNKNOWN_JOB", fmt.Errorf("job %q is unknown or already collected", id))
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "STREAM_UNSUPPORTED", fmt.Errorf("streaming is not supported"))
		return
	}
	// These headers disable intermediary buffering for the live stream.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	cursor := parseEventCursor(r)
	backlog, updates, unsubscribe := job.subscribe(cursor)
	defer unsubscribe()

	send := func(event activeScanEvent) {
		_, _ = fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.ID, event.Kind, event.Data)
		flusher.Flush()
	}
	for _, event := range backlog {
		send(event)
		cursor = event.ID
	}
	// A quiet run still has to produce bytes: a crawl can go a long time between
	// progress reports, and a stream that only writes on real updates looks dead
	// to every hop in between. The comment line is ignored by EventSource.
	heartbeat := time.NewTicker(scannerStreamHeartbeat)
	defer heartbeat.Stop()
	for {
		if job.finished() && len(job.eventsSince(cursor)) == 0 {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-updates:
		case <-heartbeat.C:
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
		for _, event := range job.eventsSince(cursor) {
			send(event)
			cursor = event.ID
		}
	}
}
