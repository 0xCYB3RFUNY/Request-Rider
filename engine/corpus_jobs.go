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
}

// snapshot returns the job as it is right now. A caller never sees a half-written
// finding slice or a counter read while a worker was still changing it.
func (j *corpusJob) snapshot() map[string]interface{} {
	j.mu.Lock()
	defer j.mu.Unlock()

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
func (j *corpusJob) run(ctx context.Context, input scannerCorpusRequest, transport http.RoundTripper) {
	j.mu.Lock()
	j.cancel = func() {}
	j.mu.Unlock()

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
		},
		OnFinding: func(finding scanner.CorpusFinding) {
			emit.Lock()
			findings = append(findings, finding)
			emit.Unlock()
		},
	})

	j.mu.Lock()
	defer j.mu.Unlock()
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
