package active

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// BrowserPage is what one real browser load produced.
//
// The field that matters is Network: it is the page's own list of requests, so a
// request the injected script caused is a fact about execution rather than a
// guess from a response body. Nothing else here is load-bearing — Status and URL
// are carried so a failure can be reported with the page it happened on.
type BrowserPage struct {
	// URL is where the browser ended up, which is not always where it was sent.
	URL string `json:"url"`
	// Status is the status the browser saw for the navigation, 0 when there was
	// no response at all.
	Status int `json:"status"`
	// Network is every request the page issued while it was loaded, in the order
	// the browser issued them.
	Network []string `json:"network"`
	// Error is the browser's own failure text, empty on a load that worked.
	Error string `json:"error,omitempty"`
}

// Requested reports whether the page asked for exactly this URL.
//
// Exact, not "contains": a marker is a URL this run chose, and a match that
// merely contains it would also match a page that merely echoes the injected
// text into a link — which is the reflection the detector already reports and
// must not be counted a second time as execution.
func (p BrowserPage) Requested(want string) bool {
	if strings.TrimSpace(want) == "" {
		return false
	}
	for _, seen := range p.Network {
		if seen == want {
			return true
		}
	}
	return false
}

// Renderer loads one URL in a real browser and reports what the page did.
//
// It exists because a reflected payload is not an executed one, and only a
// browser can tell the two apart. It is an interface so the proof can be tested
// against a scripted renderer and so a run without a browser simply has none,
// which is a visible state rather than a silent downgrade.
type Renderer interface {
	Render(ctx context.Context, target string) (BrowserPage, error)
}

// Browser proof defaults. Every one of them is a value the operator can change
// on the struct, and none of them is a ceiling on what a page may do: they bound
// how long a *confirmation* waits, not how long a scan looks.
const (
	// DefaultWorkerPollInterval is how often a running job is asked for its
	// state.
	DefaultWorkerPollInterval = 250 * time.Millisecond
	// DefaultWorkerJobTimeout bounds one confirmation. It exists so a browser
	// that never answers ends the wait instead of holding the run open, and it
	// is far above any navigation: the worker's own navigation timeout is what
	// ends a page that hangs.
	DefaultWorkerJobTimeout = 3 * time.Minute
	// DefaultWorkerNavigationTimeout is the deadline the worker is asked to give
	// one navigation, so the deadline belongs to this request rather than to a
	// library default.
	DefaultWorkerNavigationTimeout = 15 * time.Second
)

// WorkerRenderer drives the project's own browser worker over its `/target`
// protocol: a job is posted, then polled until it reports a terminal status.
//
// It is the same service Target's browser-driven mode uses, on purpose. A second
// browser stack for the active scanner would be a second fingerprint, a second
// set of timeouts and a second thing to keep alive, and the requests the worker
// reports are exactly what an execution proof needs.
type WorkerRenderer struct {
	// BaseURL is the worker's root, for example `http://127.0.0.1:8090`.
	BaseURL string
	// Client issues the worker's own API calls. Nil means a client with the
	// timeout below.
	Client *http.Client
	// NavigationTimeout is the deadline handed to the worker for one page.
	NavigationTimeout time.Duration
	// PollInterval is how often a running job is asked for its state.
	PollInterval time.Duration
	// JobTimeout bounds the whole confirmation, polling included.
	JobTimeout time.Duration
}

// workerJob is the worker's job snapshot, as far as this client reads it.
type workerJob struct {
	JobID string `json:"job_id"`
	// Status is "running", then "completed", "failed" or "cancelled".
	Status string `json:"status"`
	Error  string `json:"error"`
	Pages  []struct {
		URL     string `json:"url"`
		Status  int    `json:"status"`
		Error   string `json:"error"`
		Network []struct {
			URL    string `json:"url"`
			Method string `json:"method"`
		} `json:"network"`
	} `json:"pages"`
}

// requests flattens the job's per-page network lists into the page order, so a
// caller compares against every request the browser made rather than the first
// page's.
func (j workerJob) requests() []string {
	var out []string
	for _, page := range j.Pages {
		for _, request := range page.Network {
			if request.URL != "" {
				out = append(out, request.URL)
			}
		}
	}
	return out
}

func (w *WorkerRenderer) client() *http.Client {
	if w.Client != nil {
		return w.Client
	}
	// The client timeout is deliberately the job timeout and not the navigation
	// timeout: the poll loop is a sequence of short calls, and a client that
	// gave up after one navigation's worth of time would kill a confirmation
	// that was making progress.
	job := w.jobTimeout()
	return &http.Client{Timeout: job + 30*time.Second}
}

func (w *WorkerRenderer) navigationTimeout() time.Duration {
	if w.NavigationTimeout > 0 {
		return w.NavigationTimeout
	}
	return DefaultWorkerNavigationTimeout
}

func (w *WorkerRenderer) pollInterval() time.Duration {
	if w.PollInterval > 0 {
		return w.PollInterval
	}
	return DefaultWorkerPollInterval
}

func (w *WorkerRenderer) jobTimeout() time.Duration {
	if w.JobTimeout > 0 {
		return w.JobTimeout
	}
	return DefaultWorkerJobTimeout
}

// Render loads one URL in the worker's browser and returns what the page did.
func (w *WorkerRenderer) Render(ctx context.Context, target string) (BrowserPage, error) {
	base := strings.TrimRight(strings.TrimSpace(w.BaseURL), "/")
	if base == "" {
		return BrowserPage{}, fmt.Errorf("browser worker url is not configured")
	}
	if strings.TrimSpace(target) == "" {
		return BrowserPage{}, fmt.Errorf("no url to render")
	}
	job, err := w.post(ctx, base, map[string]any{
		"url":                   target,
		"capture_context":       "rrproof",
		"max_pages":             1,
		"max_depth":             0,
		"navigation_timeout_ms": int(w.navigationTimeout().Milliseconds()),
		"anti_detect":           false,
		"auto_interact":         false,
		"actions":               []any{},
	})
	if err != nil {
		return BrowserPage{}, err
	}
	deadline := time.Now().Add(w.jobTimeout())
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	for {
		if err := ctx.Err(); err != nil {
			return BrowserPage{}, err
		}
		if !time.Now().Before(deadline) {
			return BrowserPage{}, fmt.Errorf("browser worker job %s did not finish within %s",
				job.JobID, w.jobTimeout())
		}
		current, err := w.get(ctx, base, job.JobID)
		if err != nil {
			return BrowserPage{}, err
		}
		switch current.Status {
		case "":
			// A snapshot without a status is not a job this client understands,
			// and reporting it as "still running" would poll until the timeout
			// instead of naming the shape.
			return BrowserPage{}, fmt.Errorf("browser worker job %s reported no status", job.JobID)
		case "completed":
			page := BrowserPage{URL: target, Network: current.requests()}
			if len(current.Pages) > 0 {
				page.URL = current.Pages[0].URL
				page.Status = current.Pages[0].Status
				page.Error = current.Pages[0].Error
			}
			return page, nil
		case "failed":
			return BrowserPage{}, fmt.Errorf("browser worker job %s failed: %s",
				job.JobID, workerErrorText(current.Error))
		case "cancelled":
			return BrowserPage{}, fmt.Errorf("browser worker job %s was cancelled", job.JobID)
		}
		select {
		case <-ctx.Done():
			return BrowserPage{}, ctx.Err()
		case <-time.After(w.pollInterval()):
		}
	}
}

func (w *WorkerRenderer) post(ctx context.Context, base string, config map[string]any) (workerJob, error) {
	body, err := json.Marshal(config)
	if err != nil {
		return workerJob{}, err
	}
	return w.call(ctx, http.MethodPost, base+"/target", body)
}

func (w *WorkerRenderer) get(ctx context.Context, base, jobID string) (workerJob, error) {
	return w.call(ctx, http.MethodGet, base+"/target/"+jobID, nil)
}

func (w *WorkerRenderer) call(ctx context.Context, method, url string, body []byte) (workerJob, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return workerJob{}, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := w.client().Do(request)
	if err != nil {
		return workerJob{}, err
	}
	defer response.Body.Close()
	// The body is read under a cap: the worker is a local service, and a service
	// that answered a job request with a megabyte of something else must not be
	// able to grow this process without bound.
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return workerJob{}, err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return workerJob{}, fmt.Errorf("browser worker %s %s: %s",
			method, url, workerErrorText(string(raw)))
	}
	var job workerJob
	if err := json.Unmarshal(raw, &job); err != nil {
		return workerJob{}, fmt.Errorf("browser worker %s %s: unreadable answer: %w", method, url, err)
	}
	return job, nil
}

// workerErrorText keeps a service's answer to one readable line.
//
// It is deliberately not `firstLine` from this package: that one trims a version
// banner, which is short by nature and is written to sit in a table cell. This
// text goes into an error a reader sees in a log, and a service that answered a
// job request with a whole page must not put that page in the message.
func workerErrorText(s string) string {
	s = firstLine(s)
	const limit = 300
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}
