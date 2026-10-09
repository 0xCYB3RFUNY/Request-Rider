// CorpusRun executes the enumeration corpus against a target and reports what the
// server was willing to answer.
//
// # What this is for
//
// The active scanner finds what is *wrong with* a response. This finds what is
// *present that should not be*: a backup file, an admin panel, a version control
// directory, a leftover source file. Neither substitutes for the other, and a tool
// that only does the first reports a server full of published backups as clean.
//
// # Cost, and why it is visible
//
// A full run sends one request per distinct method and path — 5483 checks collapse
// to far fewer requests, but that is still thousands. Three things keep that honest
// rather than quiet:
//
//   - the request count is reported, separately from the check and finding counts,
//     because they are three different units;
//   - `Tags` narrows what a run spends requests on, and the narrowing is the
//     operator's, not a default this code chose;
//   - `Timeout` is a per-request bound with a documented default, not a ceiling on
//     how much a run may do: a run may probe every path it was given, and it takes
//     as long as the target makes it take.
//
// # Why one request answers several checks
//
// Several ids probe the same path with different match expressions — a banner, a
// CMS marker and a directory listing on `/`. Sending one request per id would
// multiply the cost of the whole class to learn the same thing more than once.

package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CorpusRunRequest is one enumeration run.
type CorpusRunRequest struct {
	// Target is the absolute http or https URL to enumerate.
	Target string
	// Tags narrows the corpus to these tuning letters. Empty means all of it.
	Tags []string
	// Concurrency is how many requests are in flight. Zero picks a small default
	// from the machine.
	Concurrency int
	// Delay is a pause between requests. It exists so a run against a fragile
	// target can be slowed by the operator; zero means no pause.
	Delay time.Duration
	// Timeout bounds one request. Zero means the default below.
	Timeout time.Duration
	// MaxChecks bounds how many checks a run evaluates, so an operator can take a
	// sample instead of the whole class. Zero means no bound: the corpus is finite
	// and the operator asked for all of it.
	MaxChecks int
	// RoundTripper is how the run's requests leave the process. It is required for
	// the same reason it is on an active scan: a silent fallback to
	// http.DefaultTransport would lose the recording transport, and the operator's
	// Traffic view would show nothing while the run reported pages fetched.
	RoundTripper http.RoundTripper
	// OnProgress receives live counters so a caller can show where a run is without
	// waiting for it to finish. It is called from the run's workers and is
	// serialised the same way OnFinding is, because the obvious caller is a
	// counter and a struct read from several goroutines is not a counter.
	//
	// Done and Total are **requests**, not checks: several checks answer from one
	// response, so a percent computed over checks would jump past 100 and back.
	// Total is the number of requests the selection will send, which is known
	// before the first one goes out.
	OnProgress func(progress CorpusProgress)
	// OnFinding receives each finding as it is raised, so a run can stream.
	//
	// It is called from the run's workers, and it is serialised before it is called:
	// a callback that appends to a slice is the obvious thing to write, and a
	// signature that made every caller find a mutex first would be a trap dressed
	// as an API. Findings therefore arrive one at a time, from no fixed goroutine.
	OnFinding func(CorpusFinding)
}

// corpusDefaults are the values a run uses when the operator expressed no intent.
//
// They are bounds on time and parallelism, not on coverage: every check the filter
// selects is evaluated, and the numbers below change how fast that happens and how
// long one slow request may hold a worker.
const (
	corpusDefaultConcurrency = 8
	corpusDefaultTimeout     = 10 * time.Second
	corpusMaxBodyBytes       = 1 << 20
)

// CorpusProgress is where a run is, measured in requests and findings.
type CorpusProgress struct {
	// Done and Total count requests. Total is zero until the selection is known.
	Done, Total int64
	// Checks and Findings count corpus rows, which is a different unit from
	// requests: one response answers every check written for its path.
	Checks, Findings int64
	// Skipped counts corpus rows that got no verdict because their request never
	// came back. It is a separate number on purpose: without it a run over a target
	// that drops connections reports fewer checks than the corpus holds, and the
	// shortfall is indistinguishable from a corpus that was quietly narrowed.
	Skipped int64
	// Percent is -1 while Total is unknown, so a caller shows an indeterminate bar
	// rather than inventing a number.
	Percent int
	// Truncated says a bound cut the selection short.
	Truncated bool
}

// CorpusFinding is one raised finding.
type CorpusFinding struct {
	// CheckID is the corpus row that matched.
	CheckID string
	// Method and Path are the request that answered.
	Method string
	Path   string
	// StatusCode is the response status.
	StatusCode int
	// Description is the corpus row's explanation of what the path is.
	Description string
	// Evidence is the part of the response that matched, trimmed to a size a report
	// can carry.
	Evidence string
}

// CorpusRunResult is what a finished run did.
type CorpusRunResult struct {
	// Requests is how many requests the run actually sent.
	Requests int
	// Checks is how many corpus rows it evaluated.
	Checks int
	// Skipped is how many rows got no verdict because the request for their path
	// never came back — a refused connection, a timeout, a reset.
	Skipped int
	// Findings is how many rows matched.
	Findings int
	// Stats describes the selection that was run.
	Stats CorpusStats `json:"stats"`
	// Duration is the wall time of the run.
	Duration time.Duration
	// Truncated says the run stopped early because a bound was reached, so a report
	// that shows a clean target can say whether it looked at everything.
	Truncated bool
}

// RunCorpus enumerates a target.
//
// The returned error is reserved for the run not having happened at all: an
// unreadable corpus, an unparsable target, a transport that is required and
// missing. A target that answers nothing is a finished run with zero findings, not
// an error, because those are different facts and an operator reads them
// differently.
func RunCorpus(ctx context.Context, request CorpusRunRequest) (CorpusRunResult, error) {
	started := time.Now()

	if request.RoundTripper == nil {
		return CorpusRunResult{}, fmt.Errorf("scanner: a corpus run needs a RoundTripper; " +
			"the default transport would bypass the recording path the operator's Traffic view reads")
	}
	base, err := url.Parse(request.Target)
	if err != nil || base.Host == "" {
		return CorpusRunResult{}, fmt.Errorf("scanner: %q is not an absolute URL", request.Target)
	}

	all, err := LoadDefaultCorpus()
	if err != nil {
		return CorpusRunResult{}, err
	}
	selected := FilterCorpus(all, request.Tags)
	if request.MaxChecks > 0 && len(selected) > request.MaxChecks {
		selected = selected[:request.MaxChecks]
	}
	requests := GroupCorpus(selected)

	timeout := request.Timeout
	if timeout <= 0 {
		timeout = corpusDefaultTimeout
	}
	concurrency := request.Concurrency
	if concurrency <= 0 {
		concurrency = corpusDefaultConcurrency
	}

	client := &http.Client{
		Transport: request.RoundTripper,
		Timeout:   timeout,
		// Redirects are not followed: a check asks whether a path answers, and
		// following a redirect turns "this path exists" into "some other path
		// exists", which is a claim about a different URL.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	var (
		requestsSent  atomic.Int64
		checksRun     atomic.Int64
		raised        atomic.Int64
		checksSkipped atomic.Int64
		queue         = make(chan CorpusRequest)
		wait          sync.WaitGroup
		emit          sync.Mutex
		runCtx        = ctx
	)
	if request.Delay > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithCancel(ctx)
		defer cancel()
	}

	worker := func() {
		defer wait.Done()
		for item := range queue {
			if runCtx.Err() != nil {
				return
			}
			if request.Delay > 0 {
				select {
				case <-time.After(request.Delay):
				case <-runCtx.Done():
					return
				}
			}
			status, body, header := corpusFetch(runCtx, client, base, item)
			requestsSent.Add(1)
			if status == 0 && body == "" && header == nil {
				// No answer at all: a refused connection, a timeout, a reset. The
				// checks written for this path get no verdict, and that is a different
				// statement from "the path does not exist" — so they are counted
				// apart rather than left to show up as a gap between the corpus size
				// and the number of checks the report claims to have read.
				checksSkipped.Add(int64(len(item.Checks)))
				// Reported here and at the end of the loop body, never before the
				// counters move: reporting first made every counter lag by exactly one
				// request, and a run in which nothing answered ended by reporting 6479
				// skipped of 6480 rows — one row that no counter had heard of yet,
				// which is precisely the kind of gap the counter exists to close.
				reportProgress(request.OnProgress, requestsSent.Load(), int64(len(requests)),
					checksRun.Load(), raised.Load(), checksSkipped.Load())
				continue
			}
			for _, check := range item.Checks {
				// Counted before the verdict, not after it. The counter stood next to
				// `raised.Add(1)` and therefore only ever counted matches, so `Checks`
				// and `Findings` were the same number on every run and the report read
				// "5906 findings from 5906 checks" for a corpus of 6480 rows: the
				// number of checks the run actually looked at was never reported at all,
				// and a corpus row that did not match was indistinguishable from a
				// corpus row that was never run.
				checksRun.Add(1)
				if !check.Match(status, body, header) {
					continue
				}
				raised.Add(1)
				if request.OnFinding == nil {
					continue
				}
				finding := CorpusFinding{
					CheckID:     check.ID,
					Method:      item.Method,
					Path:        item.Path,
					StatusCode:  status,
					Description: check.Description,
					Evidence:    corpusEvidence(check, status, body, header),
				}
				emit.Lock()
				request.OnFinding(finding)
				emit.Unlock()
			}
			// Same reason as the other report: after this request's checks have been
			// judged, so the panel never shows a total that the next request has
			// already overtaken.
			reportProgress(request.OnProgress, requestsSent.Load(), int64(len(requests)),
				checksRun.Load(), raised.Load(), checksSkipped.Load())
		}
	}

	for i := 0; i < concurrency; i++ {
		wait.Add(1)
		go worker()
	}
feed:
	for _, item := range requests {
		select {
		case queue <- item:
		case <-runCtx.Done():
			break feed
		}
	}
	close(queue)
	wait.Wait()

	result := CorpusRunResult{
		Requests:  int(requestsSent.Load()),
		Checks:    int(checksRun.Load()),
		Findings:  int(raised.Load()),
		Skipped:   int(checksSkipped.Load()),
		Stats:     DescribeCorpus(selected),
		Duration:  time.Since(started),
		Truncated: request.MaxChecks > 0 && len(selected) < len(FilterCorpus(all, request.Tags)),
	}
	// A cancelled run reports what it managed and says so, rather than reporting a
	// clean target because it stopped early.
	if err := ctx.Err(); err != nil {
		result.Truncated = true
	}
	return result, nil
}

// reportProgress hands the live counters to the caller's callback, or drops them when
// there is no callback.
func reportProgress(callback func(CorpusProgress), done, total, checks, findings, skipped int64) {
	if callback == nil {
		return
	}
	percent := -1
	if total > 0 {
		percent = int(float64(done) * 100 / float64(total))
		if percent > 100 {
			percent = 100
		}
	}
	callback(CorpusProgress{
		Done: done, Total: total, Checks: checks, Findings: findings, Percent: percent,
		Skipped: skipped,
	})
}

// corpusFetch sends one grouped request. A zero status means the exchange did not
// produce a response, which is not the same as a response with status 0.
func corpusFetch(ctx context.Context, client *http.Client, base *url.URL, item CorpusRequest) (int, string, http.Header) {
	target := *base
	target.RawQuery = ""

	// `URL.Path` holds the **decoded** path; `RawPath` holds the original when it
	// differs. Writing the corpus path straight into `Path` therefore makes
	// `String()` escape the percent signs a second time: a check written for `/%00`
	// went out as `/%2500`, and one for `/%2e/` as `/%252e/`. Measured on the
	// parity stand, 110 checks on percent-encoded paths asked a question about a
	// path the target was never asked for, so a body the server did return went
	// unread.
	//
	// An escape the path cannot be decoded from is a data problem, not something to
	// paper over: it is sent as written rather than silently rewritten.
	if decoded, err := url.PathUnescape(item.Path); err == nil {
		target.Path = decoded
		target.RawPath = item.Path
	} else {
		// A path with a broken escape has no decoded form. Go has no way to send one
		// unescaped, so `Path` would re-escape it and the server would be asked
		// about a different path. The converter removes such rows — two of them,
		// `/%NETHOOD%/` and `/%a%s%p%d` — with a count, rather than shipping a
		// request that silently asks about something else.
		target.Path = item.Path
		target.RawPath = ""
	}

	method := item.Method
	if method == "" {
		method = http.MethodGet
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), nil)
	if err != nil {
		return 0, "", nil
	}
	// `url.Parse` inside NewRequest re-derives the escaped path, and a corpus path
	// holding characters Go escapes — `<`, `'`, parentheses — comes back changed:
	// `/<script>alert('Vulnerable')</script>` left as `%3Cscript%3E…`, which asks the
	// server about a path the check was never written for. Measured on the parity
	// stand, 26 of the 29 paths only Nikto reported failed for exactly this reason.
	//
	// The comparison is on the parsed request rather than on the template URL,
	// because the template still carries the original bytes and would report "no
	// difference" for every one of them.
	if request.URL.EscapedPath() != item.Path {
		request.URL.Opaque = item.Path
		request.Host = target.Host
	}
	request.Header.Set("User-Agent", corpusUserAgent)
	request.Header.Set("Accept", "*/*")

	response, err := client.Do(request)
	if err != nil {
		return 0, "", nil
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, corpusMaxBodyBytes))
	if err != nil {
		// The server did not finish sending the body, so what arrived is a prefix
		// of an answer and not the answer. Measured: a truncated response still
		// matched a body check, because net/http hands back the bytes it did get
		// together with the error. Keeping the prefix would let any content check
		// fire on a response nobody finished reading.
		//
		// The status is kept: it was sent whole, and "this path answers 200" does
		// not depend on the body having arrived.
		return response.StatusCode, "", response.Header
	}
	return response.StatusCode, string(raw), response.Header
}

// corpusUserAgent identifies the scanner instead of impersonating a browser.
//
// The project already has a browser-impersonating agent for browser-driven work;
// reusing it here would make an enumeration run indistinguishable from a visitor
// in the target's logs, which is the opposite of what an operator wants from a
// report they may have to show someone.
const corpusUserAgent = "RequestRider enumeration/1.0"

// corpusEvidence is the part of the response a check matched.
//
// For a body check that is the line carrying the pattern; for a header check, the
// header. Reporting the whole response would make a report unreadable, and
// reporting nothing but a status would leave a triager with nothing to check
// against.
func corpusEvidence(check CorpusCheck, status int, body string, header http.Header) string {
	// Evidence is bytes a remote server chose, so it carries whatever control
	// characters that server felt like sending. Two of them are fatal downstream:
	// a raw control character inside a JSON string makes the whole response
	// unparsable, and the browser's `response.json()` then rejects it — so one
	// server's form-feed turned a finished 96%-complete run into an empty panel.
	// Measured on https://yandex.ru/: `json: invalid control character at line 1`.
	//
	// Tab and newline are kept: they are how a body is laid out, and they are legal
	// inside a JSON string. Everything else below 0x20, plus DEL, is dropped.
	return stripControlCharacters(evidenceText(check, status, body, header))
}

// stripControlCharacters removes the control characters that cannot travel inside a
// JSON string. It replaces nothing with a placeholder: the text is evidence, and a
// space where a byte was would read as a real character of the server's answer.
func stripControlCharacters(text string) string {
	var out strings.Builder
	out.Grow(len(text))
	for _, symbol := range text {
		if symbol == '\t' || symbol == '\n' || symbol == '\r' {
			out.WriteRune(symbol)
			continue
		}
		if symbol < 0x20 || symbol == 0x7f {
			continue
		}
		out.WriteRune(symbol)
	}
	return out.String()
}

func evidenceText(check CorpusCheck, status int, body string, header http.Header) string {
	const limit = 300
	switch check.Kind {
	case MatchCode:
		return fmt.Sprintf("status %d on %s %s", status, check.Method, check.Path)
	case MatchHeader:
		for name, values := range header {
			for _, value := range values {
				if check.pattern != nil && check.pattern.MatchString(value) {
					return trimEvidence(name+": "+value, limit)
				}
			}
		}
		return fmt.Sprintf("status %d on %s %s", status, check.Method, check.Path)
	default:
		for _, line := range strings.Split(body, "\n") {
			if check.pattern != nil && check.pattern.MatchString(line) {
				return trimEvidence(strings.TrimSpace(line), limit)
			}
		}
		return trimEvidence(body, limit)
	}
}

func trimEvidence(text string, limit int) string {
	text = strings.TrimSpace(text)
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "…"
}
