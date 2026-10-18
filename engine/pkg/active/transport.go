// The one way a probe reaches the target.
//
// # Why the transport is injected and never constructed here
//
// An autonomous scanner is the tool most likely to be noticed by a target and
// the tool whose traffic most needs to be attributable. Both properties come
// from the same decision: this file does not build an HTTP client, it is handed
// one. The engine supplies the recording transport, which routes every exchange
// through the local MITM proxy, so a probe's request is stored in History with
// its complete raw request and response, linked to the capture context of the
// Project the run belongs to. That is the same accounting every other tool in
// the project gets, and it is why this file cannot fall back to
// `http.DefaultTransport` when the injected value is nil: a silent fallback
// would produce a working scanner whose evidence vanished, and the operator
// would learn that from an empty History long after the run.
//
// # What is deliberately not here
//
// There is no `InsecureSkipVerify` and no TLS configuration of any kind. The
// upstream leg is verified by the proxy against the system roots, and this
// client trusts the engine's own CA because the proxy is the one terminating
// TLS. A target with a broken certificate fails at the proxy, where it belongs.
// Disabling verification would make every scan silently accept a machine-in-the-
// middle, which is the one outcome an evidence-first scanner cannot afford.
//
// There is also no response-size cap. The engine reads analysis bodies in full
// (`readAnalysisBody`), and a probe that read only the first megabyte would
// truncate exactly the evidence a boolean-differential comparison needs, then
// report the difference as a finding. An unreadable body is a read error that
// this package returns, not a silently shortened string.
package active

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"intruder/engine/pkg/bypass"
	"intruder/engine/pkg/runstate"
)

// DefaultTimeout bounds one probe request when the caller supplies no deadline
// of its own. It is a transport deadline for a single request, not a limit on
// what an operator can scan: the scan's own timeout is a visible field, and a
// caller that wants a different bound sets one and this value is not consulted.
const DefaultTimeout = 15 * time.Second

// Options configures a Transport.
type Options struct {
	// Timeout bounds one request. Zero means DefaultTimeout.
	Timeout time.Duration
	// UserAgent identifies the scanner in the target's access log. An
	// operator reading their own log has to be able to tell a probe from a page
	// load, so this is never disguised as a browser.
	UserAgent string
	// AcceptLanguage is the analyst's language preference, sent as
	// Accept-Language. Empty omits the header rather than inventing one.
	AcceptLanguage string
	// Bypass turns the 403 ladder on for this transport.
	//
	// It is a field rather than always-on for the reason the rest of this project
	// is built the way it is: a bypass form is a real request against a real
	// target, and a scan that sent extra requests per refused endpoint without
	// saying so would be a scan whose footprint its operator cannot see. Off by
	// default, visible when on, and what it spent is in `BypassStats`.
	Bypass bool
	// BypassForms narrows the ladder. Nil means every form, and it is read only
	// when `Bypass` is set — a selection with the ladder off is a contradiction,
	// not a narrower run.
	BypassForms []string
	// Gate pauses the run and releases in-flight probes. Nil means no pause.
	Gate *runstate.Gate
	// Ledger records transport failures. Nil means none is recorded.
	Ledger *runstate.Ledger
}

// Response is one completed exchange, with the timing a differential detector
// needs.
type Response struct {
	// StatusCode is the HTTP status of the final response.
	StatusCode int
	// Status is the full status line, e.g. "404 Not Found".
	Status string
	// Header is the final response's header set.
	Header http.Header
	// Body is the response body read in full.
	Body string
	// FinalURL is where the exchange ended after redirects. A redirect probe
	// compares this against the request URL, and a body-diff detector needs to
	// know it is comparing two different resources.
	FinalURL string
	// Duration is the wall time of the exchange, which is what a time-based
	// detector reads as signal.
	Duration time.Duration
	// HTTPVersion is the protocol the final response was written in, e.g.
	// "HTTP/1.1" or "HTTP/2.0".
	//
	// It is the second half of the hidden-HTTP-2 evidence: the TLS state says
	// what the connection negotiated, this says what the message claimed, and
	// the row is about the two disagreeing.
	HTTPVersion string
	// TLS is the connection state the exchange was made over, nil for a
	// cleartext one.
	//
	// It is here because three of the checks are about the connection rather
	// than the message: the certificate the client was shown, the protocol that
	// was negotiated, and whether the two agree. Without it those three have no
	// input at all, and the register recorded them as "the transport does not
	// hand the detector the negotiated protocol" — a statement about `Response`
	// rather than about the target.
	//
	// The limitation is real and is reported rather than hidden: a run whose
	// RoundTripper is the recording proxy is looking at **the proxy's**
	// connection, not the target's. `tlsCertificate` reads the issuer for that
	// reason and names the observation instead of claiming a chain it did not
	// see.
	TLS *tls.ConnectionState
}

// HeaderValue returns one header's values joined, or "" when the header is
// absent. The two existence checks a chain rule makes — "is this cookie issued
// at all" and "does it carry HttpOnly" — are one call each through this.
func (r *Response) HeaderValue(name string) string {
	if r == nil || r.Header == nil {
		return ""
	}
	return strings.Join(r.Header.Values(name), "; ")
}

// SetCookies returns every Set-Cookie value of the response. A chain rule that
// reasons about session hardening needs the raw values, not the parsed jar,
// because the jar has already discarded the attributes the rule is about.
func (r *Response) SetCookies() []string {
	if r == nil {
		return nil
	}
	return r.Header.Values("Set-Cookie")
}

// Transport issues probe requests through an injected RoundTripper.
type Transport struct {
	next     http.RoundTripper
	follow   *http.Client
	nofollow *http.Client
	timeout  time.Duration
	accept   string
	agent    string
	// requests counts every request this transport issues, and it is counted here
	// rather than by the callers because `Do` is the single point every request
	// passes through: the crawl fetches with it, `Baseline` delegates to it, and
	// `Fire` delegates to it. Counting at the call sites instead missed every probe
	// a detector made — a live run against a real target reported "requests: 2"
	// after nine modules had spent a minute and a half hitting it, which is the one
	// number an operator uses to judge how hard a scan pressed the target.
	requests atomic.Int64
	// ladder is nil unless the operator turned the bypass on. A nil ladder is not
	// an empty one: it means `Do` sends exactly what it was given, which is what
	// a run that never opted in must do.
	ladder *bypass.Driver
	gate   *runstate.Gate
	ledger *runstate.Ledger
	// bypassWalks and bypassHits count what the ladder spent and what it reached.
	// They sit next to `requests` because they are the same number from the
	// operator's side: what a scan pressed a target with, and how much of that was
	// spent getting past a refusal rather than doing the work.
	bypassWalks atomic.Int64
	bypassHits  atomic.Int64
}

// Requests is how many requests this transport has issued.
func (t *Transport) Requests() int { return int(t.requests.Load()) }

// CountExternalRequests adds requests a run made **outside** this transport to the
// same counter.
//
// Three detectors write onto a socket they opened themselves — the certificate
// read, the desynchronisation probe, and anything else that needs framing the
// `http.Client` cannot produce — and a request the target received but the report
// does not count is exactly the number an operator uses to judge how hard a scan
// pressed them. The counter is therefore the run's count, not this type's, and
// those probes have to add themselves to it.
//
// It takes a count rather than being a bare increment because one probe may make
// several exchanges on one connection, and the caller is the only one that knows
// how many.
func (t *Transport) CountExternalRequests(n int) {
	if t == nil || n <= 0 {
		return
	}
	t.requests.Add(int64(n))
}

// BypassStats is what the bypass ladder spent and what it reached.
//
// It is reported rather than inferred because every form is a real request, and
// a run that quietly multiplied its own footprint would be a run whose cost the
// operator could only discover afterwards. Zero with the ladder off is the honest
// answer, not a missing one.
func (t *Transport) BypassStats() (walks, hits, requests int) {
	if t.ladder == nil {
		return 0, 0, 0
	}
	return int(t.bypassWalks.Load()), int(t.bypassHits.Load()), t.ladder.Requests()
}

// NewTransport binds a probe client to an injected RoundTripper.
//
// A nil RoundTripper is an error rather than a default. The engine always has
// one to give, and the only way to reach this function without one is a caller
// that has lost the recording transport — a run that would then report
// vulnerabilities with no stored evidence behind any of them.
func NewTransport(next http.RoundTripper, opts Options) (*Transport, error) {
	if next == nil {
		return nil, fmt.Errorf("active: transport requires an injected RoundTripper, got nil")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	// A jar is shared by every probe of a run so a session cookie obtained by
	// one request is presented to the next, the way a browser behaves. A scan
	// that dropped it would fail to reach anything behind a login even when the
	// operator supplied valid credentials, and would report the page as clean.
	jar, err := cookiejar.New(nil)
	if err != nil {
		// The stdlib jar has no failure mode today, but a probe client that
		// cannot hold cookies is a different client than the one intended, and
		// a silent one would reach the same conclusion about the same target.
		return nil, fmt.Errorf("active: cookie jar: %w", err)
	}
	accept := strings.TrimSpace(opts.AcceptLanguage)
	agent := strings.TrimSpace(opts.UserAgent)
	if agent == "" {
		agent = DefaultUserAgent
	}
	newClient := func(followRedirects bool) *http.Client {
		client := &http.Client{Transport: next, Jar: jar, Timeout: timeout}
		client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
			// A detector that asked not to follow must see the 3xx itself: an
			// open-redirect probe reads the Location header, and following it
			// would hide the very answer it went for.
			if !followRedirects || len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		}
		return client
	}
	transport := &Transport{
		next:     next,
		follow:   newClient(true),
		nofollow: newClient(false),
		timeout:  timeout,
		accept:   accept,
		agent:    agent,
	}
	if opts.Bypass {
		transport.ladder = bypass.New(opts.BypassForms)
	}
	transport.gate = opts.Gate
	transport.ledger = opts.Ledger
	return transport, nil
}

// send issues one request and, when the ladder is on, walks it when the target
// refuses the shape the request arrived in.
//
// It returns the attempt alongside the response for two reasons: the counters
// below need to know whether a walk ended in a hit, and a caller that wants to
// report *which* form reached a resource needs the record rather than the
// absence of a 403. The attempt is nil when the ladder is off, which is how a
// caller tells "no walk happened" from "a walk happened and reached nothing".
func (t *Transport) send(
	ctx context.Context, client *http.Client, req *http.Request,
) (*http.Response, *bypass.Attempt, error) {
	if t.ladder == nil {
		resp, err := client.Do(req)
		return resp, nil, err
	}
	t.bypassWalks.Add(1)
	resp, attempt, err := t.ladder.Attempt(ctx, client, req)
	if attempt != nil && attempt.Bypassed() {
		t.bypassHits.Add(1)
	}
	return resp, attempt, err
}

// Do issues one request.
//
// values is the form body for every method except GET, and the query string for
// GET. A nil or empty values sends no body and no query, rather than a bare
// trailing "?" that some servers treat as a different resource.
func (t *Transport) Do(ctx context.Context, method, rawURL string, values url.Values, followRedirects bool, extra http.Header) (*Response, error) {
	// Counted before the request is built, so a request that fails still counts:
	// it still reached for the target, and a counter that hides the failures would
	// under-report the run's footprint rather than describe it.
	t.requests.Add(1)
	if ctx == nil {
		return nil, fmt.Errorf("active: Do requires a context")
	}
	// The deadline is the caller's when it set one. A scan that must be slow
	// because the target is slow says so in a visible field; this only supplies
	// a bound for a caller that expressed no intent.
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.timeout)
		defer cancel()
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	target := rawURL
	hasBody := len(values) > 0 && method != http.MethodGet
	if method == http.MethodGet && len(values) > 0 {
		trimmed := rawURL
		if index := strings.IndexByte(trimmed, '?'); index >= 0 {
			trimmed = trimmed[:index]
		}
		target = trimmed + "?" + values.Encode()
	}

	var body io.Reader
	if hasBody {
		body = strings.NewReader(values.Encode())
	}
	return t.issue(ctx, method, target, rawURL, body,
		formContentType, followRedirects, extra)
}

// DoBody issues one request with a body the caller wrote itself.
//
// It exists for the probes that cannot express their input as a form: a JSON
// merge is the upstream prototype-pollution family's whole point, and a scanner
// that can only send `a=1&b=2` cannot send `{"__proto__":{"polluted":"…"}}` at
// all. It is additive — every other detector still goes through `Do`, unchanged —
// and it records itself in the same request counter, because a probe that hid its
// requests from the count would under-report the run's footprint.
func (t *Transport) DoBody(ctx context.Context, method, rawURL string, body []byte,
	contentType string, followRedirects bool, extra http.Header) (*Response, error) {
	t.requests.Add(1)
	if ctx == nil {
		return nil, fmt.Errorf("active: DoBody requires a context")
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.timeout)
		defer cancel()
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodPost
	}
	if strings.TrimSpace(contentType) == "" {
		contentType = "application/octet-stream"
	}
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	return t.issue(ctx, method, rawURL, rawURL, reader, contentType, followRedirects, extra)
}

// formContentType is what every request built from a `url.Values` carries.
const formContentType = "application/x-www-form-urlencoded"

// issue is the one place a probe's request is built and answered.
//
// `url` is where the request goes and `label` is what an error names: they differ
// for `Do`, whose target carries a query string it assembled, and are the same for
// `DoBody`, whose caller wrote the whole address. Keeping them apart is what stops
// an error message from printing an address the target never saw.
func (t *Transport) issue(ctx context.Context, method, target, label string, body io.Reader,
	contentType string, followRedirects bool, extra http.Header) (*Response, error) {
	if t.gate != nil {
		if err := t.gate.Wait(ctx); err != nil {
			return nil, err
		}
		var release func()
		ctx, release = t.gate.Child(ctx)
		defer release()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, fmt.Errorf("active: build %s %s: %w", method, label, err)
	}
	req.Header.Set("User-Agent", t.userAgent())
	req.Header.Set("Accept", "*/*")
	if t.accept != "" {
		req.Header.Set("Accept-Language", t.accept)
	}
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	// extra is applied last so a probe can set Origin, Referer or a cookie
	// header that the defaults would otherwise own.
	for name, values := range extra {
		req.Header[name] = append([]string(nil), values...)
	}

	client := t.follow
	if !followRedirects {
		client = t.nofollow
	}
	started := time.Now()
	resp, _, err := t.send(ctx, client, req)
	if err != nil {
		// A cancelled run is not a probe failure and must not be reported as
		// one, or an operator who pressed Cancel would read the resulting
		// silence as a clean target.
		//
		// The distinction that matters here is *whose* cancellation it is, and it
		// is not the same question as "is the context done". A client timeout
		// cancels the request's own context as a side effect, so a request that
		// timed out arrives with `ctx.Err()` already set — and treating that as a
		// cancellation is what would swallow every timeout a run ever hits, which
		// is precisely the evidence the failure ledger exists to keep. So the test
		// is on the error itself: `context.Canceled` means somebody stopped this
		// probe, and a deadline means the target did not answer in time.
		if errors.Is(err, context.Canceled) {
			if t.gate != nil {
				if paused, _ := t.gate.Paused(); paused {
					return nil, runstate.ErrPaused
				}
			}
			return nil, context.Canceled
		}
		if t.ledger != nil {
			// The address as sent and the caller's name for the probe are kept
			// apart here for the same reason they are kept apart in the error
			// message: a detector labels its probes ("sqli on /search"), and
			// writing that into the resend queue would produce a queue entry that
			// cannot be sent. The queue entry has to name the URL, and the label is
			// what says which probe went unanswered.
			t.ledger.Record(runstate.Failure{
				Method:     method,
				URL:        target,
				Label:      label,
				Class:      runstate.ClassifyTransportError(err),
				Error:      err.Error(),
				DurationMS: time.Since(started).Milliseconds(),
			})
		}
		return nil, fmt.Errorf("active: %s %s: %w", method, label, err)
	}
	defer resp.Body.Close()
	// Read in full. A probe that read a prefix would compare two halves of two
	// documents and call the difference a finding; an unreadable body is an
	// error this package reports instead of shortening the string silently.
	data, err := io.ReadAll(resp.Body)
	final := label
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	if err != nil {
		if t.ledger != nil {
			t.ledger.Record(runstate.Failure{
				Method:     method,
				URL:        final,
				Label:      label,
				Class:      runstate.ClassifyTransportError(err),
				Error:      err.Error(),
				DurationMS: time.Since(started).Milliseconds(),
			})
		}
		return nil, fmt.Errorf("active: read %s %s: %w", method, label, err)
	}
	if t.ledger != nil {
		t.ledger.Success(final)
	}
	return &Response{
		StatusCode:  resp.StatusCode,
		Status:      resp.Status,
		Header:      resp.Header,
		Body:        string(data),
		FinalURL:    final,
		Duration:    time.Since(started),
		HTTPVersion: resp.Proto,
		TLS:         resp.TLS,
	}, nil
}

// DefaultUserAgent identifies a probe in the target's access log.
//
// It names itself. An operator reading their own log has to be able to tell a
// scan from a page load, and a User-Agent that impersonates Chrome would make
// that impossible — the same reason the value carries the tool's name rather
// than a browser's.
const DefaultUserAgent = "RequestRider-ActiveScanner"

func (t *Transport) userAgent() string {
	return t.agent
}

// Baseline issues the point's original request, untouched. A differential
// detector compares a payload response against this, so it has to be the
// request the application would have received without the scanner.
func (t *Transport) Baseline(ctx context.Context, p Point, followRedirects bool) (*Response, error) {
	return t.Do(ctx, p.Method, p.URL, p.Values, followRedirects, nil)
}

// Fire issues the point's request with one parameter replaced by payload and
// every sibling parameter left as the page supplied it.
//
// An empty param sends the baseline request. That is what makes one function
// serve both roles without a second code path that could drift.
func (t *Transport) Fire(ctx context.Context, p Point, param, payload string, followRedirects bool, extra http.Header) (*Response, error) {
	values := url.Values{}
	for key, list := range p.Values {
		for _, value := range list {
			values.Add(key, value)
		}
	}
	if param != "" {
		values.Set(param, payload)
	}
	return t.Do(ctx, p.Method, p.URL, values, followRedirects, extra)
}

// Curl renders a copy-pasteable reproduction of a request.
//
// It exists because a finding a triager cannot reproduce is a finding they will
// close. The command is the same request the probe sent, so running it by hand
// either reproduces the finding or shows that it was not one.
func Curl(method, rawURL string, values url.Values) string {
	command := "curl -sS -i"
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, "":
	default:
		command += " -X " + strings.ToUpper(strings.TrimSpace(method))
	}
	command += " '" + rawURL + "'"
	if len(values) > 0 && !strings.EqualFold(method, http.MethodGet) {
		command += " --data '" + values.Encode() + "'"
	}
	return command
}

// CurlPoint renders the reproduction of a single point with one parameter
// replaced.
//
// The values are handed to Curl rather than dropped, because a POST surface
// carries its parameters in the body: a command without them would send an
// empty request, succeed, and reproduce nothing. The parameter list is encoded
// in a fixed order so two runs over the same page produce byte-identical
// commands, and a diff between two reports shows only what changed on the
// target.
func CurlPoint(p Point, param, payload string) string {
	values := url.Values{}
	for key, list := range p.Values {
		for _, value := range list {
			values.Add(key, value)
		}
	}
	if param != "" {
		values.Set(param, payload)
	}
	target := p.URL
	if p.Method == http.MethodGet && len(values) > 0 {
		target = p.URL + "?" + encodeStable(values)
	}
	return Curl(p.Method, target, values)
}

// encodeStable encodes a parameter set with its keys in a fixed order, so the
// same values always produce the same string.
func encodeStable(values url.Values) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	encoded := url.Values{}
	for _, key := range keys {
		encoded[key] = values[key]
	}
	return encoded.Encode()
}
