package scanner

// Tests for the corpus runner.
//
// The fixture is a live server with switchable answers, because the property under
// test is which responses raise rows and which do not. A mocked transport would
// agree with a runner that matched everything, and the one thing this runner must
// never do is report a clean target as covered.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestARunNeedsATransportAndAnAbsoluteTarget(t *testing.T) {
	if _, err := RunCorpus(context.Background(), CorpusRunRequest{
		Target: "https://example.invalid/",
	}); err == nil {
		t.Error("a run with no RoundTripper was allowed; it would bypass the recording path silently")
	}
	if _, err := RunCorpus(context.Background(), CorpusRunRequest{
		Target:       "not a url",
		RoundTripper: http.DefaultTransport,
	}); err == nil {
		t.Error("a relative target was accepted")
	}
}

func TestTheRunnerFindsWhatTheTargetPublishesAndIgnoresTheRest(t *testing.T) {
	// `/admin` answers 200, which the corpus has a code check for; `/secret.txt`
	// carries a marker a body check looks for; everything else 404s.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("admin console"))
		case "/secret.txt":
			_, _ = w.Write([]byte("internal notes: vhod takoy-toy frazy"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	findings := runSample(t, server.URL, []CorpusCheck{
		{ID: "code-admin", Method: "GET", Path: "/admin", Kind: MatchCode, Value: "200"},
		{ID: "body-secret", Method: "GET", Path: "/secret.txt", Kind: MatchBody,
			Value: "vhod takoy-toy frazy", pattern: mustCompile(t, "vhod takoy-toy frazy")},
		{ID: "code-missing", Method: "GET", Path: "/nothing-here", Kind: MatchCode, Value: "200"},
	})

	byID := map[string]CorpusFinding{}
	for _, f := range findings {
		byID[f.CheckID] = f
	}
	if _, raised := byID["code-admin"]; !raised {
		t.Error("a 200 on a published path raised nothing")
	}
	secret, raised := byID["body-secret"]
	if !raised {
		t.Error("a marker in a published body raised nothing")
	} else if secret.Evidence == "" {
		t.Error("the finding carries no evidence a triager could check against")
	}
	if _, raised := byID["code-missing"]; raised {
		t.Error("a 404 raised a row; a path that does not exist is not a finding")
	}
}

func TestOneRequestAnswersEveryCheckOnItsPath(t *testing.T) {
	// The whole cost argument rests on this: three checks on one path must be one
	// request, and all three must still be evaluated against the single answer.
	var mu sync.Mutex
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("engine banner"))
	}))
	defer server.Close()

	findings := runSample(t, server.URL, []CorpusCheck{
		{ID: "a", Method: "GET", Path: "/", Kind: MatchCode, Value: "200"},
		{ID: "b", Method: "GET", Path: "/", Kind: MatchBody, Value: "banner",
			pattern: mustCompile(t, "banner")},
		{ID: "c", Method: "GET", Path: "/", Kind: MatchBody, Value: "engine",
			pattern: mustCompile(t, "engine")},
	})

	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Errorf("three checks on one path cost %d requests, want 1", hits)
	}
	if len(findings) != 3 {
		t.Errorf("%d of 3 checks matched the single answer", len(findings))
	}
}

func TestABoundIsVisibleRatherThanSilent(t *testing.T) {
	// A run that sampled part of the corpus and reported a clean target would be
	// the most expensive lie this runner could tell.
	checks := make([]CorpusCheck, 0, 40)
	for i := 0; i < 40; i++ {
		checks = append(checks, CorpusCheck{
			ID: "c", Method: "GET", Path: "/x", Kind: MatchCode, Value: "404",
		})
	}
	checks = append(checks, CorpusCheck{ID: "expensive", Method: "GET", Path: "/found",
		Kind: MatchCode, Value: "200"})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/found" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	result := runBounded(t, server.URL, checks, 5)
	if !result.Truncated {
		t.Error("a bounded run did not report itself as truncated")
	}
	if result.Stats.Selected != 5 {
		t.Errorf("Selected = %d, want 5", result.Stats.Selected)
	}
}

func TestAnUnreachableTargetIsNotAnErrorButNotACleanBillEither(t *testing.T) {
	// Nothing answered, so nothing was found. That is a finished run with no
	// findings — not a failure, and emphatically not a statement about the target.
	transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})
	result, err := RunCorpus(context.Background(), CorpusRunRequest{
		Target:       "https://127.0.0.1:1/",
		RoundTripper: transport,
		MaxChecks:    3,
	})
	if err != nil {
		t.Fatalf("an unreachable target was reported as an error: %v", err)
	}
	if result.Findings != 0 {
		t.Errorf("an unreachable target raised %d findings", result.Findings)
	}
}

func TestCancellingStopsTheRunAndSaysSo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(120 * time.Millisecond)
		cancel()
	}()

	checks := make([]CorpusCheck, 0, 60)
	for i := 0; i < 60; i++ {
		checks = append(checks, CorpusCheck{ID: "c", Method: "GET", Path: "/",
			Kind: MatchCode, Value: "200"})
	}
	// The runner evaluates the embedded corpus, so a bounded run with the default
	// corpus is what this measures: it must stop and must not claim completeness.
	result, err := RunCorpus(ctx, CorpusRunRequest{
		Target:       server.URL,
		RoundTripper: http.DefaultTransport,
		MaxChecks:    40,
		Concurrency:  2,
	})
	if err != nil {
		t.Fatalf("RunCorpus: %v", err)
	}
	if !result.Truncated {
		t.Error("a cancelled run reported itself as complete")
	}
}

func TestTheEvidenceIsThePartThatMatched(t *testing.T) {
	// A report that shows a status code and nothing else leaves a triager with
	// nothing to check the finding against, and one that shows the whole body makes
	// a report unreadable. Each kind of check therefore has to name the text it
	// matched, and each has a defined answer when there is no such text.
	header := http.Header{}
	header.Set("Server", "nginx/1.18.0")

	code := corpusEvidence(CorpusCheck{Kind: MatchCode, Value: "200"}, 200, "body", header)
	if !strings.Contains(code, "200") {
		t.Errorf("a code check's evidence does not name the status: %q", code)
	}

	headerCheck := CorpusCheck{Kind: MatchHeader, Value: "nginx/[0-9]",
		pattern: mustCompile(t, "nginx/[0-9]")}
	got := corpusEvidence(headerCheck, 200, "body", header)
	if !strings.Contains(got, "Server") || !strings.Contains(got, "nginx/1.18.0") {
		t.Errorf("a header check's evidence does not name the header and its value: %q", got)
	}
	// The same check against a header set that carries no match has to answer with
	// something true rather than nothing at all.
	absent := corpusEvidence(headerCheck, 200, "body", http.Header{"X-Other": []string{"x"}})
	if !strings.Contains(absent, "200") {
		t.Errorf("a header check with no matching header produced no usable evidence: %q", absent)
	}

	bodyCheck := CorpusCheck{Kind: MatchBody, Value: "needle",
		pattern: mustCompile(t, "needle")}
	line := corpusEvidence(bodyCheck, 200, "first line\n   needle on its own line   \nlast", nil)
	if !strings.Contains(line, "needle on its own line") {
		t.Errorf("a body check's evidence is not the line that matched: %q", line)
	}
	if strings.HasPrefix(line, "first line") {
		t.Errorf("the evidence kept lines around the match: %q", line)
	}
	// A body that somehow matched without a matching line falls back to the body,
	// trimmed, rather than to an empty string.
	fallback := corpusEvidence(bodyCheck, 200, strings.Repeat("x", 900), nil)
	if len(fallback) <= 300 {
		t.Errorf("a long body was not trimmed: %d bytes", len(fallback))
	}
	if !strings.HasSuffix(fallback, "…") {
		t.Errorf("a trimmed body does not say it was trimmed: %q", fallback[len(fallback)-12:])
	}
}

func TestADelaySlowsTheRunWithoutChangingWhatItFinds(t *testing.T) {
	// The delay exists so an operator can be gentle with a fragile target. It must
	// cost time and nothing else: a run that finds less once a delay is set reads
	// as "the delay changed the result", which it cannot have.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	findings := runSample(t, server.URL, []CorpusCheck{
		{ID: "a", Method: "GET", Path: "/", Kind: MatchCode, Value: "200"},
		{ID: "b", Method: "GET", Path: "/x", Kind: MatchCode, Value: "200"},
	})
	if len(findings) != 2 {
		t.Fatalf("without a delay the run raised %d of 2", len(findings))
	}

	started := time.Now()
	slow := runSampleDelayed(t, server.URL, []CorpusCheck{
		{ID: "a", Method: "GET", Path: "/", Kind: MatchCode, Value: "200"},
		{ID: "b", Method: "GET", Path: "/x", Kind: MatchCode, Value: "200"},
	}, 60*time.Millisecond)
	if len(slow) != 2 {
		t.Errorf("with a delay the run raised %d of 2; the delay changed the result", len(slow))
	}
	if elapsed := time.Since(started); elapsed < 60*time.Millisecond {
		t.Errorf("the run finished in %s with a 60ms delay, so the delay did nothing", elapsed)
	}
}

func TestARedirectIsTheAnswerAndNotThePlaceItPointsAt(t *testing.T) {
	// A check asks whether a path answers. Following the redirect answers a
	// different question — whether some other path exists — and a finding that says
	// "this path exists" because it points at a login page is wrong.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("login page"))
	}))
	defer server.Close()

	findings := runSample(t, server.URL, []CorpusCheck{
		{ID: "redirected-away", Method: "GET", Path: "/admin", Kind: MatchBody,
			Value: "login page", pattern: mustCompile(t, "login page")},
		{ID: "the-redirect-code", Method: "GET", Path: "/admin", Kind: MatchCode, Value: "302"},
	})
	byID := map[string]CorpusFinding{}
	for _, f := range findings {
		byID[f.CheckID] = f
	}
	if _, raised := byID["redirected-away"]; raised {
		t.Error("the runner followed the redirect and reported the target's content as the path's")
	}
	if _, raised := byID["the-redirect-code"]; !raised {
		t.Error("the redirect itself was not reported, though it is what the path answered")
	}
}

func TestACheckWithNoMethodIsSentAsAGet(t *testing.T) {
	// A row without a method is malformed, but sending nothing at all would be
	// worse than defaulting: the path is still worth asking about.
	var seen string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	runSample(t, server.URL, []CorpusCheck{
		{ID: "no-method", Method: "", Path: "/", Kind: MatchCode, Value: "200"},
	})
	if seen != http.MethodGet {
		t.Errorf("a check with no method was sent as %q, want GET", seen)
	}
}

func TestAMethodGoCannotSendIsSkippedRatherThanCrashingTheRun(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// A control character in a method is rejected by net/http while the request is
	// being built. The run has to treat that as one unusable request, not as a
	// panic and not as a reason to abandon the rows after it.
	findings := runSample(t, server.URL, []CorpusCheck{
		{ID: "bad-method", Method: "BAD METHOD", Path: "/", Kind: MatchCode, Value: "200"},
		{ID: "good", Method: "GET", Path: "/ok", Kind: MatchCode, Value: "200"},
	})
	if len(findings) != 1 || findings[0].CheckID != "good" {
		t.Errorf("the run after an unsendable request raised %v", findings)
	}
}

func TestAResponseCutOffMidBodyDoesNotBecomeAMatch(t *testing.T) {
	// The server promises more than it sends and closes. Reading yields nothing and
	// an error; treating the empty body as a match would let any content check fire
	// on every truncated response.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\nshort"))
		_ = conn.Close()
	}))
	defer server.Close()

	findings := runSample(t, server.URL, []CorpusCheck{
		{ID: "truncated", Method: "GET", Path: "/", Kind: MatchCode, Value: "200"},
		{ID: "body", Method: "GET", Path: "/", Kind: MatchBody, Value: "short",
			pattern: mustCompile(t, "short")},
	})
	if len(findings) != 1 || findings[0].CheckID != "truncated" {
		t.Errorf("a truncated response raised %v; only the status it really sent should count", findings)
	}
}

func TestAFailedCorpusStopsTheRunBeforeItSpendsARequest(t *testing.T) {
	corpusOnce.Do(func() {})
	previousCorpus, previousErr := cachedCorpus, cachedErr
	cachedCorpus, cachedErr = nil, fmt.Errorf("fixture: parse failed")
	t.Cleanup(func() { cachedCorpus, cachedErr = previousCorpus, previousErr })

	var hit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if _, err := RunCorpus(context.Background(), CorpusRunRequest{
		Target: server.URL, RoundTripper: http.DefaultTransport,
	}); err == nil {
		t.Fatal("a run with an unreadable corpus reported success")
	}
	if hit {
		t.Error("the run sent requests before it could read the corpus")
	}
}

func runSampleDelayed(t *testing.T, target string, checks []CorpusCheck, delay time.Duration) []CorpusFinding {
	t.Helper()
	corpusOnce.Do(func() {})
	previousCorpus, previousErr := cachedCorpus, cachedErr
	cachedCorpus, cachedErr = checks, nil
	t.Cleanup(func() { cachedCorpus, cachedErr = previousCorpus, previousErr })

	var findings []CorpusFinding
	if _, err := RunCorpus(context.Background(), CorpusRunRequest{
		Target:       target,
		RoundTripper: http.DefaultTransport,
		Concurrency:  2,
		Delay:        delay,
		Timeout:      3 * time.Second,
		OnFinding:    func(f CorpusFinding) { findings = append(findings, f) },
	}); err != nil {
		t.Fatalf("RunCorpus: %v", err)
	}
	return findings
}

func TestCancellingDuringAPerRequestDelayStopsTheWorkerToo(t *testing.T) {
	// The cancellation test above covers a run whose workers finish their queue
	// before the cancel lands. This one covers the other shape: a worker parked in
	// the per-request delay when the cancel arrives. Both places have to wake —
	// a run that keeps sleeping through a cancel is a run an operator cannot stop.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checks := make([]CorpusCheck, 0, 120)
	for i := 0; i < 120; i++ {
		checks = append(checks, CorpusCheck{
			ID: "c", Method: "GET", Path: "/" + strings.Repeat("x", i%7+1) + string(rune('a'+i%26)),
			Kind: MatchCode, Value: "200",
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(120 * time.Millisecond)
		cancel()
	}()

	corpusOnce.Do(func() {})
	previousCorpus, previousErr := cachedCorpus, cachedErr
	cachedCorpus, cachedErr = checks, nil
	t.Cleanup(func() { cachedCorpus, cachedErr = previousCorpus, previousErr })

	started := time.Now()
	result, err := RunCorpus(ctx, CorpusRunRequest{
		Target:       server.URL,
		RoundTripper: http.DefaultTransport,
		Concurrency:  1,
		Delay:        40 * time.Millisecond,
		Timeout:      3 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunCorpus: %v", err)
	}
	elapsed := time.Since(started)
	if !result.Truncated {
		t.Error("a cancelled run reported itself as complete")
	}
	// 120 checks at 40ms each is 4.8s of delay alone. A run that slept through the
	// cancel would be near that; one that wakes on it is far below.
	if elapsed > 2*time.Second {
		t.Errorf("the run took %s; a 120ms cancel did not wake the sleeping worker", elapsed)
	}
}

// runSample runs the runner against a fixed check list by writing a one-row corpus
// and loading it, so the test exercises the same path a real run takes.
func runSample(t *testing.T, target string, checks []CorpusCheck) []CorpusFinding {
	t.Helper()
	return runCorpusWith(t, target, checks, 0)
}

func runBounded(t *testing.T, target string, checks []CorpusCheck, bound int) CorpusRunResult {
	t.Helper()
	var seen CorpusRunResult
	_ = runCorpusWithReporting(t, target, checks, bound, &seen)
	return seen
}

func runCorpusWith(t *testing.T, target string, checks []CorpusCheck, bound int) []CorpusFinding {
	t.Helper()
	return runCorpusWithReporting(t, target, checks, bound, nil)
}

// runCorpusWithReporting drives the runner over an explicit check list.
//
// The production runner reads the embedded corpus, so a test cannot hand it a
// different one. Rather than add a seam to production code for a test's benefit,
// the tests swap the cached corpus for the duration of the call and restore it
// afterwards; the alternative — a runner that takes its corpus as a field — is a
// worse API, because a caller could then point a scan at a list it built by
// accident.
func runCorpusWithReporting(t *testing.T, target string, checks []CorpusCheck, bound int, seen *CorpusRunResult) []CorpusFinding {
	t.Helper()

	// Burn the once against the real corpus first. Assigning without doing this
	// loses the swap: `LoadDefaultCorpus` fires the once, which overwrites what the
	// test just put there, and the run then executes the repository's 5483 checks
	// instead of the three under test.
	corpusOnce.Do(func() {
		cachedCorpus, cachedErr = ParseCorpus(strings.NewReader(string(embeddedCorpus)))
	})
	previous := cachedCorpus
	previousErr := cachedErr
	cachedCorpus = checks
	cachedErr = nil
	t.Cleanup(func() {
		cachedCorpus = previous
		cachedErr = previousErr
	})

	var findings []CorpusFinding
	result, err := RunCorpus(context.Background(), CorpusRunRequest{
		Target:       target,
		RoundTripper: http.DefaultTransport,
		MaxChecks:    bound,
		Concurrency:  4,
		Timeout:      3 * time.Second,
		OnFinding: func(f CorpusFinding) {
			findings = append(findings, f)
		},
	})
	if err != nil {
		t.Fatalf("RunCorpus: %v", err)
	}
	if seen != nil {
		*seen = result
	}
	return findings
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAPercentEncodedPathIsSentAsItWasWritten(t *testing.T) {
	// `URL.Path` is the decoded path, so assigning an escaped one into it makes the
	// request escape the percent signs again: `/%00` left as `/%2500`. Measured
	// against the parity stand, 110 checks on percent-encoded paths were answered
	// by a server that had never been asked those paths. This records what actually
	// arrives on the wire rather than what the URL struct looks like afterwards.
	var seen []string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.RequestURI)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>File Name</html>"))
	}))
	defer target.Close()

	base, err := url.Parse(target.URL)
	if err != nil {
		t.Fatalf("parsing the target: %v", err)
	}
	client := &http.Client{Transport: http.DefaultTransport}

	for _, want := range []string{"/%00", "/%2e/", "/%22%3cscript%3e", "/.env"} {
		seen = nil
		status, body, _ := corpusFetch(context.Background(), client, base, CorpusRequest{
			Method: http.MethodGet,
			Path:   want,
		})
		if len(seen) != 1 {
			t.Fatalf("path %s produced %d requests, want 1", want, len(seen))
		}
		if seen[0] != want {
			t.Errorf("path %s arrived as %s; a check must ask the server the path it was written for", want, seen[0])
		}
		if status != http.StatusOK || !strings.Contains(body, "File Name") {
			t.Errorf("path %s: status %d, body %q", want, status, body)
		}
	}
}

func TestTheCorpusHoldsNoPathThatCannotBeSentAsWritten(t *testing.T) {
	// Two rows of the base — `/%NETHOOD%/` and `/%a%s%p%d` — have escapes that do
	// not decode. Go cannot send such a path unescaped: it arrives as `/%25…`, which
	// is a different path, so the check would ask about something nobody wrote and
	// report a clean result either way. The converter drops them with a count, and
	// this is the check that the drop actually happened.
	all, err := LoadDefaultCorpus()
	if err != nil {
		t.Fatalf("loading the corpus: %v", err)
	}
	for _, check := range all {
		if reMatchBrokenEscape(check.Path) {
			t.Errorf("check %s carries a path Go cannot send as written: %s", check.ID, check.Path)
		}
	}
}

// reMatchBrokenEscape reports a percent sign that is not the start of a two-digit
// escape. Go's own rule, written out so this test does not depend on how the
// runner happens to handle such a path.
var reMatchBrokenEscape = regexp.MustCompile("%(?:[^0-9A-Fa-f]|[0-9A-Fa-f][^0-9A-Fa-f]|[0-9A-Fa-f]$)").MatchString

func TestACorpusPathArrivesWithItsOwnBytes(t *testing.T) {
	// The base writes this path with raw `<`, `'` and parentheses — 26 rows of the
	// database do. Go escapes all of them by default, so the server would be asked
	// about `%3Cscript%3E…`: a different path from the one the check is written
	// for. The measurement is the raw request target as it arrived, because the
	// server's own `URL.EscapedPath()` escapes again and reports the escaped form
	// even when the wire carried the original bytes.
	var seen string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.RequestURI
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<script>alert('Vulnerable');</script>"))
	}))
	defer target.Close()

	base, err := url.Parse(target.URL)
	if err != nil {
		t.Fatalf("parsing the target: %v", err)
	}
	want := "/<script>alert('Vulnerable')</script>"
	status, body, _ := corpusFetch(context.Background(), &http.Client{Transport: http.DefaultTransport}, base, CorpusRequest{
		Method: http.MethodGet,
		Path:   want,
	})
	if seen != want {
		t.Errorf("the request target arrived as %s, want %s", seen, want)
	}
	if status != http.StatusOK || !strings.Contains(body, "Vulnerable") {
		t.Errorf("status %d, body %q", status, body)
	}
}

func TestEvidenceFromARemoteServerCarriesNoControlCharacters(t *testing.T) {
	// A live target sent a form feed inside the matching text. One raw control
	// character makes the whole JSON response unparsable, and the browser rejects
	// it — a run that reached 96 % then showed an empty panel.
	body := "<html>\x0cFile Name</html>"
	finding := CorpusFinding{
		CheckID: "000679", Method: http.MethodGet, Path: "/%00",
		Evidence: corpusEvidence(CorpusCheck{
			ID: "000679", Kind: MatchBody, Value: "File Name",
			pattern: mustCompile(t, "File Name"),
		}, 200, body, nil),
	}
	for _, symbol := range finding.Evidence {
		if symbol < 0x20 && symbol != '\t' && symbol != '\n' && symbol != '\r' {
			t.Fatalf("evidence carries control character %q; the JSON response stops parsing", symbol)
		}
	}
	if !strings.Contains(finding.Evidence, "File Name") {
		t.Errorf("evidence lost the matching text: %q", finding.Evidence)
	}
}

// TestChecksCountEveryRowTheRunLookedAtAndNotOnlyTheMatches is the test for a
// counter that stood on the wrong side of an `if`. One response answers every check
// written for its path, so "checks run" is the number of rows whose verdict was
// asked for — matched or not. Reporting only the matches made `Checks` and
// `Findings` identical on every run, which is how a 6480-row corpus came to be
// reported as "5906 findings from 5906 checks" with the rest of the corpus
// silently unaccounted for.
func TestChecksCountEveryRowTheRunLookedAtAndNotOnlyTheMatches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello there"))
	}))
	defer server.Close()

	checks := []CorpusCheck{
		{ID: "000001", Method: http.MethodGet, Path: "/", Kind: MatchCode, Value: "200"},
		{ID: "000002", Method: http.MethodGet, Path: "/", Kind: MatchBody, Value: "needle",
			pattern: mustCompile(t, "needle")},
		{ID: "000003", Method: http.MethodGet, Path: "/", Kind: MatchBody, Value: "hello",
			pattern: mustCompile(t, "hello")},
	}
	result := runBounded(t, server.URL, checks, 0)
	if result.Findings != 2 {
		t.Fatalf("Findings = %d, want 2 (the code and the body row that matches)", result.Findings)
	}
	if result.Checks != 3 {
		t.Errorf("Checks = %d, want 3: every row written for the path was looked at, "+
			"and a row that did not match is still a row the run read", result.Checks)
	}
	if result.Checks == result.Findings {
		t.Errorf("Checks (%d) equals Findings (%d): the two numbers can only be equal "+
			"when nothing failed to match, which is not a thing a real run reports",
			result.Checks, result.Findings)
	}
}

// TestChecksWhoseRequestNeverCameBackAreCountedApart covers a run over a target
// that answers some paths and drops the rest. Those checks get no verdict, which
// is a different statement from "the path does not exist" — and without a number
// of their own the only trace of them is a gap between the corpus size and the
// checks the report claims to have read, which is exactly how a quietly narrowed
// run would look.
func TestChecksWhoseRequestNeverCameBackAreCountedApart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gone/" {
			// A connection that comes up and dies without a status line: the
			// round trip fails, so there is no response to judge any check against.
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Error("the test server cannot hijack the connection")
				return
			}
			conn, _, err := hijacker.Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checks := []CorpusCheck{
		{ID: "000001", Method: http.MethodGet, Path: "/alive/", Kind: MatchCode, Value: "200"},
		{ID: "000002", Method: http.MethodGet, Path: "/gone/", Kind: MatchCode, Value: "200"},
		{ID: "000003", Method: http.MethodGet, Path: "/gone/", Kind: MatchBody, Value: "x",
			pattern: mustCompile(t, "x")},
	}
	result := runBounded(t, server.URL, checks, 0)
	if result.Findings != 1 {
		t.Fatalf("Findings = %d, want 1 (only the path that answered)", result.Findings)
	}
	if result.Checks != 1 {
		t.Errorf("Checks = %d, want 1: a check whose request died was never judged, "+
			"so it is not one of the checks the run read", result.Checks)
	}
	if result.Skipped != 2 {
		t.Errorf("Skipped = %d, want 2: the two checks written for the path that never "+
			"answered are named as their own number instead of vanishing", result.Skipped)
	}
}

// TestTheLastProgressReportMatchesTheRunItDescribes covers a target that answers
// nothing at all. Progress used to be reported before the counters for that request
// moved, so every number in a live panel lagged by exactly one request — and on a
// run where nothing answered the final report said 6479 of 6480 rows skipped: one
// row that no counter had heard of, which is the very gap the counter exists to
// close. The last report a run makes has to be the run's own final state.
func TestTheLastProgressReportMatchesTheRunItDescribes(t *testing.T) {
	transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})
	checks := []CorpusCheck{
		{ID: "000001", Method: http.MethodGet, Path: "/a/", Kind: MatchCode, Value: "200"},
		{ID: "000002", Method: http.MethodGet, Path: "/b/", Kind: MatchCode, Value: "200"},
		{ID: "000003", Method: http.MethodGet, Path: "/c/", Kind: MatchCode, Value: "200"},
	}
	corpusOnce.Do(func() {
		cachedCorpus, cachedErr = ParseCorpus(strings.NewReader(string(embeddedCorpus)))
	})
	previous, previousErr := cachedCorpus, cachedErr
	cachedCorpus, cachedErr = checks, nil
	t.Cleanup(func() { cachedCorpus, cachedErr = previous, previousErr })

	var last CorpusProgress
	var reports int
	result, err := RunCorpus(context.Background(), CorpusRunRequest{
		Target:       "https://127.0.0.1:1/",
		RoundTripper: transport,
		Concurrency:  1,
		Timeout:      time.Second,
		OnProgress:   func(p CorpusProgress) { last = p; reports++ },
	})
	if err != nil {
		t.Fatalf("RunCorpus: %v", err)
	}
	if reports == 0 {
		t.Fatal("the run reported no progress at all")
	}
	if result.Checks != 0 || result.Skipped != len(checks) {
		t.Fatalf("Checks = %d, Skipped = %d, want 0 and %d: nothing answered, so every "+
			"row was read and none was judged", result.Checks, result.Skipped, len(checks))
	}
	if last.Skipped != int64(result.Skipped) {
		t.Errorf("the last progress report says %d rows unanswered while the run finished "+
			"with %d: a live panel reading the last report understates the run by one "+
			"request", last.Skipped, result.Skipped)
	}
	if last.Checks != int64(result.Checks) {
		t.Errorf("the last progress report says %d checks read while the run finished with "+
			"%d", last.Checks, result.Checks)
	}
	if last.Done != int64(result.Requests) {
		t.Errorf("the last progress report says %d requests sent while the run sent %d",
			last.Done, result.Requests)
	}
}
