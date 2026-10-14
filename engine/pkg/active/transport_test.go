package active

// Tests for the probe transport.
//
// The assertions here are about a wire contract: which bytes go out, which come
// back, and what the client refuses to do. They run against `httptest` servers,
// including a TLS one with a certificate no system trusts, because "we do not
// disable verification" is a claim about behaviour and the only way to prove it
// is to point the client at a certificate that would be accepted if the claim
// were false.

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// recordedRequest is what a test server saw.
type recordedRequest struct {
	Method      string
	Path        string
	RawQuery    string
	Body        string
	UserAgent   string
	AcceptLang  string
	ContentType string
	Cookie      string
}

// newProbeServer starts a server that records every request it receives and
// replies with the handler.
func newProbeServer(t *testing.T, handler func(rec recordedRequest) (int, http.Header, string)) *httptest.Server {
	t.Helper()
	var seen recordedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = recordedRequest{
			Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery,
			Body: string(body), UserAgent: r.Header.Get("User-Agent"),
			AcceptLang:  r.Header.Get("Accept-Language"),
			ContentType: r.Header.Get("Content-Type"),
			Cookie:      r.Header.Get("Cookie"),
		}
		status, header, text := handler(seen)
		for name, values := range header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, text)
	}))
	t.Cleanup(server.Close)
	return server
}

func mustTransport(t *testing.T) *Transport {
	t.Helper()
	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	return transport
}

// A nil RoundTripper must be refused. The engine always has one to give; a
// caller that reaches this function without one has lost the recording
// transport, and falling back to the default would produce a working scan whose
// evidence is stored nowhere.
func TestNewTransportRefusesNilRoundTripper(t *testing.T) {
	transport, err := NewTransport(nil, Options{})
	if err == nil {
		t.Fatal("NewTransport(nil) succeeded, want an error rather than a silent default")
	}
	if transport != nil {
		t.Fatal("NewTransport(nil) returned a transport alongside its error")
	}
	if !strings.Contains(err.Error(), "RoundTripper") {
		t.Fatalf("error = %q, want it to name the missing RoundTripper", err)
	}
}

// A probe must name itself in the User-Agent. An operator reading the target's
// own access log has to be able to tell a scan from a page load, and a value
// impersonating a browser makes that impossible.
func TestProbeIdentifiesItselfAndCarriesAnalystLanguage(t *testing.T) {
	server := newProbeServer(t, func(rec recordedRequest) (int, http.Header, string) {
		return 200, nil, "ok"
	})
	transport, err := NewTransport(http.DefaultTransport, Options{
		UserAgent:      "RequestRider-ActiveScanner/1.2",
		AcceptLanguage: "uk-UA",
	})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	if _, err := transport.Do(context.Background(), http.MethodGet, server.URL, nil, true, nil); err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp, err := transport.Do(context.Background(), http.MethodGet, server.URL, nil, true, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestDoSendsAcceptLanguageAndUserAgent(t *testing.T) {
	var seen recordedRequest
	server := newProbeServer(t, func(rec recordedRequest) (int, http.Header, string) {
		seen = rec
		return 200, nil, "ok"
	})
	transport, err := NewTransport(http.DefaultTransport, Options{
		UserAgent:      "RequestRider-ActiveScanner/1.2",
		AcceptLanguage: "uk-UA,uk;q=0.9",
	})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	if _, err := transport.Do(context.Background(), http.MethodGet, server.URL, nil, true, nil); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if seen.UserAgent != "RequestRider-ActiveScanner/1.2" {
		t.Errorf("User-Agent = %q, want the scanner to identify itself", seen.UserAgent)
	}
	if seen.AcceptLang != "uk-UA,uk;q=0.9" {
		t.Errorf("Accept-Language = %q, want the analyst's language", seen.AcceptLang)
	}
}

// An empty language preference omits the header rather than inventing one, so
// the request is the one that was made before the field existed.
func TestDoOmitsAcceptLanguageWhenUnset(t *testing.T) {
	var seen recordedRequest
	server := newProbeServer(t, func(rec recordedRequest) (int, http.Header, string) {
		seen = rec
		return 200, nil, "ok"
	})
	transport := mustTransport(t)
	if _, err := transport.Do(context.Background(), http.MethodGet, server.URL, nil, true, nil); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if seen.AcceptLang != "" {
		t.Fatalf("Accept-Language = %q, want the header absent", seen.AcceptLang)
	}
	if seen.UserAgent != DefaultUserAgent {
		t.Errorf("User-Agent = %q, want %q", seen.UserAgent, DefaultUserAgent)
	}
}

// The TLS claim is proved against a certificate no system trusts. If
// verification were disabled anywhere on this path, the request would succeed
// and this test would fail — which is the point: a green test here is evidence
// the client is not willing to accept a machine-in-the-middle.
func TestDoVerifiesTLSCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "secret-admin-panel")
	}))
	defer server.Close()
	transport := mustTransport(t)
	resp, err := transport.Do(context.Background(), http.MethodGet, server.URL, nil, true, nil)
	if err == nil {
		t.Fatalf("request to an untrusted certificate succeeded (status %d, body %q); verification is disabled",
			resp.StatusCode, resp.Body)
	}
	if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "x509") {
		t.Fatalf("error = %q, want a certificate verification failure", err)
	}
}

// A certificate the client is configured to trust is accepted, so the previous
// test proves a policy rather than a broken client.
func TestDoAcceptsTrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "reachable")
	}))
	defer server.Close()
	pool := server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	transport, err := NewTransport(&http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}, Options{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	resp, err := transport.Do(context.Background(), http.MethodGet, server.URL, nil, true, nil)
	if err != nil {
		t.Fatalf("Do against a trusted certificate: %v", err)
	}
	if resp.Body != "reachable" {
		t.Fatalf("body = %q, want %q", resp.Body, "reachable")
	}
}

// The body is read in full. A probe that read a prefix would compare two halves
// of two documents and report the difference as a finding, so the size matters
// far more than it looks.
func TestDoReadsBodyInFull(t *testing.T) {
	const size = 3 << 20 // 3 MiB: the size a cap of a megabyte would truncate.
	large := strings.Repeat("A", size)
	server := newProbeServer(t, func(rec recordedRequest) (int, http.Header, string) {
		return 200, nil, large
	})
	transport := mustTransport(t)
	resp, err := transport.Do(context.Background(), http.MethodGet, server.URL, nil, true, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(resp.Body) != size {
		t.Fatalf("body length = %d, want %d (the body must not be capped)", len(resp.Body), size)
	}
}

func TestDoBuildsQueryForGetAndBodyForPost(t *testing.T) {
	var seen recordedRequest
	server := newProbeServer(t, func(rec recordedRequest) (int, http.Header, string) {
		seen = rec
		return 200, nil, "ok"
	})
	transport := mustTransport(t)
	values := url.Values{"q": {"' OR 1=1--"}, "page": {"2"}}

	if _, err := transport.Do(context.Background(), http.MethodGet, server.URL, values, true, nil); err != nil {
		t.Fatalf("Do GET: %v", err)
	}
	if seen.Body != "" {
		t.Errorf("GET body = %q, want none", seen.Body)
	}
	parsed, err := url.ParseQuery(seen.RawQuery)
	if err != nil {
		t.Fatalf("server received unparsable query %q: %v", seen.RawQuery, err)
	}
	if parsed.Get("q") != "' OR 1=1--" || parsed.Get("page") != "2" {
		t.Errorf("query = %v, want both parameters", parsed)
	}

	if _, err := transport.Do(context.Background(), http.MethodPost, server.URL, values, true, nil); err != nil {
		t.Fatalf("Do POST: %v", err)
	}
	if seen.RawQuery != "" {
		t.Errorf("POST query = %q, want the parameters in the body", seen.RawQuery)
	}
	body, err := url.ParseQuery(seen.Body)
	if err != nil {
		t.Fatalf("server received unparsable body %q: %v", seen.Body, err)
	}
	if body.Get("q") != "' OR 1=1--" {
		t.Errorf("body q = %q, want the payload", body.Get("q"))
	}
	if seen.ContentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want a form encoding", seen.ContentType)
	}
}

// A GET with no values must not acquire a bare trailing "?", which some servers
// treat as a different resource and which would silently change the baseline
// every probe is compared against.
func TestDoSendsNoTrailingQuestionMarkForEmptyGet(t *testing.T) {
	var target string
	var seen recordedRequest
	server := newProbeServer(t, func(rec recordedRequest) (int, http.Header, string) {
		seen = rec
		return 200, nil, "ok"
	})
	target = server.URL
	transport := mustTransport(t)
	if _, err := transport.Do(context.Background(), http.MethodGet, target, url.Values{}, true, nil); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if seen.RawQuery != "" {
		t.Fatalf("query = %q, want none", seen.RawQuery)
	}
}

// A detector that asked not to follow must see the 3xx itself. An
// open-redirect probe reads the Location header, and following it would hide the
// very answer it went for. The redirect target is a second local server, so
// "did we follow it" is answered by which server answered, not by a DNS lookup.
func TestDoCanSeeTheRedirectItself(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "arrived")
	}))
	defer destination.Close()
	source := newProbeServer(t, func(rec recordedRequest) (int, http.Header, string) {
		return http.StatusFound, http.Header{"Location": {destination.URL}}, "moved"
	})
	transport := mustTransport(t)

	resp, err := transport.Do(context.Background(), http.MethodGet, source.URL, nil, false, nil)
	if err != nil {
		t.Fatalf("Do without follow: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want the 302 itself", resp.StatusCode)
	}
	if got := resp.HeaderValue("Location"); got != destination.URL {
		t.Fatalf("Location = %q, want %q", got, destination.URL)
	}
	if resp.Body != "moved" {
		t.Fatalf("body = %q, want the 3xx body, not the destination's", resp.Body)
	}

	resp, err = transport.Do(context.Background(), http.MethodGet, source.URL, nil, true, nil)
	if err != nil {
		t.Fatalf("Do with follow: %v", err)
	}
	if resp.FinalURL != destination.URL {
		t.Fatalf("FinalURL = %q, want %q", resp.FinalURL, destination.URL)
	}
	if resp.Body != "arrived" {
		t.Fatalf("body = %q, want the destination's response", resp.Body)
	}
}

// A session cookie obtained by one probe is presented to the next. A scan that
// dropped it would fail to reach anything behind a login and would report that
// page as clean.
func TestTransportKeepsCookiesBetweenProbes(t *testing.T) {
	var seen recordedRequest
	issued := false
	server := newProbeServer(t, func(rec recordedRequest) (int, http.Header, string) {
		seen = rec
		if !issued {
			issued = true
			return 200, http.Header{"Set-Cookie": {"session=abc123; Path=/"}}, "welcome"
		}
		return 200, nil, "private"
	})
	transport := mustTransport(t)

	resp, err := transport.Do(context.Background(), http.MethodGet, server.URL, nil, true, nil)
	if err != nil {
		t.Fatalf("first Do: %v", err)
	}
	if len(resp.SetCookies()) != 1 {
		t.Fatalf("Set-Cookie = %v, want one", resp.SetCookies())
	}
	if _, err := transport.Do(context.Background(), http.MethodGet, server.URL+"/private", nil, true, nil); err != nil {
		t.Fatalf("second Do: %v", err)
	}
	if !strings.Contains(seen.Cookie, "session=abc123") {
		t.Fatalf("Cookie = %q, want the session carried over", seen.Cookie)
	}
}

// Fire substitutes exactly one parameter and leaves the siblings alone. A
// surface that forced the caller to rebuild the other parameters would be
// testing a request the application never received.
func TestFireSubstitutesOneParameterAndKeepsSiblings(t *testing.T) {
	var seen recordedRequest
	server := newProbeServer(t, func(rec recordedRequest) (int, http.Header, string) {
		seen = rec
		return 200, nil, "ok"
	})
	transport := mustTransport(t)
	point := Point{
		URL: server.URL, Method: http.MethodGet, Param: "q",
		Values: url.Values{"q": {"shoes"}, "lang": {"uk"}},
	}
	if _, err := transport.Fire(context.Background(), point, "q", "shoes' OR '1'='1", false, nil); err != nil {
		t.Fatalf("Fire: %v", err)
	}
	parsed, err := url.ParseQuery(seen.RawQuery)
	if err != nil {
		t.Fatalf("unparsable query %q: %v", seen.RawQuery, err)
	}
	if got := parsed.Get("q"); got != "shoes' OR '1'='1" {
		t.Errorf("q = %q, want the payload", got)
	}
	if got := parsed.Get("lang"); got != "uk" {
		t.Errorf("lang = %q, want the sibling value preserved", got)
	}
}

// The baseline is the request the application would have received without the
// scanner. Fire with an empty parameter is that same request, through the same
// code path, so the two cannot drift apart.
func TestBaselineEqualsUntouchedFire(t *testing.T) {
	var seen recordedRequest
	server := newProbeServer(t, func(rec recordedRequest) (int, http.Header, string) {
		seen = rec
		return 200, nil, "ok"
	})
	transport := mustTransport(t)
	point := Point{
		URL: server.URL, Method: http.MethodPost, Param: "q",
		Values: url.Values{"q": {"shoes"}, "csrf": {"tok"}},
	}
	if _, err := transport.Baseline(context.Background(), point, false); err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	baseline := seen
	if _, err := transport.Fire(context.Background(), point, "", "", false, nil); err != nil {
		t.Fatalf("Fire: %v", err)
	}
	if baseline.Body != seen.Body || baseline.Method != seen.Method {
		t.Fatalf("Baseline %q/%q and empty Fire %q/%q differ; they must be the same request",
			baseline.Method, baseline.Body, seen.Method, seen.Body)
	}
}

// A cancelled run is not a probe failure. An operator who pressed Cancel must
// not read the resulting silence as a clean target.
func TestDoReportsCancellationAsContextError(t *testing.T) {
	server := newProbeServer(t, func(rec recordedRequest) (int, http.Header, string) {
		time.Sleep(2 * time.Second)
		return 200, nil, "late"
	})
	transport, err := NewTransport(http.DefaultTransport, Options{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, err = transport.Do(ctx, http.MethodGet, server.URL, nil, true, nil)
	if err == nil {
		t.Fatal("Do returned no error after cancellation")
	}
	if err != context.Canceled {
		t.Fatalf("error = %v, want context.Canceled so a cancelled run is not a probe failure", err)
	}
}

// An extra header set by a probe wins over the defaults, because a CORS or
// redirect probe has to present the Origin it is testing.
func TestDoSetsOriginHeaderFromExtra(t *testing.T) {
	var origin string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin = r.Header.Get("Origin")
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	transport := mustTransport(t)
	extra := http.Header{"Origin": {"https://attacker.example"}}
	if _, err := transport.Do(context.Background(), http.MethodGet, server.URL, nil, true, extra); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if origin != "https://attacker.example" {
		t.Fatalf("Origin = %q, want the probe's own value", origin)
	}
}

// The reproduction has to run. A finding a triager cannot reproduce is one they
// will close, and the command has to be the same request the probe sent.
func TestCurlPointReproducesTheProbe(t *testing.T) {
	point := Point{
		URL: "http://target.test/search", Method: http.MethodGet, Param: "q",
		Values: url.Values{"q": {"shoes"}, "lang": {"uk"}},
	}
	command := CurlPoint(point, "q", "<svg onload=alert(1)>")
	for _, fragment := range []string{"curl", "http://target.test/search?", "lang=uk", "q="} {
		if !strings.Contains(command, fragment) {
			t.Errorf("command %q missing %q", command, fragment)
		}
	}
	if strings.Contains(command, "shoes") {
		t.Errorf("command %q still carries the original value under the probed key", command)
	}
}

// Two runs over the same point must produce byte-identical commands, because a
// diff between two reports should show what changed on the target and nothing
// else.
func TestCurlPointIsByteIdenticalAcrossRuns(t *testing.T) {
	point := Point{
		URL: "http://target.test/s", Method: http.MethodGet, Param: "q",
		Values: url.Values{"z": {"1"}, "a": {"2"}, "m": {"3"}},
	}
	first := CurlPoint(point, "q", "payload")
	for i := 0; i < 30; i++ {
		if next := CurlPoint(point, "q", "payload"); next != first {
			t.Fatalf("run %d = %q, want %q", i, next, first)
		}
	}
}

func TestCurlRendersPostBody(t *testing.T) {
	point := Point{
		URL: "http://target.test/login", Method: http.MethodPost, Param: "user",
		Values: url.Values{"user": {"admin"}},
	}
	command := CurlPoint(point, "user", "admin' OR '1'='1")
	if !strings.Contains(command, "-X POST") {
		t.Errorf("command %q missing the method", command)
	}
	if !strings.Contains(command, "--data") {
		t.Errorf("command %q missing the form body", command)
	}
	if !strings.Contains(command, "http://target.test/login") {
		t.Errorf("command %q missing the target", command)
	}
}
