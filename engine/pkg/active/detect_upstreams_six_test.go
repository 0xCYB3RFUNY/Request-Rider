package active

// Tests for the three detectors ported from lonkero and Dalfox: outdated
// client-side libraries, server-side includes and the web-cache-deception
// precondition.
//
// Each fixture answers the one thing its detector claims, so a finding can only
// appear if the detector's own rule fired. The controls are the part that
// matters: a page with a *fixed* library, a page that echoes the SSI directive
// back without executing it, and a dynamic path that 404s for a static
// extension are the three cases that turn a table of patterns into noise.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// js-library
// ---------------------------------------------------------------------------

func jsLibraryFixture(t *testing.T, body string) (*Transport, Point) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return mustTransport(t), Point{URL: server.URL, Method: http.MethodGet, Param: "", Values: url.Values{}}
}

func (JSLibrary) probe(t *testing.T, transport *Transport, p Point) []Finding {
	t.Helper()
	return JSLibrary{}.Scan(context.Background(), transport, p, baselineOf(t, transport, p))
}

func TestJSLibraryReportsVersionBelowTheFixedRelease(t *testing.T) {
	transport, point := jsLibraryFixture(t, `<html><head>`+
		`<script src="/static/jquery-3.4.1.min.js"></script>`+
		`<script src="/static/handlebars.min.js"></script>`+
		`</head><body>ok</body></html>`)
	findings := (JSLibrary{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (handlebars has no version in its file name)", len(findings))
	}
	finding := findings[0]
	if finding.Tier != TierPublic {
		t.Errorf("tier = %q, want %q: a version in a src is a property of the page, not an exploit",
			finding.Tier, TierPublic)
	}
	if finding.Severity != SeverityInfo {
		t.Errorf("severity = %q, want info: %s caps %q at info", finding.Severity, finding.Tier, finding.Severity)
	}
	if !strings.Contains(finding.Title, "jQuery 3.4.1") {
		t.Errorf("title = %q, want the library and the version", finding.Title)
	}
	if !strings.Contains(finding.Description, "CVE-2020-11022") {
		t.Errorf("description does not name the advisories: %q", finding.Description)
	}
}

func TestJSLibraryReadsTheVersionFromTheQueryString(t *testing.T) {
	transport, point := jsLibraryFixture(t, `<script src="/cdn/lodash.js?v=4.17.15"></script>`)
	findings := (JSLibrary{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Title, "4.17.15") {
		t.Errorf("title = %q, want the version from the query string", findings[0].Title)
	}
}

// A page on the fixed release is not a finding. This is the case that makes the
// table usable: without it every site that has ever upgraded would carry a row.
func TestJSLibraryIsSilentOnFixedVersions(t *testing.T) {
	transport, point := jsLibraryFixture(t, `<script src="/static/jquery-3.7.1.min.js"></script>`+
		`<script src="/static/bootstrap.bundle.min.js"></script>`+
		`<script src="/static/angular.min.js"></script>`)
	if findings := (JSLibrary{}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: %s", len(findings), findings[0].Title)
	}
}

// A library named in an image URL is not loaded as code.
func TestJSLibraryIgnoresNonScriptURLs(t *testing.T) {
	transport, point := jsLibraryFixture(t,
		`<img src="/img/jquery-1.7.2.min.js.png"><a href="/docs/jquery-1.7.2.js">docs</a>`)
	if findings := (JSLibrary{}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: only a script src loads a library", len(findings))
	}
}

func TestJSVersionBelowComparesComponentwise(t *testing.T) {
	cases := []struct {
		have, fixed string
		want        bool
	}{
		{"3.4.1", "3.5.0", true},
		{"3.5.0", "3.5.0", false},
		{"3.10.0", "3.5.0", false},
		{"2.6.4", "3.0.0", true},
		{"1.12", "1.13.0", true},
		{"1.13", "1.13.0", false},
		{"not-a-version", "3.5.0", false},
	}
	for _, tc := range cases {
		if got := jsVersionBelow(tc.have, tc.fixed); got != tc.want {
			t.Errorf("jsVersionBelow(%q, %q) = %v, want %v", tc.have, tc.fixed, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// ssi
// ---------------------------------------------------------------------------

// ssiFixture decides whether the include filter is on: when it is, the response
// echoes the probe header the way nginx and Apache do.
func ssiFixture(t *testing.T, enabled bool) (*Transport, Point) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		value := r.URL.Query().Get("q")
		_, _ = io.WriteString(w, "<html><body><p>"+value+"</p></body></html>")
		if enabled {
			// The second pass over the body, which is what mod_include and nginx's
			// ssi filter do: the directive is replaced by the header's value.
			_, _ = io.WriteString(w, "<!--#echo var=\"HTTP_X_RR_SSI_PROBE\"-->"+
				"\n<div>probe:"+r.Header.Get(ssiProbeHeader)+"</div>")
		}
	}))
	t.Cleanup(server.Close)
	return mustTransport(t), Point{
		URL: server.URL, Method: http.MethodGet, Param: "q", Values: url.Values{"q": {"hello"}},
	}
}

func (SSI) probe(t *testing.T, transport *Transport, p Point) []Finding {
	t.Helper()
	return SSI{}.Scan(context.Background(), transport, p, baselineOf(t, transport, p))
}

func TestSSIReportsTheCanaryThatWasNeverInAParameter(t *testing.T) {
	transport, point := ssiFixture(t, true)
	findings := (SSI{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Tier != TierVerified {
		t.Errorf("tier = %q, want %q", finding.Tier, TierVerified)
	}
	if !strings.Contains(finding.Evidence, "probe:rrssi") {
		t.Errorf("evidence = %q, want the echoed header value", finding.Evidence)
	}
	if !ssiCarriesDirective(finding.Payload) {
		t.Errorf("payload = %q, want an include directive", finding.Payload)
	}
}

// The decisive control: a page that reflects the value contains the directive
// and does not execute it. A detector that looked for its own payload in the
// body would report this page.
func TestSSIIsSilentWhenTheDirectiveIsOnlyReflected(t *testing.T) {
	transport, point := ssiFixture(t, false)
	if findings := (SSI{}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: the directive was echoed, not executed", len(findings))
	}
}

// The control for the content-type guard: the server *does* echo the probe header,
// so the only thing that can keep this row off the report is the check that a
// JSON body is not processed for includes. A fixture that answered "nothing" here
// would pass for the wrong reason — the probe would find nothing either way.
func TestSSISkipsNonHTMLResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"q":"`+r.URL.Query().Get("q")+`","probe":"`+
			r.Header.Get(ssiProbeHeader)+`"}`)
	}))
	t.Cleanup(server.Close)
	transport := mustTransport(t)
	point := Point{URL: server.URL, Method: http.MethodGet, Param: "q", Values: url.Values{"q": {"hello"}}}
	if findings := (SSI{}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: a JSON body is not processed for includes", len(findings))
	}
}

// ---------------------------------------------------------------------------
// cache-deception
// ---------------------------------------------------------------------------

// cacheFixture serves one long document for every path that is not a static
// suffix, and a 404 with the same body for the ones that are — unless
// `servesSuffix` is set, which is the vulnerable behaviour.
func cacheFixture(t *testing.T, servesSuffix bool, body string) (*Transport, Point) {
	t.Helper()
	handler := func(w http.ResponseWriter, r *http.Request) {
		isStatic := strings.HasSuffix(r.URL.Path, ".css") || strings.HasSuffix(r.URL.Path, ".js") ||
			strings.HasSuffix(r.URL.Path, ".png") || strings.HasSuffix(r.URL.Path, ".ico")
		if isStatic && !servesSuffix {
			// A soft 404: the status says the path does not exist while the body
			// still carries the document. The status check is what has to stop the
			// finding here, so the body must not be empty.
			w.WriteHeader(http.StatusNotFound)
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, body)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, body)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)
	return mustTransport(t), Point{URL: server.URL + "/profile", Method: http.MethodGet, Values: url.Values{}}
}

const cachePageBody = `<html><body><h1>Account</h1><p>Signed in as operator@example.test with 4 saved ` +
	`payment methods and a shipping address in Rotterdam. This paragraph exists so that the document is long ` +
	`enough for the detector to compare it, and it is deliberately boring.</p></body></html>`

func (WebCacheDeception) probe(t *testing.T, transport *Transport, p Point) []Finding {
	t.Helper()
	return WebCacheDeception{}.Scan(context.Background(), transport, p, baselineOf(t, transport, p))
}

func TestCacheDeceptionReportsTheStaticPathThatServesTheDocument(t *testing.T) {
	transport, point := cacheFixture(t, true, cachePageBody)
	findings := (WebCacheDeception{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Tier != TierVerified {
		t.Errorf("tier = %q, want %q", finding.Tier, TierVerified)
	}
	if !strings.Contains(finding.Payload, ".css") {
		t.Errorf("payload = %q, want the suffixed path", finding.Payload)
	}
	if !strings.Contains(finding.Description, "not established by this scan") {
		t.Errorf("description must state that the cache itself was not proven: %q", finding.Description)
	}
}

func TestCacheDeceptionIsSilentWhenStaticPaths404(t *testing.T) {
	transport, point := cacheFixture(t, false, cachePageBody)
	if findings := (WebCacheDeception{}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}

// The comparison has to survive the values that legitimately differ between two
// fetches, or the detector is silent on every real site.
func TestCacheDeceptionIgnoresPerRequestTokens(t *testing.T) {
	rotating := `<html><body><input type="hidden" name="csrf_token" value="a1b2c3d4e5f60718293a4b5c6d7e8f90">` +
		`<p>Signed in as operator@example.test with 4 saved payment methods and a shipping address in ` +
		`Rotterdam, plus a long enough paragraph so the body passes the size check for this comparison.</p>` +
		`</body></html>`
	var counter int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter++
		page := rotating
		if r.URL.Path == "/profile" {
			// Only the baseline differs: the token and the request id.
			page = strings.ReplaceAll(rotating, "a1b2c3d4e5f60718293a4b5c6d7e8f90", tokenFor(counter))
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, page)
	}))
	t.Cleanup(server.Close)
	transport := mustTransport(t)
	point := Point{URL: server.URL + "/profile", Method: http.MethodGet, Values: url.Values{}}
	findings := (WebCacheDeception{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: a rotated token is not a different page", len(findings))
	}
}

func tokenFor(n int) string {
	return strings.Repeat("0123456789abcdef", 2) + string(rune('a'+n))
}

func TestStripDynamicNoiseKeepsRealContent(t *testing.T) {
	body := `<p>Signed in as operator@example.test</p><input name="csrf_token" value="0123456789abcdef0123456789abcdef">`
	stripped := stripDynamicNoise(body)
	if !strings.Contains(stripped, "Signed in as operator@example.test") {
		t.Errorf("stripped body lost content: %q", stripped)
	}
	if strings.Contains(stripped, "0123456789abcdef0123456789abcdef") {
		t.Errorf("stripped body kept the rotating token: %q", stripped)
	}
}
