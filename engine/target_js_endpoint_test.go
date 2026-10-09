package main

// Tests for the on-request JavaScript analysis the browser-driven crawler needs
// (`target_js_endpoint.go`).
//
// The tests run against a real HTTP server rather than a mocked transport,
// because the claim under test is that this path reads the same bytes the crawl
// reads and produces the same record. A mock would agree with whatever the
// handler does, which is the failure mode the project's own rules name: a test
// that cannot fail is not evidence.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// newTestServer is the smallest server the handler needs: a crawler client is
// built from its request transport, and the default transport is what a
// httptest server is reachable through.
func newTestServer() *server {
	return &server{}
}

// scriptRefs builds the reference list from bare URLs, which is the form a
// caller uses when it has one page for every script.
func scriptRefs(urls ...string) []targetScriptRef {
	refs := make([]targetScriptRef, 0, len(urls))
	for _, raw := range urls {
		refs = append(refs, targetScriptRef{URL: raw})
	}
	return refs
}

func newJSServer(t *testing.T, body string, contentType string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

// analysisBody is the same fixture both original tools were measured against.
const analysisBody = `// TODO: rotate the demo key
const cfg = { dbPassword: 'sup3r-s3cret-db-pass', slackToken: 'xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx' };
function paint(box, html) {
  box.innerHTML = html;
  document.write(html);
}
eval('render(' + location.hash.substring(1) + ')');
const who = 'security@corp-internal.test';
async function load(id) {
  return (await fetch('/api/v1/users/' + id, { method: 'GET' })).json();
}
`

// TestTargetJSAnalysisReadsARealScript is the central claim: a URL served as
// JavaScript comes back as the crawler's own page record, carrying endpoints,
// sinks and secrets. Reverting the handler to a stub makes `js` absent.
func TestTargetJSAnalysisReadsARealScript(t *testing.T) {
	server := newJSServer(t, analysisBody, "application/javascript")
	entries, _ := newTestServer().analyzeScriptURLs(t.Context(), scriptRefs(server.URL+"/assets/app.js"), 0)

	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Kind != "javascript" {
		t.Fatalf("kind = %q, want javascript", entry.Kind)
	}
	if entry.Status != 200 {
		t.Fatalf("status = %d, want 200", entry.Status)
	}
	if entry.Bytes != len(analysisBody) {
		t.Fatalf("bytes = %d, want %d", entry.Bytes, len(analysisBody))
	}
	if entry.JS == nil {
		t.Fatal("no analysis on the record for a URL served as JavaScript")
	}
	endpoints, _ := entry.JS["endpoints"].([]interface{})
	if len(endpoints) == 0 {
		t.Fatalf("no endpoints in the analysis: %v", entry.JS)
	}
	findings, _ := entry.JS["findings"].([]interface{})
	if len(findings) < 3 {
		t.Fatalf("findings = %d, want at least the two DOM writes and the eval", len(findings))
	}
	secrets, _ := entry.JS["secrets"].([]interface{})
	if len(secrets) < 2 {
		t.Fatalf("secrets = %d, want the password and the Slack token", len(secrets))
	}
	// The record must be the crawler's shape, not a new one: the same renderer
	// draws both modes, and a second shape would mean a second report.
	if _, ok := entry.JS["bytes"]; !ok {
		t.Fatalf("analysis record has no bytes field: %v", entry.JS)
	}
	if _, ok := entry.JS["ms"]; !ok {
		t.Fatalf("analysis record has no ms field: %v", entry.JS)
	}
	// Fetch time and analysis time are separate numbers: folding them together
	// would make a slow site and a heavy bundle indistinguishable on one row.
	if entry.Time < 0 {
		t.Fatalf("fetch time = %d, want a reported duration", entry.Time)
	}
	// The record travels as JSON, so both durations arrive as JSON numbers. They
	// live in different places on purpose: the fetch is the record's own `time`,
	// the parse is `js.ms`, and a record that carried only one of them would make
	// a slow site and a heavy bundle indistinguishable on the same row.
	if _, ok := entry.JS["time"]; ok {
		t.Fatalf("the analysis carries its own fetch time, so the two are not separable: %v", entry.JS)
	}
	analysisMillis, ok := entry.JS["ms"].(float64)
	if !ok {
		t.Fatalf("analysis time is not a json number: %#v", entry.JS["ms"])
	}
	if analysisMillis < 0 {
		t.Fatalf("analysis time = %v, want a duration", analysisMillis)
	}
}

// TestTargetJSAnalysisFoldsDuplicateURLs: a page loads the same bundle from
// several component bundles. Analysing it once per occurrence would pay the most
// expensive operation in the process for a file already read.
func TestTargetJSAnalysisFoldsDuplicateURLs(t *testing.T) {
	server := newJSServer(t, analysisBody, "application/javascript")
	url := server.URL + "/assets/app.js"
	entries, _ := newTestServer().analyzeScriptURLs(t.Context(), scriptRefs(url, url, " "+url), 0)
	if len(entries) != 1 {
		t.Fatalf("entries = %d for three references to one URL, want 1", len(entries))
	}
}

// TestTargetJSAnalysisUsesTheCrawlerPredicate pins both halves of the rule the
// static crawler already applies: a resource is a program when the crawl queued
// it as one, or when the server says it is. Both modes must answer identically
// for identical bytes, so this handler reuses the predicate instead of
// inventing a stricter one — a divergence here would mean the same `.js` file is
// analysed in one mode and ignored in the other, with nothing on the screen to
// explain why.
func TestTargetJSAnalysisUsesTheCrawlerPredicate(t *testing.T) {
	// Queued as a script, served as HTML: still analysed, and it has nothing in
	// it. Silence is the answer; a missing record would be a different claim.
	html := newJSServer(t, "<html>not a program</html>", "text/html; charset=utf-8")
	entries, _ := newTestServer().analyzeScriptURLs(t.Context(), scriptRefs(html.URL+"/assets/app.js"), 0)
	if len(entries) != 1 || entries[0].JS == nil {
		t.Fatalf("a URL queued as a script was not analysed: %+v", entries)
	}
	findings, _ := entries[0].JS["findings"].([]interface{})
	if len(findings) != 0 {
		t.Fatalf("an HTML page produced findings: %v", findings)
	}

	// Not queued as a script, served as a program: the content type decides, and
	// a server that ships a program from an extensionless path is common.
	script := newJSServer(t, analysisBody, "application/javascript")
	entries, _ = newTestServer().analyzeScriptURLs(t.Context(), scriptRefs(script.URL+"/bundle"), 0)
	if len(entries) != 1 || entries[0].JS == nil {
		t.Fatalf("a program served from an extensionless path was not analysed: %+v", entries)
	}
	if entries[0].Kind != "page" {
		t.Fatalf("kind = %q, want the URL's own classification", entries[0].Kind)
	}

	// Neither: a JSON document is not a program and must stay an answer.
	config := newJSServer(t, `{"key":"value"}`, "application/json")
	entries, _ = newTestServer().analyzeScriptURLs(t.Context(), scriptRefs(config.URL+"/api/config.json"), 0)
	if len(entries) != 1 || entries[0].JS != nil {
		t.Fatalf("a JSON document was analysed as a program: %+v", entries)
	}
}

// TestTargetJSAnalysisDoesNotLoseTheRestOnOneFailure: a bundle on a host that
// has gone away must not blank the analysis of the ones that loaded.
func TestTargetJSAnalysisDoesNotLoseTheRestOnOneFailure(t *testing.T) {
	server := newJSServer(t, analysisBody, "application/javascript")
	entries, _ := newTestServer().analyzeScriptURLs(t.Context(), scriptRefs(
		"http://127.0.0.1:1/gone.js", server.URL+"/app.js"), 0)
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2 (the failed one is an answer too)", len(entries))
	}
	if entries[0].Error == "" {
		t.Fatal("an unreachable host produced no error on its entry")
	}
	if entries[1].JS == nil {
		t.Fatal("one failure took the next analysis with it")
	}
}

// TestTargetJSAnalysisRefusesNonHTTPURLs: the list arrives from JSON, and a
// `file://` or `javascript:` entry is a question about the protocol, not about a
// program. The reason is asserted exactly, because the refusal must name the
// protocol rather than pass a `file://` URL to the transport and let the operator
// read "unsupported protocol scheme" as a network problem with the target.
func TestTargetJSAnalysisRefusesNonHTTPURLs(t *testing.T) {
	entries, _ := newTestServer().analyzeScriptURLs(t.Context(), scriptRefs(
		"file:///etc/passwd", "javascript:alert(1)", "data:text/javascript,1"), 0)
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want every URL answered", len(entries))
	}
	for _, entry := range entries {
		if entry.JS != nil {
			t.Fatalf("%s was analysed: %+v", entry.URL, entry)
		}
		if entry.Error != "not an http(s) url" {
			t.Fatalf("%s was refused as %q, want the protocol named", entry.URL, entry.Error)
		}
	}
}

// TestTargetJSAnalysisClassifiesBySuffixAndContentType pins the classification
// the URL carries before anything is fetched, including the case the upstream
// crawler queues by path rather than by extension.
func TestTargetJSAnalysisClassifiesBySuffixAndContentType(t *testing.T) {
	cases := map[string]string{
		"https://shop.example/a.js":   "javascript",
		"https://shop.example/a.mjs":  "javascript",
		"https://shop.example/a.cjs":  "javascript",
		"https://shop.example/a.json": "json",
		"https://shop.example/a.map":  "json",
		"https://shop.example/bundle": "page",
	}
	for raw, want := range cases {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if got := classifyScriptURL(parsed); got != want {
			t.Fatalf("classifyScriptURL(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestTargetJSAnalysisHandlerRejectsNonPOST states the contract of the route
// itself: it is a POST of URLs and answers nothing else.
func TestTargetJSAnalysisHandlerRejectsNonPOST(t *testing.T) {
	server := newTestServer()
	recorder := httptest.NewRecorder()
	server.targetJSAnalysisHandler(recorder, httptest.NewRequest(http.MethodGet, "/proxy/target-js", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET returned %d, want 405", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/proxy/target-js", strings.NewReader(`{"urls":[]}`))
	server.targetJSAnalysisHandler(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST returned %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	payload := map[string]interface{}{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("answer is not json: %v", err)
	}
	if _, ok := payload["results"]; !ok {
		t.Fatalf("answer has no results key: %s", recorder.Body.String())
	}
}

// TestTargetJSAnalysisSendsThePageAsReferer: a browser-driven crawl knows which
// page loaded which bundle, and some CDNs answer a bundle request that claims to
// come from nowhere differently from the same request made by the site. The
// object form exists so that difference does not decide whether one mode can read
// a bundle the other mode reads.
func TestTargetJSAnalysisSendsThePageAsReferer(t *testing.T) {
	// The pairs are keyed by the script's own path rather than collected in a
	// list. Reads run concurrently, so the order the server is asked in is not a
	// property of anything: what is guaranteed is the order of the *answer*, and
	// this test is about which referer travelled with which request.
	seen := map[string]string{}
	var lock sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lock.Lock()
		seen[r.URL.Path] = r.Header.Get("Referer")
		lock.Unlock()
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(analysisBody))
	}))
	t.Cleanup(server.Close)

	server_refs := []targetScriptRef{
		{URL: server.URL + "/app.js", Referer: "https://shop.example/cart"},
		{URL: server.URL + "/vendor.js"},
	}
	entries, _ := newTestServer().analyzeScriptURLs(t.Context(), server_refs, 0)
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if len(seen) != 2 {
		t.Fatalf("the server saw %d distinct scripts, want 2: %v", len(seen), seen)
	}
	if seen["/app.js"] != "https://shop.example/cart" {
		t.Errorf("referer of /app.js = %q, want the page that loaded it", seen["/app.js"])
	}
	if seen["/vendor.js"] != "" {
		t.Errorf("a script with no page invented a referer: %q", seen["/vendor.js"])
	}
}

// TestTargetJSAnalysisNamesDroppedEntries: a list that quietly loses an entry is
// a list whose length the analyst cannot trust, so the answer says so instead of
// returning a shorter one without comment.
func TestTargetJSAnalysisNamesDroppedEntries(t *testing.T) {
	refs, rejected := normalizeScriptRefs([]json.RawMessage{
		json.RawMessage(`"https://shop.example/a.js"`),
		json.RawMessage(`{"url":"https://shop.example/b.js","referer":"https://shop.example/"}`),
		json.RawMessage(`{"referer":"https://shop.example/"}`),
		json.RawMessage(`42`),
	}, "https://fallback.example/")
	if rejected == "" {
		t.Fatal("two nameless entries were dropped without a word")
	}
	if len(refs) != 2 {
		t.Fatalf("refs = %d, want the two that named a url", len(refs))
	}
	if refs[0].Referer != "https://fallback.example/" {
		t.Fatalf("a bare url did not take the fallback referer: %q", refs[0].Referer)
	}
	if refs[1].Referer != "https://shop.example/" {
		t.Fatalf("the object form lost its own referer: %q", refs[1].Referer)
	}
}

// TestTargetJSAnalysisObjectFormCarriesItsOwnReferer: the fallback applies to a
// bare string only. An object that names a page keeps it, including when the
// fallback names a different page.
func TestTargetJSAnalysisObjectFormCarriesItsOwnReferer(t *testing.T) {
	refs, rejected := normalizeScriptRefs([]json.RawMessage{
		json.RawMessage(`{"url":"https://shop.example/a.js"}`),
	}, "https://fallback.example/")
	if rejected != "" {
		t.Fatalf("a valid object was rejected: %s", rejected)
	}
	if refs[0].Referer != "https://fallback.example/" {
		t.Fatalf("an object with no referer did not take the fallback: %q", refs[0].Referer)
	}
}
