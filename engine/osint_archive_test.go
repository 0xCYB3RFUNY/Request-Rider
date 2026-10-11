package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// archiveFixture is a local stand-in for the public archive index, so the
// transform behaviour is asserted without depending on a third party.
type archiveFixture struct {
	// bodies maps a request path onto the raw response body.
	bodies map[string]string
	// statuses maps a request path onto a non-200 status code.
	statuses map[string]int
	// headers maps a request path onto the response headers it carries.
	headers map[string]map[string]string
	// requests records every request path, in order.
	requests []string
	// agents records the User-Agent of every request.
	agents []string
}

func (fixture *archiveFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fixture.requests = append(fixture.requests, r.URL.Path)
	fixture.agents = append(fixture.agents, r.Header.Get("User-Agent"))
	for name, value := range fixture.headers[r.URL.Path] {
		w.Header().Set(name, value)
	}
	if status, ok := fixture.statuses[r.URL.Path]; ok {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, "<html><title>upstream failure</title></html>")
		return
	}
	body, ok := fixture.bodies[r.URL.Path]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, body)
}

func newArchiveFixture(t *testing.T) (*server, *archiveFixture, func()) {
	t.Helper()
	fixture := &archiveFixture{
		bodies:   map[string]string{},
		statuses: map[string]int{},
		headers:  map[string]map[string]string{},
	}
	httpServer := httptest.NewServer(fixture)
	engine := &server{transport: &http.Transport{}, archiveIndexBase: httpServer.URL}
	// The chain is replaced rather than extended so a test transform never
	// reaches the public network: the crawl collections the production chain
	// discovers would be a live request from a unit test.
	engine.archiveIndexList = func(ctx context.Context, prefix string) ([]archiveEndpoint, error) {
		return archiveEndpoints(engine.archiveIndexBase, prefix), nil
	}
	return engine, fixture, httpServer.Close
}

// The archives are URL-keyed, so the query follows the shape of the input: a
// bare domain is asked host-wide, a URL is asked for its own path prefix. Both
// resolve to the same host, and the narrowing is reported rather than applied
// silently — a result that claimed host-wide coverage from a path query would
// be worth more than it is.
func TestArchiveQueryTargetFollowsTheInputShape(t *testing.T) {
	cases := []struct {
		name       string
		value      string
		wantHost   string
		wantPrefix string
		wantNarrow bool
	}{
		{"bare domain", "example.test", "example.test", "example.test/*", false},
		{"trailing dot", "example.test.", "example.test", "example.test/*", false},
		{"host with port", "example.test:8443", "example.test", "example.test/*", false},
		{"absolute url", "https://example.test/a/b", "example.test", "example.test/a/b/*", true},
		{"url with root path", "https://example.test/", "example.test", "example.test/*", false},
		{"url with query", "https://example.test/search?q=1", "example.test", "example.test/search/*", true},
		{"scheme relative", "//example.test/api", "example.test", "example.test/api/*", true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			host, prefix, err := archiveQueryTarget(testCase.value)
			if err != nil {
				t.Fatalf("archiveQueryTarget(%q) error: %v", testCase.value, err)
			}
			if host != testCase.wantHost {
				t.Fatalf("host = %q, want %q", host, testCase.wantHost)
			}
			if prefix != testCase.wantPrefix {
				t.Fatalf("prefix = %q, want %q", prefix, testCase.wantPrefix)
			}
			if narrowed := prefix != host+"/*"; narrowed != testCase.wantNarrow {
				t.Fatalf("narrowed = %v, want %v", narrowed, testCase.wantNarrow)
			}
		})
	}
}

func TestArchiveQueryTargetRejectsUnusableInput(t *testing.T) {
	for _, value := range []string{"", "   ", "http://", "not a url at all", "ftp://example.test/x"} {
		if _, _, err := archiveQueryTarget(value); err == nil {
			t.Fatalf("archiveQueryTarget(%q) accepted an input it cannot query", value)
		}
	}
}

// A narrowed query has to be visible in the result. A URL run that reported
// nothing about its prefix would read as host-wide coverage it never asked for,
// which is the kind of quiet overstatement that makes a result worth more than
// it is.
func TestWaybackRunStatesThePrefixItQueried(t *testing.T) {
	engine, fixture, closeFixture := newArchiveFixture(t)
	defer closeFixture()
	// The fixture answers so the run reaches the end; the assertion is about what
	// the result says about its own query, not about the rows that came back.
	fixture.bodies["/cdx/search/cdx"] = `[["original"],["https://example.test/api/v1/users"]]`

	result := osintTransformResult{}
	input := osintTransformInput{Value: "https://example.test/api/v1", ConfirmNetwork: true}
	if err := engine.runWaybackURLsWithCollector(context.Background(), &result, input, nil); err != nil {
		t.Fatalf("runWaybackURLsWithCollector: %v", err)
	}
	if result.Metadata["wayback_prefix"] != "example.test/api/v1/*" {
		t.Fatalf("prefix reported = %v", result.Metadata["wayback_prefix"])
	}
	if result.Metadata["wayback_host"] != "example.test" {
		t.Fatalf("host reported = %v", result.Metadata["wayback_host"])
	}
	if result.Metadata["wayback_input"] != input.Value {
		t.Fatalf("input reported = %v", result.Metadata["wayback_input"])
	}
	// The narrowing is stated in words too, because metadata is read by machines
	// and the warning is what the analyst reads.
	stated := false
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "example.test/api/v1/*") {
			stated = true
		}
	}
	if !stated {
		t.Fatalf("the narrowed prefix is not stated in the warnings: %#v", result.Warnings)
	}
	// A domain run stays exactly as it was: host-wide, with nothing to declare.
	plain := osintTransformResult{}
	if err := engine.runWaybackURLsWithCollector(context.Background(), &plain,
		osintTransformInput{Value: "example.test", ConfirmNetwork: true}, nil); err != nil {
		t.Fatalf("domain run: %v", err)
	}
	if plain.Metadata["wayback_prefix"] != "example.test/*" {
		t.Fatalf("domain prefix = %v", plain.Metadata["wayback_prefix"])
	}
	for _, warning := range plain.Warnings {
		if strings.Contains(warning, "narrowed") {
			t.Fatalf("a domain run must not claim narrowing: %q", warning)
		}
	}
}

func TestArchiveEndpointsUseTheConfiguredIndexBase(t *testing.T) {
	endpoints := archiveEndpoints("", "yandex.ru/*")
	if len(endpoints) != 2 {
		t.Fatalf("endpoints = %#v", endpoints)
	}
	if !strings.HasPrefix(endpoints[0].query, publicArchiveIndex+"/cdx/search/cdx?url=") {
		t.Fatalf("cdx query = %q", endpoints[0].query)
	}
	if !strings.HasPrefix(endpoints[1].query, publicArchiveIndex+"/web/timemap/json?url=") {
		t.Fatalf("timemap query = %q", endpoints[1].query)
	}
	// The collapsed CDX index is preferred over the per-capture timemap index.
	if !strings.Contains(endpoints[0].query, "collapse=urlkey") {
		t.Fatalf("cdx query lost the urlkey collapse: %q", endpoints[0].query)
	}
	// The field list is checked by field, not by a literal substring: the query
	// asks for more than it used to, and a check for "fl=original" would then
	// fail on a query that still requests it.
	fields := archiveEndpointFields(endpoints[0].query)
	for _, field := range []string{"original", "timestamp", "filename", "offset", "length"} {
		if !fields[field] {
			t.Fatalf("cdx query does not ask for the %q field: %q", field, endpoints[0].query)
		}
	}
	local := archiveEndpoints("http://127.0.0.1:9/", "yandex.ru/*")
	if !strings.HasPrefix(local[0].query, "http://127.0.0.1:9/cdx/search/cdx?") {
		t.Fatalf("configured base = %q", local[0].query)
	}
}

func TestArchiveURLColumnAndTargetValidation(t *testing.T) {
	if column := archiveURLColumn([]string{"urlkey", "timestamp", "original"}); column != 2 {
		t.Fatalf("timemap original column = %d", column)
	}
	if column := archiveURLColumn([]string{"original"}); column != 0 {
		t.Fatalf("cdx original column = %d", column)
	}
	if column := archiveURLColumn([]string{"urlkey", "timestamp"}); column != -1 {
		t.Fatalf("missing original column = %d", column)
	}
	if target, ok := archiveURLTarget(" https://Yandex.RU/a?b=1#frag "); !ok || target != "https://yandex.ru/a" {
		t.Fatalf("target = %q ok = %v", target, ok)
	}
	for _, candidate := range []string{"", "original", "mailto:analyst@yandex.ru", "ftp://yandex.ru/f", "/relative/path", "//yandex.ru/a"} {
		if _, ok := archiveURLTarget(candidate); ok {
			t.Fatalf("candidate %q was accepted as an archived URL", candidate)
		}
	}
	// A bare host is a real captured resource and normalizes to the root path.
	if target, ok := archiveURLTarget("https://yandex.ru"); !ok || target != "https://yandex.ru/" {
		t.Fatalf("bare host = %q ok = %v", target, ok)
	}
}

// The public archive stores captured credential URLs and fragment variants.
// Neither may become a stored identity, and a default port must not split one
// resource into two graph identities.
func TestArchiveURLTargetDropsCredentialsAndFragments(t *testing.T) {
	cases := map[string]string{
		"https://user@yandex.ru/":            "https://yandex.ru/",
		"https://user:secret@yandex.ru/a":    "https://yandex.ru/a",
		"http://yakovenko.tosha@yandex.ru/":  "http://yandex.ru/",
		"http://www.yandex.ru:80/#x7AE69DD2": "http://www.yandex.ru/",
		"http://Yandex.ru:80/a?b=1#c":        "http://yandex.ru/a",
		"https://yandex.ru:443/":             "https://yandex.ru/",
		"https://yandex.ru:8443/":            "https://yandex.ru:8443/",
		"http://[2001:db8::1]:80/":           "http://[2001:db8::1]/",
	}
	for candidate, want := range cases {
		target, ok := archiveURLTarget(candidate)
		if !ok || target != want {
			t.Fatalf("archiveURLTarget(%q) = %q ok = %v, want %q", candidate, target, ok, want)
		}
		if strings.Contains(target, "@") {
			t.Fatalf("credential survived canonicalization: %q", target)
		}
	}
}

// A hostile archive row must be dropped rather than fail the transform, and
// must never be able to widen the identity into another host.
func TestArchiveURLTargetRejectsUnstorableHosts(t *testing.T) {
	for _, candidate := range []string{
		"https://-yandex.ru/",
		"https://yandex-.ru/",
		"https://yandex..ru/",
		"https://yandex.ru./../evil",
		"https://xn--/",
		"https://yandex.ru:99999/",
		"https://[2001:db8::zz]/",
	} {
		if target, ok := archiveURLTarget(candidate); ok {
			t.Fatalf("archiveURLTarget(%q) = %q, want rejection", candidate, target)
		}
	}
}

func TestStreamArchiveIndexReadsCDXLayout(t *testing.T) {
	engine, fixture, closeFixture := newArchiveFixture(t)
	defer closeFixture()
	fixture.bodies["/cdx/search/cdx"] = `[["original"],["https://yandex.ru/a"],["https://yandex.ru/b"]]`

	urls := []string{}
	index, err := streamArchiveIndex(context.Background(), engine.requestHTTPClient(), archiveEndpoints(engine.archiveIndexBase, "yandex.ru/*")[0], func(candidate archiveCapture) {
		if target, ok := archiveURLTarget(candidate.url); ok {
			urls = append(urls, target)
		}
	})
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if !index.complete || index.truncated() || index.rows != 2 || len(urls) != 2 || urls[1] != "https://yandex.ru/b" {
		t.Fatalf("index = %#v urls = %#v", index, urls)
	}
	// The archive rejects default HTTP clients, so a descriptive User-Agent
	// is part of the adapter contract.
	if len(fixture.agents) != 1 || fixture.agents[0] != "RequestRider-OSINT-Transform/1.0" {
		t.Fatalf("user agents = %#v", fixture.agents)
	}
}

func TestStreamArchiveIndexKeepsRowsBeforeTruncatedTail(t *testing.T) {
	// A large host prefix regularly ends mid-array. The rows that already
	// arrived are real data and must not be discarded.
	engine, fixture, closeFixture := newArchiveFixture(t)
	defer closeFixture()
	fixture.bodies["/web/timemap/json"] = `[["urlkey","timestamp","original","mimetype","statuscode"],` +
		`["ru,yandex.ru)/","20240101000000","https://yandex.ru/a","text/html","200"],` +
		`["ru,yandex.ru)/b","20240101000001","https://yandex.ru/b","text/html","200"],` +
		`["ru,yandex.ru)/c","2024010`

	urls := []string{}
	index, err := streamArchiveIndex(context.Background(), engine.requestHTTPClient(), archiveEndpoints(engine.archiveIndexBase, "yandex.ru/*")[1], func(candidate archiveCapture) {
		if target, ok := archiveURLTarget(candidate.url); ok {
			urls = append(urls, target)
		}
	})
	if err != nil {
		t.Fatalf("a truncated stream must stay usable: %v", err)
	}
	if index.complete || !index.truncated() || index.rows != 2 || len(urls) != 2 {
		t.Fatalf("index = %#v urls = %#v", index, urls)
	}
}

func TestStreamArchiveIndexRejectsUnusableAnswers(t *testing.T) {
	engine, fixture, closeFixture := newArchiveFixture(t)
	defer closeFixture()
	fixture.bodies["/cdx/search/cdx"] = `<html>temporarily offline</html>`
	fixture.bodies["/web/timemap/json"] = `[["urlkey","timestamp"],["a","b"]]`
	fixture.statuses["/empty"] = http.StatusServiceUnavailable

	for name, endpoint := range map[string]archiveEndpoint{
		"html page":  {name: "html", query: engine.archiveIndexBase + "/cdx/search/cdx"},
		"no column":  {name: "header", query: engine.archiveIndexBase + "/web/timemap/json"},
		"http error": {name: "offline", query: engine.archiveIndexBase + "/empty"},
	} {
		urls := []string{}
		index, err := streamArchiveIndex(context.Background(), engine.requestHTTPClient(), endpoint, func(candidate archiveCapture) {
			urls = append(urls, candidate.url)
		})
		if err == nil {
			t.Fatalf("%s: an unusable answer was accepted", name)
		}
		if index.rows != 0 || len(urls) != 0 {
			t.Fatalf("%s: an unusable answer produced rows: %#v", name, index)
		}
	}
}

// The archive documents Retry-After on 429 as the cue to back off, so a
// rate-limited answer has to say how long it asked for.
func TestArchiveRateLimitExplainsItself(t *testing.T) {
	engine, fixture, closeFixture := newArchiveFixture(t)
	defer closeFixture()
	fixture.statuses["/cdx/search/cdx"] = http.StatusTooManyRequests
	fixture.headers["/cdx/search/cdx"] = map[string]string{"Retry-After": "37"}

	_, err := streamArchiveIndex(context.Background(), engine.requestHTTPClient(), archiveEndpoints(engine.archiveIndexBase, "yandex.ru/*")[0], func(archiveCapture) {})
	if err == nil {
		t.Fatal("a rate limited answer was accepted")
	}
	if !strings.Contains(err.Error(), "HTTP 429") || !strings.Contains(err.Error(), "retry after 37s") {
		t.Fatalf("error %q does not explain the rate limit", err)
	}
}

func TestRetryAfterNoteOnlyReportsAUsableWait(t *testing.T) {
	header := http.Header{}
	if note := retryAfterNote(header); note != "" {
		t.Fatalf("absent header = %q", note)
	}
	header.Set("Retry-After", "")
	if note := retryAfterNote(header); note != "" {
		t.Fatalf("empty header = %q", note)
	}
	header.Set("Retry-After", "-5")
	if note := retryAfterNote(header); note != "" {
		t.Fatalf("negative wait = %q", note)
	}
	header.Set("Retry-After", "Wed, 21 Oct 2026 07:28:00 GMT")
	if note := retryAfterNote(header); !strings.Contains(note, "Wed, 21 Oct 2026") {
		t.Fatalf("date wait = %q", note)
	}
}

func TestStreamJSONArrayReportsTruncatedAndNonArrayBodies(t *testing.T) {
	visited := 0
	err := streamJSONArray(strings.NewReader(`[{"a":1},{"a":2},{"a":`), func(json.RawMessage) error {
		visited++
		return nil
	})
	if err == nil {
		t.Fatal("a truncated array was accepted")
	}
	if visited != 2 {
		t.Fatalf("visited %d elements before the truncation", visited)
	}
	if err := streamJSONArray(strings.NewReader(`{"a":1}`), func(json.RawMessage) error { return nil }); err == nil {
		t.Fatal("a non-array response was accepted")
	}
	completed := 0
	if err := streamJSONArray(strings.NewReader(`[1,2,3]`), func(json.RawMessage) error {
		completed++
		return nil
	}); err != nil {
		t.Fatalf("complete array: %v", err)
	}
	if completed != 3 {
		t.Fatalf("completed elements = %d", completed)
	}
}

func TestRunWaybackURLsFallsBackToTheSecondIndex(t *testing.T) {
	engine, fixture, closeFixture := newArchiveFixture(t)
	defer closeFixture()
	fixture.statuses["/cdx/search/cdx"] = http.StatusServiceUnavailable
	fixture.bodies["/web/timemap/json"] = `[["urlkey","timestamp","original"],["ru,yandex.ru)/","20240101","https://yandex.ru/a"]]`

	result, err := engine.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "wayback_urls", Value: "Yandex.RU", ConfirmNetwork: true,
	})
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	// The host itself is emitted so the observed_at relation has both
	// endpoints in the graph.
	if len(result.Entities) != 2 || result.Entities[0].Identity != "yandex.ru" || result.Entities[1].Identity != "https://yandex.ru/a" {
		t.Fatalf("entities = %#v", result.Entities)
	}
	if len(result.Relations) != 1 || result.Relations[0].Type != "observed_at" || result.Relations[0].Target != "yandex.ru" {
		t.Fatalf("relations = %#v", result.Relations)
	}
	if len(fixture.requests) != 2 || fixture.requests[0] != "/cdx/search/cdx" || fixture.requests[1] != "/web/timemap/json" {
		t.Fatalf("requests = %#v", fixture.requests)
	}
	if result.Metadata["archive_index"] != "timemap" || result.Metadata["archive_urls"] != 1 {
		t.Fatalf("metadata = %#v", result.Metadata)
	}
	if result.Metadata["archive_stream_complete"] != true {
		t.Fatalf("stream completeness = %#v", result.Metadata["archive_stream_complete"])
	}
	if result.Entities[1].Provenance["archive_index"] != "timemap" {
		t.Fatalf("provenance = %#v", result.Entities[1].Provenance)
	}
}

func TestRunWaybackURLsDeduplicatesRepeatedCaptures(t *testing.T) {
	engine, fixture, closeFixture := newArchiveFixture(t)
	defer closeFixture()
	fixture.statuses["/cdx/search/cdx"] = http.StatusTooManyRequests
	// The timemap index keeps one row per capture of the same URL.
	fixture.bodies["/web/timemap/json"] = `[["urlkey","timestamp","original"],
		["ru,yandex.ru)/","20240101","https://yandex.ru/a"],
		["ru,yandex.ru)/","20240202","https://yandex.ru/a"],
		["ru,yandex.ru)/b","20240303","http://yandex.ru/b"]]`

	result, err := engine.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "wayback_urls", Value: "yandex.ru", ConfirmNetwork: true,
	})
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	// Two archived URLs plus the host entity itself.
	if len(result.Entities) != 3 || len(result.Relations) != 2 {
		t.Fatalf("entities = %#v relations = %#v", result.Entities, result.Relations)
	}
	if result.Metadata["archive_rows"] != 3 || result.Metadata["archive_urls"] != 2 {
		t.Fatalf("metadata = %#v", result.Metadata)
	}
}

func TestRunWaybackURLsReportsEveryFailedIndex(t *testing.T) {
	engine, fixture, closeFixture := newArchiveFixture(t)
	defer closeFixture()
	fixture.statuses["/cdx/search/cdx"] = http.StatusTooManyRequests
	fixture.statuses["/web/timemap/json"] = http.StatusServiceUnavailable

	_, err := engine.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "wayback_urls", Value: "yandex.ru", ConfirmNetwork: true,
	})
	if err == nil {
		t.Fatal("expected an explicit lookup failure")
	}
	message := err.Error()
	for _, fragment := range []string{"WAYBACK_LOOKUP_FAILED", "cdx index", "HTTP 429", "timemap index", "HTTP 503"} {
		if !strings.Contains(message, fragment) {
			t.Fatalf("error %q does not report %q", message, fragment)
		}
	}
}

func TestRunWaybackURLsReportsPartialIndex(t *testing.T) {
	engine, fixture, closeFixture := newArchiveFixture(t)
	defer closeFixture()
	fixture.statuses["/cdx/search/cdx"] = http.StatusBadGateway
	fixture.bodies["/web/timemap/json"] = `[["original"],["https://yandex.ru/a"],["https://yandex.ru/b"],["https://yan`

	result, err := engine.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "wayback_urls", Value: "yandex.ru", ConfirmNetwork: true,
	})
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if len(result.Entities) != 3 {
		t.Fatalf("entities = %#v", result.Entities)
	}
	// The partial stream is reported, and so is the index the chain walked past:
	// a result that dropped the collapsed index has to say so, because the two
	// indexes do not cover the same history.
	joined := strings.Join(result.Warnings, " | ")
	if !strings.Contains(joined, "ended early after 2 rows") {
		t.Fatalf("warnings = %#v, want the truncated stream reported", result.Warnings)
	}
	if !strings.Contains(joined, "cdx index: archive returned HTTP 502") {
		t.Fatalf("warnings = %#v, want the index that was skipped reported", result.Warnings)
	}
	if result.Metadata["archive_stream_complete"] != false {
		t.Fatalf("metadata = %#v", result.Metadata)
	}
	// A partial index still carries real coverage, so no second attempt is made.
	if len(fixture.requests) != 2 {
		t.Fatalf("requests = %#v", fixture.requests)
	}
}

func TestRunWaybackURLsReportsEmptyIndexWithoutFallback(t *testing.T) {
	engine, fixture, closeFixture := newArchiveFixture(t)
	defer closeFixture()
	fixture.bodies["/cdx/search/cdx"] = `[]`

	result, err := engine.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "wayback_urls", Value: "yandex.ru", ConfirmNetwork: true,
	})
	if err != nil {
		t.Fatalf("an empty index is not a failure: %v", err)
	}
	if len(result.Entities) != 1 || result.Entities[0].Identity != "yandex.ru" {
		t.Fatalf("entities = %#v", result.Entities)
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "holds no captures for yandex.ru") {
		t.Fatalf("warnings = %#v", result.Warnings)
	}
	if len(fixture.requests) != 1 {
		t.Fatalf("an answering index triggered a fallback: requests = %#v", fixture.requests)
	}
}

// TestArchiveChainSpansMoreThanOneHost proves the chain is a chain. The two
// Internet Archive indexes behind one hostname share that host's rate limit, so
// a chain built from a single host has no fallback at all for the failure that
// actually happens: the host answering 429 to every client from one egress
// address. A second, independently operated archive is the only thing that makes
// the fallback real.
func TestArchiveChainSpansMoreThanOneHost(t *testing.T) {
	hosts := map[string]bool{}
	engine := &server{transport: &http.Transport{}}
	engine.archiveIndexList = nil
	// The production chain is asserted on its shape rather than by calling it,
	// because building it asks the crawl index which collections exist.
	chain := append(
		archiveEndpoints("", "example.com"),
		archiveEndpoint{name: "crawl CC-MAIN-2026-39", query: "https://index.commoncrawl.org/CC-MAIN-2026-39-index?url=example.com%2F%2A&output=json", layout: archiveLayoutObjects, field: "url", continueOnEmpty: true},
	)
	for _, endpoint := range chain {
		parsed, err := url.Parse(endpoint.query)
		if err != nil {
			t.Fatalf("endpoint %q is not a URL: %v", endpoint.name, err)
		}
		hosts[parsed.Host] = true
	}
	if len(hosts) < 2 {
		t.Fatalf("chain = %v, want indexes on at least two hosts", hosts)
	}
	if hosts["web.archive.org"] != true {
		t.Fatalf("the archive the transform is named after is missing: %v", hosts)
	}
}

// TestCrawlIndexEndpointsComeFromThePublishedList proves the crawl collections
// are taken from the index that publishes them rather than guessed. A hard-coded
// collection id rots into a collection that no longer exists, and a lookup
// against a collection that is gone answers 404 forever.
func TestCrawlIndexEndpointsComeFromThePublishedList(t *testing.T) {
	published := `[{"id":"CC-MAIN-2026-39","cdx-api":"https://index.commoncrawl.org/CC-MAIN-2026-39-index"},
	{"id":"CC-MAIN-2026-34","cdx-api":"https://index.commoncrawl.org/CC-MAIN-2026-34-index"},
	{"id":"broken","cdx-api":""}]`
	fixture := &archiveFixture{bodies: map[string]string{"/collinfo.json": published}}
	httpServer := httptest.NewServer(fixture)
	defer httpServer.Close()
	engine := &server{transport: &http.Transport{}, crawlIndexBase: httpServer.URL}

	endpoints, err := engine.crawlIndexEndpoints(context.Background(), engine.requestHTTPClient(), "example.com/*")
	if err != nil {
		t.Fatalf("collections: %v", err)
	}
	if len(endpoints) != 2 {
		t.Fatalf("endpoints = %d, want one per usable collection", len(endpoints))
	}
	// The newest collection is asked first: a host crawled last month is answered
	// by last month's collection, and the newest is what "recently archived" means.
	if endpoints[0].name != "crawl CC-MAIN-2026-39" || endpoints[1].name != "crawl CC-MAIN-2026-34" {
		t.Fatalf("order = %q, %q, want newest first", endpoints[0].name, endpoints[1].name)
	}
	first := endpoints[0]
	if first.layout != archiveLayoutObjects || first.field != "url" {
		t.Fatalf("crawl layout = %q/%q, want the object layout read from \"url\"", first.layout, first.field)
	}
	if !strings.Contains(first.query, "url=example.com%2F%2A") {
		t.Fatalf("crawl query = %q, want the host prefix escaped", first.query)
	}
	// A collection that never crawled the host is not an answer, so the chain
	// must keep looking; the archive indexes keep their existing meaning.
	if !first.continueOnEmpty {
		t.Fatal("an empty crawl collection was treated as an answer")
	}
	for _, endpoint := range archiveEndpoints("", "example.com/*") {
		if endpoint.continueOnEmpty {
			t.Fatalf("%q is an archive: an empty answer from it is an answer", endpoint.name)
		}
	}
}

// TestCrawlIndexFailureShortensTheChainInsteadOfFailing proves an unreachable
// crawl index does not take the archive chain down with it: every index that did
// answer is still used, and the analyst is told which part was unavailable.
func TestCrawlIndexFailureShortensTheChainInsteadOfFailing(t *testing.T) {
	fixture := &archiveFixture{
		bodies:   map[string]string{},
		statuses: map[string]int{"/collinfo.json": http.StatusInternalServerError},
	}
	httpServer := httptest.NewServer(fixture)
	defer httpServer.Close()
	engine := &server{transport: &http.Transport{}, archiveIndexBase: "https://archive.invalid", crawlIndexBase: httpServer.URL}

	chain, note := engine.archiveChain(context.Background(), engine.requestHTTPClient(), "example.com/*")
	if note == "" {
		t.Fatal("an unreachable crawl index was not reported")
	}
	if len(chain) != 2 {
		t.Fatalf("chain = %d indexes, want the archive indexes kept", len(chain))
	}
	for _, endpoint := range chain {
		if !strings.HasPrefix(endpoint.query, "https://archive.invalid/") {
			t.Fatalf("chain lost the configured archive base: %q", endpoint.query)
		}
	}
}

// TestStreamArchiveIndexReadsTheObjectLayout proves the crawl index's JSON Lines
// answer is consumed the same way the array layouts are: row by row, as it
// arrives, because a host with a long capture history produces a long response.
func TestStreamArchiveIndexReadsTheObjectLayout(t *testing.T) {
	body := strings.Join([]string{
		`{"urlkey":"com,example)/","timestamp":"20260904131850","url":"https://example.com/","status":"200"}`,
		`{"urlkey":"com,example)/","timestamp":"20260904132130","url":"https://example.com/a","status":"200"}`,
		// A line that is not an object must not end the read: one malformed row
		// cannot cost the rows that follow it.
		`not json at all`,
		`{"timestamp":"20260904132200"}`,
		`{"url":"   "}`,
		`{"url":"https://example.com/b"}`,
		``,
	}, "\n")
	fixture := &archiveFixture{bodies: map[string]string{"/index": body}}
	httpServer := httptest.NewServer(fixture)
	defer httpServer.Close()
	endpoint := archiveEndpoint{
		name:   "crawl CC-MAIN-2026-39",
		query:  httpServer.URL + "/index",
		layout: archiveLayoutObjects,
		field:  "url",
	}
	engine := &server{transport: &http.Transport{}}

	var got []string
	index, err := streamArchiveIndex(context.Background(), engine.requestHTTPClient(), endpoint, func(value archiveCapture) {
		got = append(got, value.url)
	})
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	want := []string{"https://example.com/", "https://example.com/a", "https://example.com/b"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("rows = %v, want %v", got, want)
	}
	if index.rows != len(want) {
		t.Fatalf("index rows = %d, want %d", index.rows, len(want))
	}
	if !index.complete {
		t.Fatal("a fully read object stream was reported as truncated")
	}
}

// TestStreamArchiveIndexRejectsAnObjectStreamWithoutTheURLField proves a
// response that carries no archived URL is not mistaken for coverage.
func TestStreamArchiveIndexRejectsAnObjectStreamWithoutTheURLField(t *testing.T) {
	fixture := &archiveFixture{bodies: map[string]string{"/index": `{"timestamp":"2026"}` + "\n"}}
	httpServer := httptest.NewServer(fixture)
	defer httpServer.Close()
	endpoint := archiveEndpoint{name: "crawl", query: httpServer.URL + "/index", layout: archiveLayoutObjects, field: "url"}
	engine := &server{transport: &http.Transport{}}

	index, err := streamArchiveIndex(context.Background(), engine.requestHTTPClient(), endpoint, func(archiveCapture) {})
	if err == nil {
		t.Fatalf("an object stream without the url field was accepted: %+v", index)
	}
}

// TestArchiveRateLimitWaitIsBoundedAndHonoursTheArchive proves a 429 is read as
// the request it is. The archive's own wait wins, an unnamed wait gets a short
// pause, and a long wait is capped so one busy index cannot make a running
// transform look hung. Any other status is a refusal, not a pause.
func TestArchiveRateLimitWaitIsBoundedAndHonoursTheArchive(t *testing.T) {
	limited := func(header map[string]string) error {
		response := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}}
		for name, value := range header {
			response.Header.Set(name, value)
		}
		return archiveStatusError(response)
	}
	wait, ok := archiveRateLimitWait(limited(map[string]string{"Retry-After": "3"}))
	if !ok || wait != 3*time.Second {
		t.Fatalf("wait = %v ok = %v, want the archive's own 3s", wait, ok)
	}
	// A host that refuses without naming a wait is still given a pause: the
	// alternative is abandoning a host that may simply be busy.
	wait, ok = archiveRateLimitWait(limited(nil))
	if !ok || wait != archiveRateLimitPause {
		t.Fatalf("wait = %v ok = %v, want the short default pause", wait, ok)
	}
	wait, ok = archiveRateLimitWait(limited(map[string]string{"Retry-After": "9999"}))
	if !ok || wait != archiveRateLimitWaitCap {
		t.Fatalf("wait = %v, want the cap %v", wait, archiveRateLimitWaitCap)
	}
	// A date, an empty value and a malformed value are all unreadable, and an
	// unreadable wait must fall back rather than become a zero-length pause.
	for _, junk := range []string{"", "   ", "soon", "-5", "Wed, 21 Oct 2026 07:28:00 GMT"} {
		wait, ok = archiveRateLimitWait(limited(map[string]string{"Retry-After": junk}))
		if !ok || wait != archiveRateLimitPause {
			t.Fatalf("Retry-After %q gave wait = %v, want the short default pause", junk, wait)
		}
	}
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusBadGateway, http.StatusInternalServerError} {
		response := &http.Response{StatusCode: status, Header: http.Header{}}
		if _, ok := archiveRateLimitWait(archiveStatusError(response)); ok {
			t.Fatalf("HTTP %d was treated as a rate limit", status)
		}
	}
}

// TestArchiveBackoffStopsOnCancelAndPause proves the wait is a pause point like
// every other step: cancelling or replacing the route ends it at once, and a
// paused job does not spend its pause inside a timer it cannot interrupt.
func TestArchiveBackoffStopsOnCancelAndPause(t *testing.T) {
	// A cancelled context returns immediately instead of sitting out the wait.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if err := archiveBackoff(ctx, nil, 30*time.Second); err == nil {
		t.Fatal("a cancelled backoff reported success")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("a cancelled backoff waited %v", elapsed)
	}
	// A wait that is already over is not a wait.
	if err := archiveBackoff(context.Background(), nil, 0); err != nil {
		t.Fatalf("empty backoff: %v", err)
	}
	// A short wait really elapses, so the pause is not a no-op that pretends to
	// have retried.
	started = time.Now()
	if err := archiveBackoff(context.Background(), nil, 120*time.Millisecond); err != nil {
		t.Fatalf("backoff: %v", err)
	}
	if elapsed := time.Since(started); elapsed < 100*time.Millisecond {
		t.Fatalf("backoff returned after %v, want the wait honoured", elapsed)
	}
}

// chainReply is one answer a fixture index gives.
type chainReply struct {
	status int
	body   string
	header map[string]string
}

// chainFixture serves a hand-built chain, so the fallback behaviour is asserted
// without a third party. Each entry names a path, a status and a body.
type chainFixture struct {
	archiveFixture
	// replies maps a request path onto successive answers, so an index can be
	// made to rate limit once and then answer.
	replies map[string][]chainReply
	// asked counts the requests per path.
	asked map[string]int
}

func (fixture *chainFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	attempt := fixture.asked[r.URL.Path]
	fixture.asked[r.URL.Path] = attempt + 1
	answers := fixture.replies[r.URL.Path]
	if len(answers) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// The last configured answer is the one that repeats, so a table of
	// {limited, answered} answers the second request and stays answered.
	if attempt >= len(answers) {
		attempt = len(answers) - 1
	}
	answer := answers[attempt]
	for name, value := range answer.header {
		w.Header().Set(name, value)
	}
	w.Header().Set("Content-Type", "application/json")
	if answer.status != 0 && answer.status != http.StatusOK {
		w.WriteHeader(answer.status)
		_, _ = io.WriteString(w, "upstream failure")
		return
	}
	_, _ = io.WriteString(w, answer.body)
}

func newChainEngine(t *testing.T, replies map[string][]chainReply) (*server, *chainFixture, func()) {
	t.Helper()
	fixture := &chainFixture{replies: replies, asked: map[string]int{}}
	httpServer := httptest.NewServer(fixture)
	engine := &server{transport: &http.Transport{}, crawlIndexBase: httpServer.URL}
	return engine, fixture, httpServer.Close
}

// fixtureHost returns the host of the local fixture a chain engine talks to, so
// a hand-built chain points at the fixture rather than the public archive.
func fixtureHost(engine *server) string {
	if engine.crawlIndexBase != "" {
		return strings.TrimPrefix(engine.crawlIndexBase, "http://")
	}
	return "127.0.0.1:0"
}

// TestRunWaybackURLsRetriesARateLimitedIndex proves a 429 is treated as the
// request it is: the same index is asked again after the wait it named, and the
// retry goes through the same row path as the first attempt.
//
// The failure this exists for is real and observed: the archive answered 429 to
// every request from one egress address, both archive indexes at once, and the
// transform reported a hard failure for a host that simply needed another index.
func TestRunWaybackURLsRetriesARateLimitedIndex(t *testing.T) {
	limited := chainReply{status: http.StatusTooManyRequests, body: "slow down", header: map[string]string{"Retry-After": "1"}}
	answered := chainReply{body: `[["original"],["https://example.com/"]]`}
	engine, fixture, closeServer := newChainEngine(t, map[string][]chainReply{"/cdx": {limited, answered}})
	defer closeServer()
	engine.archiveIndexList = func(ctx context.Context, domain string) ([]archiveEndpoint, error) {
		return []archiveEndpoint{{name: "cdx", query: "http://" + fixtureHost(engine) + "/cdx", layout: archiveLayoutRows}}, nil
	}

	result := &osintTransformResult{}
	started := time.Now()
	if err := engine.runWaybackURLsWithCollector(context.Background(), result, osintTransformInput{
		Transform: "wayback_urls", Value: "example.com", ConfirmNetwork: true,
	}, nil); err != nil {
		t.Fatalf("run: %v", err)
	}
	if fixture.asked["/cdx"] != 2 {
		t.Fatalf("index asked %d times, want the retry after the 429", fixture.asked["/cdx"])
	}
	if elapsed := time.Since(started); elapsed < time.Second {
		t.Fatalf("the retry did not wait the second the archive asked for (%v)", elapsed)
	}
	if len(result.Entities) != 2 || len(result.Relations) != 1 {
		t.Fatalf("entities = %d relations = %d, want the host and its one URL", len(result.Entities), len(result.Relations))
	}
	if result.Metadata["archive_index"] != "cdx" {
		t.Fatalf("metadata = %#v, want the index that answered named", result.Metadata)
	}
}

// TestRunWaybackURLsKeepsWalkingWhenAnIndexStaysRateLimited proves a host that
// never frees up does not cost the whole transform: the chain moves on, and the
// refusal stays visible in the failure list instead of being retried away.
func TestRunWaybackURLsKeepsWalkingWhenAnIndexStaysRateLimited(t *testing.T) {
	refusal := chainReply{status: http.StatusTooManyRequests, body: "slow down", header: map[string]string{"Retry-After": "0"}}
	crawled := chainReply{body: `{"url":"https://example.com/crawled"}` + "\n"}
	engine, _, closeServer := newChainEngine(t, map[string][]chainReply{
		"/cdx":   {refusal, refusal, refusal},
		"/crawl": {crawled},
	})
	defer closeServer()
	host := fixtureHost(engine)
	engine.archiveIndexList = func(ctx context.Context, domain string) ([]archiveEndpoint, error) {
		return []archiveEndpoint{
			{name: "cdx", query: "http://" + host + "/cdx", layout: archiveLayoutRows},
			{name: "crawl CC-MAIN-2026-39", query: "http://" + host + "/crawl", layout: archiveLayoutObjects, field: "url", continueOnEmpty: true},
		}, nil
	}

	result := &osintTransformResult{}
	if err := engine.runWaybackURLsWithCollector(context.Background(), result, osintTransformInput{
		Transform: "wayback_urls", Value: "example.com", ConfirmNetwork: true,
	}, nil); err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Metadata["archive_index"] != "crawl CC-MAIN-2026-39" {
		t.Fatalf("metadata = %#v, want the crawl index that answered", result.Metadata)
	}
	if len(result.Entities) != 2 {
		t.Fatalf("entities = %d, want the host and the crawled URL", len(result.Entities))
	}
	urls := 0
	for _, entity := range result.Entities {
		if entity.Type == "url" {
			urls++
			if got := entity.Provenance["archive_index"]; got != "crawl CC-MAIN-2026-39" {
				t.Fatalf("row provenance = %#v, want the index that produced it", entity.Provenance)
			}
		}
	}
	if urls != 1 {
		t.Fatalf("urls = %d, want 1", urls)
	}
}

// TestRunWaybackURLsKeepsLookingPastAnEmptyCrawlCollection proves an empty
// collection does not end the search. A collection that never crawled the host
// says nothing about it, so the next collection is asked; only a real answer
// stops the chain.
func TestRunWaybackURLsKeepsLookingPastAnEmptyCrawlCollection(t *testing.T) {
	engine, fixture, closeServer := newChainEngine(t, map[string][]chainReply{
		"/empty": {{body: ""}},
		"/old":   {{body: `{"url":"https://example.com/from-the-older-crawl"}` + "\n"}},
	})
	defer closeServer()
	host := fixtureHost(engine)
	engine.archiveIndexList = func(ctx context.Context, domain string) ([]archiveEndpoint, error) {
		return []archiveEndpoint{
			{name: "crawl CC-MAIN-2026-39", query: "http://" + host + "/empty", layout: archiveLayoutObjects, field: "url", continueOnEmpty: true},
			{name: "crawl CC-MAIN-2026-34", query: "http://" + host + "/old", layout: archiveLayoutObjects, field: "url", continueOnEmpty: true},
		}, nil
	}

	result := &osintTransformResult{}
	if err := engine.runWaybackURLsWithCollector(context.Background(), result, osintTransformInput{
		Transform: "wayback_urls", Value: "example.com", ConfirmNetwork: true,
	}, nil); err != nil {
		t.Fatalf("run: %v", err)
	}
	if fixture.asked["/empty"] != 1 || fixture.asked["/old"] != 1 {
		t.Fatalf("asked = %v, want both collections consulted", fixture.asked)
	}
	if result.Metadata["archive_index"] != "crawl CC-MAIN-2026-34" {
		t.Fatalf("metadata = %#v, want the collection that actually held the host", result.Metadata)
	}
	if !strings.Contains(strings.Join(result.Warnings, " "), "holds no captures") {
		t.Fatalf("warnings = %v, want the empty collection reported", result.Warnings)
	}
}

// TestRunWaybackURLsReportsEveryFailedHost proves the refusal of one host does
// not hide the refusal of the next, and that a chain with nothing left reports
// what it tried instead of a single opaque code.
func TestRunWaybackURLsReportsEveryFailedHost(t *testing.T) {
	engine, _, closeServer := newChainEngine(t, map[string][]chainReply{
		"/one": {{status: http.StatusForbidden, body: "denied"}},
		"/two": {{status: http.StatusNotFound, body: "gone"}},
	})
	defer closeServer()
	host := fixtureHost(engine)
	engine.archiveIndexList = func(ctx context.Context, domain string) ([]archiveEndpoint, error) {
		return []archiveEndpoint{
			{name: "first", query: "http://" + host + "/one", layout: archiveLayoutRows},
			{name: "second", query: "http://" + host + "/two", layout: archiveLayoutRows},
		}, nil
	}

	result := &osintTransformResult{}
	err := engine.runWaybackURLsWithCollector(context.Background(), result, osintTransformInput{
		Transform: "wayback_urls", Value: "example.com", ConfirmNetwork: true,
	}, nil)
	if err == nil {
		t.Fatal("a chain with nothing left reported success")
	}
	message := err.Error()
	for _, want := range []string{"WAYBACK_LOOKUP_FAILED", "first", "HTTP 403", "second", "HTTP 404"} {
		if !strings.Contains(message, want) {
			t.Fatalf("error %q does not mention %q", message, want)
		}
	}
}

// TestRunWaybackURLsKeepsDeduplicatingAcrossHosts proves a URL both archives
// hold becomes one identity, whichever index delivered it. A fallback that
// duplicated every row would multiply a large host by the size of the chain.
func TestRunWaybackURLsKeepsDeduplicatingAcrossHosts(t *testing.T) {
	engine, _, closeServer := newChainEngine(t, map[string][]chainReply{
		"/a": {{body: `[["original"],["https://example.com/x"],["https://example.com/x"]]`}},
	})
	defer closeServer()
	host := fixtureHost(engine)
	engine.archiveIndexList = func(ctx context.Context, domain string) ([]archiveEndpoint, error) {
		return []archiveEndpoint{
			{name: "first", query: "http://" + host + "/a", layout: archiveLayoutRows},
			{name: "second", query: "http://" + host + "/a", layout: archiveLayoutRows},
		}, nil
	}

	result := &osintTransformResult{}
	if err := engine.runWaybackURLsWithCollector(context.Background(), result, osintTransformInput{
		Transform: "wayback_urls", Value: "example.com", ConfirmNetwork: true,
	}, nil); err != nil {
		t.Fatalf("run: %v", err)
	}
	urls := 0
	for _, entity := range result.Entities {
		if entity.Type == "url" {
			urls++
		}
	}
	if urls != 1 {
		t.Fatalf("urls = %d, want one identity for a URL both indexes hold", urls)
	}
}

// TestAFailedTransformStillReportsWhatItObserved proves the 400 body carries the
// warnings, the partial rows and the metadata of the run that failed.
//
// A transform that ends in an error has usually already learned something — four
// certificate indexes answered and a fifth refused, three archive indexes were
// consulted — and returning a bare error string threw that away. It also means a
// caller reads one shape whether the run succeeded or not.
func TestAFailedTransformStillReportsWhatItObserved(t *testing.T) {
	engine, fixture, closeServer := newChainEngine(t, map[string][]chainReply{
		"/one": {{status: http.StatusForbidden, body: "denied"}},
	})
	defer closeServer()
	host := fixtureHost(engine)
	engine.archiveIndexList = func(ctx context.Context, domain string) ([]archiveEndpoint, error) {
		return []archiveEndpoint{{name: "first", query: "http://" + host + "/one", layout: archiveLayoutRows}}, nil
	}
	// The handler resolves the source address of a network run, which is a live
	// lookup; a unit test stubs it the way the other network tests do.
	engine.sourceIPTransport = &sourceIPRoundTripper{}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/proxy/osint/transform", strings.NewReader(
		`{"transform":"wayback_urls","value":"example.com","confirm_network":true}`))
	engine.osintTransform(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	var body struct {
		Error    string   `json:"error"`
		Reason   string   `json:"reason"`
		Warnings []string `json:"warnings"`
		Entities []struct {
			Type     string `json:"type"`
			Identity string `json:"identity"`
		} `json:"entities"`
		Relations []struct {
			Type string `json:"type"`
		} `json:"relations"`
		Metadata map[string]interface{} `json:"metadata"`
		SourceIP string                 `json:"source_ip"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, recorder.Body.String())
	}
	// The keys a caller reads for a failure are unchanged.
	if body.Reason != "OSINT_TRANSFORM_FAILED" || body.Error == "" {
		t.Fatalf("body = %+v, want the usual error and reason", body)
	}
	// The host the transform was run against is real evidence and was already
	// collected when the indexes refused, so it is reported.
	if len(body.Entities) == 0 || body.Entities[0].Type != "domain" {
		t.Fatalf("entities = %+v, want the host that was asked about", body.Entities)
	}
	// The refusal that decided the outcome is named per index. On a total failure
	// it lives in the error string rather than in a warning, so the two do not
	// repeat each other, and the key is present either way.
	if !strings.Contains(body.Error, "first index") || !strings.Contains(body.Error, "HTTP 403") {
		t.Fatalf("error %q does not name the index that refused", body.Error)
	}
	if body.Warnings == nil {
		t.Fatal("the failed body has no warnings key at all, so a caller cannot read one shape")
	}
	_ = fixture
}

// TestAFailedTransformNamesTheChainItCouldNotBuild proves the reason the chain
// was short appears in the error text, not only in the warnings. The error
// string is the part a script reads, and "the second archive was never
// consulted" is what makes the first one being down matter.
func TestAFailedTransformNamesTheChainItCouldNotBuild(t *testing.T) {
	engine, _, closeServer := newChainEngine(t, map[string][]chainReply{
		"/cdx/search/cdx":   {{status: http.StatusForbidden, body: "denied"}},
		"/web/timemap/json": {{status: http.StatusForbidden, body: "denied"}},
		"/collinfo.json":    {{status: http.StatusServiceUnavailable, body: "maintenance"}},
	})
	defer closeServer()
	host := fixtureHost(engine)
	// Both index hosts are the fixture and the crawl list is refused, so the
	// production chain is what runs here: a replaced chain never consults the
	// crawl index, and then there is nothing to report about it.
	engine.crawlIndexBase = "http://" + host
	engine.archiveIndexBase = "http://" + host

	result := &osintTransformResult{}
	err := engine.runWaybackURLsWithCollector(context.Background(), result, osintTransformInput{
		Transform: "wayback_urls", Value: "example.com", ConfirmNetwork: true,
	}, nil)
	if err == nil {
		t.Fatal("a chain with nothing left reported success")
	}
	if !strings.Contains(err.Error(), "archive index chain") {
		t.Fatalf("error %q does not mention the chain that could not be built", err)
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("error %q does not say why the crawl index was unavailable", err)
	}
}

// TestArchiveRetryWaitSplitsRefusalsFromBrokenConnections proves an index is
// asked again for the failures that are not answers, and is not asked again for
// the ones that are.
//
// A rate limit names a wait and expects the client to come back. A closed
// connection or a timed-out handshake is the state of a network, not a decision
// by the index, and repeating the request is how that is ridden out. A 403, a
// 404, an index that does not exist: the index answered deliberately, and
// asking the same question again cannot change the answer.
func TestArchiveRetryWaitSplitsRefusalsFromBrokenConnections(t *testing.T) {
	// A rate limit waits as long as the index asked.
	limited := archiveStatusError(&http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{"2"}}})
	wait, again := archiveRetryWait(limited)
	if !again || wait != 2*time.Second {
		t.Fatalf("rate limit: wait = %v again = %v, want the archive's own 2s", wait, again)
	}
	// A connection that never happened waits the short default, because nothing
	// named a duration and the point is to ride out a closed connection.
	for _, transport := range []error{
		archiveTransportError{errors.New(`Get "https://index.example/query": EOF`)},
		archiveTransportError{errors.New(`Get "https://index.example/query": connection reset by peer`)},
		archiveTransportError{errors.New(`dial tcp 203.0.113.7:443: i/o timeout`)},
	} {
		wait, again = archiveRetryWait(transport)
		if !again || wait != archiveRateLimitPause {
			t.Fatalf("%v: wait = %v again = %v, want the short default pause", transport, wait, again)
		}
	}
	// A refusal is an answer and is never repeated.
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusUnauthorized, http.StatusGone} {
		refused := archiveStatusError(&http.Response{StatusCode: status, Header: http.Header{}})
		if _, again := archiveRetryWait(refused); again {
			t.Fatalf("HTTP %d was retried: the index answered deliberately", status)
		}
	}
	// A cancelled or expired run is the caller's state, not the network's, and a
	// retry would ignore the cancellation rather than honour it.
	if _, again := archiveRetryWait(context.Canceled); again {
		t.Fatal("a cancelled request was retried")
	}
	// An untagged error is not guessed at: only a request the client reported as
	// broken counts, because "no status" also covers a body that made no sense.
	if _, again := archiveRetryWait(errors.New("some other failure")); again {
		t.Fatal("an untagged error was guessed to be a transport failure")
	}
	if _, again := archiveRetryWait(nil); again {
		t.Fatal("a request that succeeded was retried")
	}
	// A body that decoded into nothing useful is the index's own content, and
	// repeating the request cannot change what it chose to send.
	if _, again := archiveRetryWait(errors.New("archive index header has no original URL column")); again {
		t.Fatal("an undecodable body was retried")
	}
}

// TestRunWaybackURLsRetriesAClosedConnection proves a dropped connection is ridden
// out rather than taken as an answer. The failure this exists for was observed:
// the second archive host closed the connection on every attempt, and one
// dropped handshake took the whole transform down.
func TestRunWaybackURLsRetriesAClosedConnection(t *testing.T) {
	// The handler aborts the first connection without answering, which is what an
	// index that gave up on the TLS session looks like from the client side, and
	// answers the second one.
	attempts := 0
	dropper := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			panic(http.ErrAbortHandler)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"url":"https://example.com/survived"}`+"\n")
	}))
	defer dropper.Close()
	engine := &server{transport: &http.Transport{}}
	engine.archiveIndexList = func(ctx context.Context, domain string) ([]archiveEndpoint, error) {
		return []archiveEndpoint{{
			name:   "dropping",
			query:  dropper.URL + "/index",
			layout: archiveLayoutObjects,
			field:  "url",
		}}, nil
	}

	result := &osintTransformResult{}
	if err := engine.runWaybackURLsWithCollector(context.Background(), result, osintTransformInput{
		Transform: "wayback_urls", Value: "example.com", ConfirmNetwork: true,
	}, nil); err != nil {
		t.Fatalf("a dropped connection was taken as an answer: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want the connection dropped once and the retry answered", attempts)
	}
	if result.Metadata["archive_index"] != "dropping" {
		t.Fatalf("metadata = %#v, want the index that answered the retry", result.Metadata)
	}
	urls := 0
	for _, entity := range result.Entities {
		if entity.Type == "url" {
			urls++
		}
	}
	if urls != 1 {
		t.Fatalf("urls = %d, want the row the retry delivered", urls)
	}
}

// TestCrawlIndexDiscoveryIsAskedAgain proves reading the collection list obeys
// the same retry policy as the queries it enables.
//
// Measured on the public index, five of twelve identical list requests were
// dropped, so a single attempt meant one reset connection removed the whole
// second archive from the chain — while the identical condition one step later
// was retried. A refusal is still not retried: an index that says no is not
// going to say yes on the second question.
func TestCrawlIndexDiscoveryIsAskedAgain(t *testing.T) {
	published := chainReply{body: `[{"id":"CC-MAIN-2026-39","cdx-api":"https://index.example/CC-MAIN-2026-39-index"}]`}
	dropper := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if droppedCount.Add(1) == 1 {
			// Break the connection the way a host that gave up on the session does.
			panic(http.ErrAbortHandler)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, published.body)
	}))
	defer dropper.Close()
	engine := &server{transport: &http.Transport{}, crawlIndexBase: dropper.URL}

	endpoints, err := engine.crawlIndexEndpoints(context.Background(), engine.requestHTTPClient(), "example.com/*")
	if err != nil {
		t.Fatalf("a dropped collection list was taken as an answer: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].name != "crawl CC-MAIN-2026-39" {
		t.Fatalf("endpoints = %+v, want the collection the retry discovered", endpoints)
	}
	if got := droppedCount.Load(); got != 2 {
		t.Fatalf("attempts = %d, want the list asked again after the dropped one", got)
	}

	// The budget is bounded and it is spent only on failures: a host that drops
	// every attempt is asked exactly the budget and then reported, and a host
	// that answers is asked once.
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		brokenCount.Add(1)
		panic(http.ErrAbortHandler)
	}))
	defer broken.Close()
	strictBudget := &server{transport: &http.Transport{}, crawlIndexBase: broken.URL}
	if _, err := strictBudget.crawlIndexEndpoints(context.Background(), strictBudget.requestHTTPClient(), "example.com/*"); err == nil {
		t.Fatal("a collection list that never answered was accepted")
	}
	if got := brokenCount.Load(); got != int64(archiveDiscoveryAttempts) {
		t.Fatalf("attempts = %d, want the discovery budget of %d and then a report", got, archiveDiscoveryAttempts)
	}
	once := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		onceCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"id":"CC-MAIN-2026-39","cdx-api":"https://index.example/x"}]`)
	}))
	defer once.Close()
	eager := &server{transport: &http.Transport{}, crawlIndexBase: once.URL}
	if _, err := eager.crawlIndexEndpoints(context.Background(), eager.requestHTTPClient(), "example.com/*"); err != nil {
		t.Fatalf("collections: %v", err)
	}
	if got := onceCount.Load(); got != 1 {
		t.Fatalf("attempts = %d, want a host that answered to be asked once", got)
	}
	// A refusal is an answer and is not asked twice.
	refused := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refusedCount.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer refused.Close()
	strict := &server{transport: &http.Transport{}, crawlIndexBase: refused.URL}
	if _, err := strict.crawlIndexEndpoints(context.Background(), strict.requestHTTPClient(), "example.com/*"); err == nil {
		t.Fatal("a refused collection list was accepted")
	}
	if got := refusedCount.Load(); got != 1 {
		t.Fatalf("attempts = %d, want a refused list asked exactly once", got)
	}
}

var droppedCount, refusedCount, brokenCount, onceCount atomic.Int64
