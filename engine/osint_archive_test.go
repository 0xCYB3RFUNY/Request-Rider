package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	return engine, fixture, httpServer.Close
}

func TestArchiveEndpointsUseTheConfiguredIndexBase(t *testing.T) {
	endpoints := archiveEndpoints("", "yandex.ru")
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
	if !strings.Contains(endpoints[0].query, "fl=original") {
		t.Fatalf("cdx query lost the original field: %q", endpoints[0].query)
	}
	local := archiveEndpoints("http://127.0.0.1:9/", "yandex.ru")
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
	index, err := streamArchiveIndex(context.Background(), engine.requestHTTPClient(), archiveEndpoints(engine.archiveIndexBase, "yandex.ru")[0], func(candidate string) {
		if target, ok := archiveURLTarget(candidate); ok {
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
	index, err := streamArchiveIndex(context.Background(), engine.requestHTTPClient(), archiveEndpoints(engine.archiveIndexBase, "yandex.ru")[1], func(candidate string) {
		if target, ok := archiveURLTarget(candidate); ok {
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
		index, err := streamArchiveIndex(context.Background(), engine.requestHTTPClient(), endpoint, func(candidate string) {
			urls = append(urls, candidate)
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

	_, err := streamArchiveIndex(context.Background(), engine.requestHTTPClient(), archiveEndpoints(engine.archiveIndexBase, "yandex.ru")[0], func(string) {})
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
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "ended early after 2 rows") {
		t.Fatalf("warnings = %#v", result.Warnings)
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
