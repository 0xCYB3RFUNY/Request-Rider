package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// certificateFixture serves one local answer per index path, so the merge, the
// retry and the pagination of the certificate chain are asserted without a
// third party.
type certificateFixture struct {
	bodies    map[string]string
	statuses  map[string]int
	headers   map[string]map[string]string
	requests  []string
	agents    []string
	auths     []string
	accepts   []string
	pageLimit int
}

func (fixture *certificateFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fixture.requests = append(fixture.requests, r.URL.Path)
	fixture.agents = append(fixture.agents, r.Header.Get("User-Agent"))
	fixture.auths = append(fixture.auths, r.Header.Get("Authorization"))
	fixture.accepts = append(fixture.accepts, r.Header.Get("Accept"))
	for name, value := range fixture.headers[r.URL.Path] {
		w.Header().Set(name, value)
	}
	if status, ok := fixture.statuses[r.URL.Path]; ok {
		w.WriteHeader(status)
		return
	}
	body, ok := fixture.bodies[r.URL.Path]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.URL.Path == "/paginated" && fixture.pageLimit > 0 {
		if seen := countRequests(fixture.requests, r.URL.Path); seen > fixture.pageLimit {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
	}
	_, _ = io.WriteString(w, body)
}

func countRequests(requests []string, path string) int {
	total := 0
	for _, item := range requests {
		if item == path {
			total++
		}
	}
	return total
}

func newCertificateFixture(t *testing.T) (*httptest.Server, *certificateFixture) {
	t.Helper()
	fixture := &certificateFixture{
		bodies:   map[string]string{},
		statuses: map[string]int{},
		headers:  map[string]map[string]string{},
	}
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)
	return server, fixture
}

// fixtureSource points one index at a local path and uses the real reader for
// the answer format that index serves.
func fixtureSource(base, name, path string, page func(io.Reader, string, *streamingCollector) (map[string]bool, string, error)) certificateSource {
	return certificateSource{
		name:   name,
		query:  base + path,
		accept: "application/json",
		page:   page,
	}
}

// fixedChain answers every zone with the same local indexes, for the tests that
// are about merging, retrying or paging rather than about zone resolution.
func fixedChain(sources []certificateSource) func(string) []certificateSource {
	return func(string) []certificateSource { return sources }
}

func TestCertificateSourcesCoverTheVerifiedIndexes(t *testing.T) {
	sources := certificateSources("yandex.ru")
	if len(sources) != 5 {
		t.Fatalf("indexes = %d: %#v", len(sources), sources)
	}
	// The indexes that measurably answer first stay in front, so a healthy
	// run does not spend the metered fallbacks to obtain the same names.
	order := []string{"crt.sh", "crt.name", "certspotter", "shodan-ctl", "ctlogs.dev"}
	for position, name := range order {
		if sources[position].name != name {
			t.Fatalf("index %d = %q, want %q", position, sources[position].name, name)
		}
		if sources[position].page == nil {
			t.Fatalf("index %q has no reader", name)
		}
		if sources[position].accept == "" {
			t.Fatalf("index %q has no media type", name)
		}
	}
	// Every index queries the requested host and nothing else.
	for _, source := range sources {
		if !strings.Contains(source.query, "yandex.ru") {
			t.Fatalf("index %q does not query the requested host: %q", source.name, source.query)
		}
	}
	// Keys are read from the environment only, and only where an index has one.
	if sources[0].keyEnv != "" || sources[3].keyEnv != "" {
		t.Fatalf("an anonymous index was given a key slot: %#v", sources)
	}
	if sources[2].keyEnv != "CERTSPOTTER_API_TOKEN" || sources[4].keyEnv != "CTLOGS_API_KEY" {
		t.Fatalf("key slots = %q / %q", sources[2].keyEnv, sources[4].keyEnv)
	}
}

func TestCertificateTransparencyNamesMergesEveryAnsweringIndex(t *testing.T) {
	server, fixture := newCertificateFixture(t)
	fixture.bodies["/crt"] = `[{"name_value":"www.example.test\ncdn.example.test"},{"name_value":"other.test"}]`
	fixture.bodies["/lines"] = "www.example.test\nshodan.example.test\n"
	fixture.bodies["/array"] = `["shodan.example.test","array.example.test"]`
	fixture.statuses["/hosted"] = http.StatusServiceUnavailable

	sources := []certificateSource{
		fixtureSource(server.URL, "crt.sh", "/crt", readCrtShNames),
		{name: "crt.name", query: server.URL + "/lines", accept: "text/plain", page: readLineNames},
		{name: "shodan-ctl", query: server.URL + "/array", accept: "application/json", page: readStringArrayNames},
		{name: "ctlogs.dev", query: server.URL + "/hosted", accept: "application/json", page: readCTLogsHosts},
	}

	evidence := certificateTransparencyNames(context.Background(), server.Client(), "example.test", nil, fixedChain(sources))
	names, warnings, counts := evidence.names, evidence.warnings, evidence.counts
	// A name two indexes both hold is still one identity.
	if len(names) != 4 {
		t.Fatalf("names = %#v", names)
	}
	for _, want := range []string{"www.example.test", "cdn.example.test", "shodan.example.test", "array.example.test"} {
		if !names[want] {
			t.Fatalf("name %q is missing from %#v", want, names)
		}
	}
	// A name from another zone and the apex itself are never accepted.
	if names["other.test"] || names["example.test"] {
		t.Fatalf("out of zone names were accepted: %#v", names)
	}
	if counts["crt.sh"] != 2 || counts["crt.name"] != 2 || counts["shodan-ctl"] != 2 {
		t.Fatalf("per index counts = %#v", counts)
	}
	if _, failed := counts["ctlogs.dev"]; failed {
		t.Fatalf("a failed index was counted as answering: %#v", counts)
	}
	// The failed index stays visible instead of disappearing silently.
	if len(warnings) != 1 || !strings.Contains(warnings[0], "ctlogs.dev") || !strings.Contains(warnings[0], "status=503") {
		t.Fatalf("warnings = %#v", warnings)
	}
	// Every index identifies itself, and the metered ones carry no key.
	for _, agent := range fixture.agents {
		if agent != "RequestRider-OSINT-Transform/1.0" {
			t.Fatalf("user agent = %q", agent)
		}
	}
	for _, auth := range fixture.auths {
		if auth != "" {
			t.Fatalf("an index credential was sent to an anonymous index: %q", auth)
		}
	}
}

func TestCertificateTransparencyNamesReportsEveryFailedIndex(t *testing.T) {
	server, fixture := newCertificateFixture(t)
	fixture.statuses["/a"] = http.StatusBadGateway
	fixture.statuses["/b"] = http.StatusTooManyRequests
	fixture.statuses["/c"] = http.StatusNotFound

	sources := []certificateSource{
		{name: "crt.sh", query: server.URL + "/a", accept: "application/json", page: readCrtShNames},
		{name: "certspotter", query: server.URL + "/b", accept: "application/json", page: readCertspotterNames},
		{name: "ctlogs.dev", query: server.URL + "/c", accept: "application/json", page: readCTLogsHosts},
	}

	evidence := certificateTransparencyNames(context.Background(), server.Client(), "example.test", nil, fixedChain(sources))
	names, warnings, counts := evidence.names, evidence.warnings, evidence.counts
	if len(names) != 0 || len(counts) != 0 {
		t.Fatalf("failed indexes produced evidence: %#v %#v", names, counts)
	}
	// Every attempted index is named, with its own status.
	if len(warnings) != 4 {
		t.Fatalf("warnings = %#v", warnings)
	}
	for _, fragment := range []string{"crt.sh", "status=502", "certspotter", "status=429", "ctlogs.dev", "status=404", "no public certificate index answered"} {
		if !strings.Contains(strings.Join(warnings, " "), fragment) {
			t.Fatalf("warnings %q do not report %q", warnings, fragment)
		}
	}
}

func TestCertificateTransparencyNamesRetriesTransientFailures(t *testing.T) {
	attempts := 0
	// The first two attempts are a mirror outage, the last one answers.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < crtLookupAttempts {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, `[{"name_value":"*.www.example.test\nwww.example.test"},{"name_value":"example.test"}]`)
	}))
	defer server.Close()

	sources := []certificateSource{
		{name: "crt.sh", query: server.URL + "/crt", accept: "application/json", page: readCrtShNames},
	}
	evidence := certificateTransparencyNames(context.Background(), server.Client(), "example.test", nil, fixedChain(sources))
	names, warnings, counts := evidence.names, evidence.warnings, evidence.counts
	if len(warnings) != 0 {
		t.Fatalf("a recovered lookup reported warnings: %#v", warnings)
	}
	if attempts != crtLookupAttempts {
		t.Fatalf("attempts = %d", attempts)
	}
	if len(names) != 1 || !names["www.example.test"] {
		t.Fatalf("names = %#v", names)
	}
	// The apex itself is the transform input, so it is not a subdomain.
	if names["example.test"] {
		t.Fatalf("the apex was returned as a subdomain: %#v", names)
	}
	if counts["crt.sh"] != 1 {
		t.Fatalf("counts = %#v", counts)
	}
}

func TestCertificateTransparencyNamesStopsOnCancelledRoute(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		cancel()
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	sources := []certificateSource{
		{name: "crt.sh", query: server.URL + "/crt", accept: "application/json", page: readCrtShNames},
	}
	evidence := certificateTransparencyNames(ctx, server.Client(), "example.test", nil, fixedChain(sources))
	_, warnings, _ := evidence.names, evidence.warnings, evidence.counts
	if attempts != 1 {
		t.Fatalf("a cancelled lookup kept retrying: attempts = %d", attempts)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "cancelled") {
		t.Fatalf("warnings = %#v", warnings)
	}
}

// A metered index is walked page by page and stops exactly where the index
// itself says its allowance is spent, with the stop reported to the analyst.
func TestCertificateTransparencyNamesFollowsTheIndexAllowance(t *testing.T) {
	// Every page is full, so the index always offers a cursor. The second
	// response reports the public allowance as spent.
	page := 0
	queries := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		queries = append(queries, r.URL.RawQuery)
		remaining := "9"
		prefix := "first"
		if page > 1 {
			remaining = "0"
			prefix = "second"
		}
		w.Header().Set("X-RateLimit-Limit", "10")
		w.Header().Set("X-RateLimit-Remaining", remaining)
		_, _ = io.WriteString(w, fullCertspotterPage(certspotterPageSize, prefix))
	}))
	defer server.Close()

	sources := []certificateSource{
		{name: "certspotter", query: server.URL + "/paged?domain=example.test", accept: "application/json", page: readCertspotterNames},
	}
	evidence := certificateTransparencyNames(context.Background(), server.Client(), "example.test", nil, fixedChain(sources))
	names, warnings, counts := evidence.names, evidence.warnings, evidence.counts
	if page != 2 {
		t.Fatalf("the walk stopped after %d page(s)", page)
	}
	if len(names) != certspotterPageSize*2 {
		t.Fatalf("names = %d", len(names))
	}
	if !names["first-0.example.test"] || !names["second-0.example.test"] {
		t.Fatalf("names = %#v", names)
	}
	if counts["certspotter"] != certspotterPageSize*2 {
		t.Fatalf("counts = %#v", counts)
	}
	// The second page was asked for with the cursor of the first one.
	if len(queries) != 2 || strings.Contains(queries[0], "after=") {
		t.Fatalf("queries = %#v", queries)
	}
	if !strings.Contains(queries[1], "after=first-99") {
		t.Fatalf("the second page did not use the cursor: %q", queries[1])
	}
	// Where the public budget stopped the walk is stated, not hidden.
	if len(warnings) != 1 || !strings.Contains(warnings[0], "2 page(s)") || !strings.Contains(warnings[0], "0 of 10") {
		t.Fatalf("warnings = %#v", warnings)
	}
}

func fullCertspotterPage(size int, prefix string) string {
	var body strings.Builder
	body.WriteString("[")
	for index := 0; index < size; index++ {
		if index > 0 {
			body.WriteString(",")
		}
		// Every row is a distinct name, so a full page cannot end the walk by
		// running out of names.
		fmt.Fprintf(&body, `{"id":"%s-%d","dns_names":["%s-%d.example.test"]}`, prefix, index, prefix, index)
	}
	body.WriteString("]")
	return body.String()
}

func TestReadCertspotterStopsOnAShortPage(t *testing.T) {
	names, cursor, err := readCertspotterNames(strings.NewReader(
		`[{"id":"1","dns_names":["a.example.test"]},{"id":"2","dns_names":["b.example.test"]}]`), "example.test", nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if cursor != "" {
		t.Fatalf("a short page offered a cursor: %q", cursor)
	}
	if len(names) != 2 {
		t.Fatalf("names = %#v", names)
	}
	names, cursor, err = readCertspotterNames(strings.NewReader(fullCertspotterPage(certspotterPageSize, "full")), "example.test", nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if cursor != fmt.Sprintf("full-%d", certspotterPageSize-1) {
		t.Fatalf("cursor = %q", cursor)
	}
	if len(names) != certspotterPageSize {
		t.Fatalf("names = %d", len(names))
	}
}

func TestReadLineNamesStreamsAndSkipsForeignRows(t *testing.T) {
	// An oversized line is refused by the scanner rather than by a hard crash.
	names, _, err := readLineNames(strings.NewReader("www.example.test\n\n  \nother.test\n"), "example.test", nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(names) != 1 || !names["www.example.test"] {
		t.Fatalf("names = %#v", names)
	}
	long := strings.Repeat("a", 2*1024*1024) + ".example.test"
	if _, _, err := readLineNames(strings.NewReader(long), "example.test", nil); err == nil {
		t.Fatal("an oversized line was accepted silently")
	}
}

func TestAddCertificateNameRejectsUnstorableNames(t *testing.T) {
	names := map[string]bool{}
	for _, candidate := range []string{
		"", "   ", "example.test", "*.", "www example.test", "evil.test",
		"..example.test", "a/../b.example.test", "user@www.example.test",
	} {
		addCertificateName(names, candidate, "example.test")
	}
	for _, candidate := range []string{"WWW.Example.Test", "*.www.example.test", "www.example.test.", "a.b.example.test"} {
		addCertificateName(names, candidate, "example.test")
	}
	if len(names) != 2 || !names["www.example.test"] || !names["a.b.example.test"] {
		t.Fatalf("names = %#v", names)
	}
}

func TestCertificateIndexMetadataRecordsEveryAnsweringIndex(t *testing.T) {
	metadata := certificateIndexMetadata(nil, map[string]int{"crt.name": 176936, "shodan-ctl": 781}, 176953)
	perIndex, ok := metadata["cert_indexes"].(map[string]interface{})
	if !ok {
		t.Fatalf("metadata = %#v", metadata)
	}
	if perIndex["crt.name"] != 176936 || perIndex["shodan-ctl"] != 781 {
		t.Fatalf("per index = %#v", perIndex)
	}
	if metadata["cert_names"] != 176953 {
		t.Fatalf("total = %#v", metadata["cert_names"])
	}
}

func TestCertificateQueryZonesWalksParentsAndStopsBeforeASingleLabel(t *testing.T) {
	for host, want := range map[string][]string{
		"www.lafann.ru":  {"www.lafann.ru", "lafann.ru"},
		"lafann.ru":      {"lafann.ru"},
		"a.b.example.ru": {"a.b.example.ru", "b.example.ru", "example.ru"},
		"WWW.Example.RU": {"www.example.ru", "example.ru"},
		"example.test.":  {"example.test"},
		// A public suffix is never asked for the certificate list of the whole
		// registry, and a value that is not a host has no zone at all.
		"ru":     {},
		"test":   {},
		"":       {},
		"...":    {},
		"a..b":   {},
		"a b.ru": {},
	} {
		zones := certificateQueryZones(host)
		if len(zones) != len(want) {
			t.Fatalf("zones for %q = %#v, want %#v", host, zones, want)
		}
		for position, zone := range want {
			if zones[position] != zone {
				t.Fatalf("zones for %q = %#v, want %#v", host, zones, want)
			}
		}
	}
	// The chain never reaches a single label, so a TLD is never queried.
	for _, host := range []string{"a.b.c.example.ru", "example.ru", "ru"} {
		for _, zone := range certificateQueryZones(host) {
			if !strings.Contains(zone, ".") {
				t.Fatalf("zone %q of %q has no parent label left", zone, host)
			}
		}
	}
}

// A host input is answered by the zone it belongs to, because the indexes are
// keyed by zone: an index that validates its input refuses the host, and the
// parent zone answers. The walk stops at the first zone that holds a name the
// transform did not already have.
func TestCertificateTransparencyNamesWalksToTheZoneOfAHostInput(t *testing.T) {
	queries := 0
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries++
		// The first query is the host itself, which is not a zone.
		if queries == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "invalid apex: not an apex (eTLD+1 is example.test)")
			return
		}
		_, _ = io.WriteString(w, "mail.example.test\nwww.example.test\nshop.example.test\n")
	}))
	defer httpServer.Close()

	sources := []certificateSource{{name: "crt.name", query: httpServer.URL + "/v1/search", accept: "text/plain", page: readLineNames}}
	evidence := certificateTransparencyNames(context.Background(), httpServer.Client(), "www.example.test", nil, fixedChain(sources))

	if evidence.zone != "example.test" {
		t.Fatalf("zone = %q, want the zone the host belongs to", evidence.zone)
	}
	// The names only survive the suffix filter when they are read as names of
	// the parent zone, which is the whole point of the walk.
	for _, want := range []string{"mail.example.test", "shop.example.test", "www.example.test"} {
		if !evidence.names[want] {
			t.Fatalf("name %q is missing from %#v", want, evidence.names)
		}
	}
	if len(evidence.names) != 3 {
		t.Fatalf("names = %#v", evidence.names)
	}
	if evidence.counts["crt.name"] != 3 {
		t.Fatalf("counts = %#v", evidence.counts)
	}
	// The index answered for the zone, so its refusal for the host is not
	// reported as an outage.
	if strings.Contains(strings.Join(evidence.warnings, " "), "status=400") {
		t.Fatalf("an index that answered the zone was reported as failed: %#v", evidence.warnings)
	}
	// The walk stopped at the answering zone instead of climbing further.
	if queries != 2 {
		t.Fatalf("the zone walk issued %d queries", queries)
	}
	if len(evidence.queried) != 2 || evidence.queried[0] != "www.example.test" || evidence.queried[1] != "example.test" {
		t.Fatalf("queried zones = %#v", evidence.queried)
	}
}

// An index that refuses a query is not asked the same question again: the
// refusal is the index's answer, while a 5xx is an outage worth retrying.
func TestCertificateTransparencyNamesDoesNotRetryARejectedQuery(t *testing.T) {
	attempts := 0
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer httpServer.Close()

	sources := []certificateSource{{name: "crt.name", query: httpServer.URL + "/v1/search", accept: "text/plain", page: readLineNames}}
	evidence := certificateTransparencyNames(context.Background(), httpServer.Client(), "example.test", nil, fixedChain(sources))

	if attempts != 1 {
		t.Fatalf("a rejected query was asked %d times", attempts)
	}
	if len(evidence.names) != 0 || len(evidence.counts) != 0 || evidence.zone != "" {
		t.Fatalf("a refused index produced evidence: %#v", evidence)
	}
	joined := strings.Join(evidence.warnings, " ")
	for _, fragment := range []string{"crt.name", "rejected the query (status=400)", "no public certificate index answered for example.test"} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("warnings %q do not report %q", evidence.warnings, fragment)
		}
	}
	if strings.Contains(joined, "after 3 attempts") {
		t.Fatalf("a refusal was reported as a retried outage: %q", evidence.warnings)
	}
}

// An index that reports its own public allowance as spent is not asked about
// the next zone, because it would answer with the same refusal.
func TestCertificateTransparencyNamesStopsAskingAnExhaustedIndex(t *testing.T) {
	metred := 0
	// The metered index serves the host zone and reports its allowance spent;
	// the open index serves the parent zone, which is what answers the walk.
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "metered") {
			metred++
			w.Header().Set("X-RateLimit-Limit", "10")
			w.Header().Set("X-RateLimit-Remaining", "0")
			_, _ = io.WriteString(w, fullCertspotterPage(1, "first"))
			return
		}
		if r.URL.Query().Get("zone") == "example.test" {
			_, _ = io.WriteString(w, "mail.example.test\n")
			return
		}
		_, _ = io.WriteString(w, "")
	}))
	defer httpServer.Close()

	// The chain builds the query of the zone it is asked about, the way the
	// production chain does, so the parent zone is queried for itself.
	chain := func(zone string) []certificateSource {
		return []certificateSource{
			{name: "certspotter", query: httpServer.URL + "/metered?zone=" + zone, accept: "application/json", page: readCertspotterNames},
			{name: "crt.name", query: httpServer.URL + "/open?zone=" + zone, accept: "text/plain", page: readLineNames},
		}
	}
	evidence := certificateTransparencyNames(context.Background(), httpServer.Client(), "www.example.test", nil, chain)
	if metred != 1 {
		t.Fatalf("an index with a spent allowance was asked %d times", metred)
	}
	if evidence.zone != "example.test" {
		t.Fatalf("zone = %q, want the zone that answered", evidence.zone)
	}
	if !evidence.names["mail.example.test"] {
		t.Fatalf("names = %#v", evidence.names)
	}
	joined := strings.Join(evidence.warnings, " ")
	if !strings.Contains(joined, "certspotter") || !strings.Contains(joined, "0 of 10") {
		t.Fatalf("warnings do not report the spent allowance: %q", evidence.warnings)
	}
}

// The names of a host input are certified under the zone the host belongs to, so
// the zone is what the relations point at, and the substitution is stated.
func TestSubdomainTransformAttributesNamesToTheCertificateZone(t *testing.T) {
	queries := 0
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries++
		if queries == 1 {
			// An index that validates its input refuses a host that is not a
			// zone, which is what crt.name does.
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, "mail.example.test\nwww.example.test\n")
	}))
	defer httpServer.Close()

	engine := &server{transport: &http.Transport{}}
	engine.certificateIndexList = func(string) []certificateSource {
		return []certificateSource{{name: "crt.name", query: httpServer.URL + "/v1/search", accept: "text/plain", page: readLineNames}}
	}
	// The wildcard probe and the brute force must not depend on real DNS: the
	// resolver is offline and the wordlist is pinned to one name.
	offlineResolver(t)
	result, err := engine.runOSINTTransform(context.Background(), osintTransformInput{
		Transform:      subdomainTransform,
		Value:          "www.example.test",
		ConfirmNetwork: true,
		Options:        map[string]interface{}{"words": []interface{}{"no-such-host-for-tests"}},
	})
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if result.Metadata["cert_input"] != "www.example.test" {
		t.Fatalf("cert_input = %#v", result.Metadata["cert_input"])
	}
	if result.Metadata["cert_zone"] != "example.test" {
		t.Fatalf("cert_zone = %#v", result.Metadata["cert_zone"])
	}

	domains := map[string]map[string]interface{}{}
	subdomains := []string{}
	for _, item := range result.Entities {
		switch item.Type {
		case "domain":
			domains[item.Identity] = item.Properties
		case "subdomain":
			subdomains = append(subdomains, item.Identity)
		}
	}
	// The queried host stays a domain of its own, and the zone the indexes
	// hold is recorded as the domain the names are certified under.
	if _, ok := domains["www.example.test"]; !ok {
		t.Fatalf("the queried host is not a domain: %#v", domains)
	}
	if role, ok := domains["example.test"]["role"]; !ok || role != "certificate_zone" {
		t.Fatalf("the certificate zone is not a domain: %#v", domains)
	}
	if len(subdomains) != 2 {
		t.Fatalf("subdomains = %#v", subdomains)
	}
	relations := 0
	for _, item := range result.Relations {
		if item.Type != "subdomain_of" {
			continue
		}
		relations++
		// Every name is certified under the zone the indexes hold, including
		// the queried host itself, which is a subdomain of that zone.
		if item.Target != "example.test" {
			t.Fatalf("a relation points at %q instead of the zone: %#v", item.Target, item)
		}
		if item.Source == "www.example.test" && item.Provenance["source"] != "certificate_transparency" {
			t.Fatalf("the queried host is not attributed to the certificate index: %#v", item)
		}
	}
	if relations != len(subdomains) {
		t.Fatalf("relations = %d for %d subdomains", relations, len(subdomains))
	}
	// The substitution is stated, so nobody reads a parent zone's names as
	// subdomains of the host they asked about.
	joined := strings.Join(result.Warnings, " ")
	for _, fragment := range []string{"www.example.test", "example.test"} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("warnings %q do not name %q", result.Warnings, fragment)
		}
	}
}
