package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// publicIndexFixture serves one local answer per request path and records what
// the transforms actually asked for, so the query, the header and the credential
// handling are asserted without a third party.
type publicIndexFixture struct {
	// mutex guards the recorded requests. The certificate chain queries its
	// indexes concurrently, and the handler that records them would otherwise be
	// the data race instead of the code under test.
	mutex    sync.Mutex
	bodies   map[string]string
	statuses map[string]int
	requests []string
	// keys records the credential header of every request. The vendor names them
	// differently on purpose — `API-Key` for urlscan, `X-Api-Key` for filescan —
	// so one list records both and a test can assert the one that belongs to the
	// transform it is exercising.
	keys  []string
	users []string
}

func (fixture *publicIndexFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	fixture.mutex.Lock()
	fixture.requests = append(fixture.requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
	fixture.users = append(fixture.users, r.Header.Get("User-Agent"))
	fixture.keys = append(fixture.keys, r.URL.Path+"|"+r.Header.Get("API-Key")+"|"+r.Header.Get("X-Api-Key"))
	fixture.mutex.Unlock()
	if status, ok := fixture.statuses[r.URL.Path]; ok {
		w.WriteHeader(status)
		return
	}
	answer, ok := fixture.bodies[r.URL.Path]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// A batch lookup is answered from the request body, so the fixture can prove
	// that the transform really sent a list rather than one identity per call.
	if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/api/reputation/") {
		var requested []string
		if json.Unmarshal(body, &requested) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		answer = fixture.batchAnswer(r.URL.Path, requested, answer)
	}
	_, _ = io.WriteString(w, answer)
}

// batchAnswer answers a batch lookup from the template, substituting the
// requested identities, so a test sees exactly the identities that were sent.
func (fixture *publicIndexFixture) batchAnswer(path string, requested []string, template string) string {
	var record map[string]interface{}
	if json.Unmarshal([]byte(template), &record) != nil {
		return template
	}
	verdict, _ := record["overall_verdict"].(string)
	answer := make([]map[string]interface{}, 0, len(requested))
	for _, value := range requested {
		kind := "ip"
		if strings.Contains(path, "/domain") {
			kind = "domain"
		}
		answer = append(answer, map[string]interface{}{
			"ioc_type": kind, "ioc_value": value, "overall_verdict": verdict,
			"mdcloud":          map[string]interface{}{"scan_time": "2026-09-20T08:00:00.000", "detected": 2},
			"filescan_reports": []map[string]string{{"verdict": "malicious"}, {"verdict": "suspicious"}},
		})
	}
	encoded, _ := json.Marshal(answer)
	return string(encoded)
}

func (fixture *publicIndexFixture) asked(substr string) bool {
	fixture.mutex.Lock()
	defer fixture.mutex.Unlock()
	for _, request := range fixture.requests {
		if strings.Contains(request, substr) {
			return true
		}
	}
	return false
}

// splitCredential splits a recorded "path|API-Key|X-Api-Key" row.
func splitCredential(record string) (string, string, string) {
	parts := strings.SplitN(record, "|", 3)
	for len(parts) < 3 {
		parts = append(parts, "")
	}
	return parts[0], parts[1], parts[2]
}

func (fixture *publicIndexFixture) requestCount() int {
	fixture.mutex.Lock()
	defer fixture.mutex.Unlock()
	return len(fixture.requests)
}

func newPublicIndexFixture(t *testing.T) (*httptest.Server, *publicIndexFixture) {
	t.Helper()
	fixture := &publicIndexFixture{
		bodies:   map[string]string{},
		statuses: map[string]int{},
	}
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)
	return server, fixture
}

// urlscanScanFixture is one public page scan. The host and apex are parameters
// so a test can put a name under the queried zone and one outside it, which is
// the case the zone filter exists for.
// TestSubdomainsReadsHistoricalRecordsFromThePassiveDNSIndex is the source that
// closed the measured gap against subfinder.
//
// Measured on `pravda.ru` 2026-10-01: certificate transparency indexes, public
// page scans and DNS guessing together produced 148 names and **missed**
// `ns1.pravda.ru` and `ns2.pravda.ru`, which subfinder found. The passive-DNS
// index returned both on its first record page, because they are *historical* NS
// records — a decommissioned host leaves them behind, and no live index
// publishes what is no longer assigned. That is why this source is here: it
// answers for the names the others structurally cannot see.
//
// The test also holds the two properties that would make such an index
// dangerous: a name outside the zone is not taken, and a rate-limited answer is
// a **named refusal**, never an empty one.
func TestSubdomainsReadsHistoricalRecordsFromThePassiveDNSIndex(t *testing.T) {
	fixtureServer, fixture := newPublicIndexFixture(t)
	fixture.bodies["/pdns_forward"] = `{"status":"ok","records":[
		{"rrname":"example.test","rrdata":"203.0.113.10","rrtype":"A","time_last":1700000000},
		{"rrname":"example.test","rrdata":"ns1.example.test","rrtype":"NS","time_last":1400000000},
		{"rrname":"example.test","rrdata":"ns2.example.test","rrtype":"NS","time_last":1400000000},
		{"rrname":"MX.example.test.","rrdata":"10 mail.example.test","rrtype":"MX","time_last":1300000000},
		{"rrname":"example.test","rrdata":"203.0.113.77","rrtype":"A","time_last":1700000000},
		{"rrname":"other.test","rrdata":"203.0.113.99","rrtype":"A","time_last":1700000000},
		{"rrname":"example.test","rrdata":"ns9.foreign.test","rrtype":"NS","time_last":1400000000}
	]}`
	engine := &server{
		transport: &http.Transport{}, urlscanBase: fixtureServer.URL,
		robtexBase:           fixtureServer.URL,
		certificateIndexList: certificateChainStub(fixtureServer.URL),
	}
	result, err := engine.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "subdomains", Value: "example.test", ConfirmNetwork: true,
		Options: map[string]interface{}{"words": []interface{}{"no-such-name-for-tests"}},
	})
	if err != nil {
		t.Fatalf("subdomains transform: %v", err)
	}
	names := map[string]bool{}
	for _, item := range result.Entities {
		if item.Type == "subdomain" {
			names[item.Identity] = true
		}
	}
	// The names live in `rrdata` — the value of an NS or MX record is a host, and
	// the `rrname` of a query about the zone is the zone itself. An MX value is
	// `10 mail.example.test`, so the priority is not part of the name. A trailing
	// dot and an upper-case name are normal in a zone file and must not make a
	// name a miss.
	for _, want := range []string{"ns1.example.test", "ns2.example.test", "mx.example.test", "mail.example.test"} {
		if !names[want] {
			t.Errorf("%s is missing: the passive-DNS index answered it and nothing else could", want)
		}
	}
	// An address is not a name. Reading `rrdata` of an A record as a hostname
	// would put `203.0.113.77` in the subdomain set.
	for _, item := range result.Entities {
		if item.Type == "subdomain" && net.ParseIP(item.Identity) != nil {
			t.Errorf("an address was added as a subdomain: %q", item.Identity)
		}
	}
	if names["other.test"] || names["ns9.foreign.test"] {
		t.Error("a name outside the zone was added as a subdomain")
	}
	if result.Metadata["robtex_records"] != 7 {
		t.Errorf("robtex_records = %v, want 7 — the whole answer, not only the part taken",
			result.Metadata["robtex_records"])
	}
	// Two rejected: the foreign `rrname` and the foreign NS value. The count is
	// what makes "the index answered 7, we took 4" checkable.
	if result.Metadata["robtex_outside_zone"] != 2 {
		t.Errorf("robtex_outside_zone = %v, want 2 — the foreign rrname and the foreign NS value",
			result.Metadata["robtex_outside_zone"])
	}

	// The free tier allows ten requests an hour. A 429 has to be a named refusal
	// that says what the limit is, because an empty answer and a refused one are
	// opposite claims about the same run.
	limitedServer, limited := newPublicIndexFixture(t)
	limited.bodies["/pdns_forward"] = `{"status":"ratelimited","ip":"203.0.113.7"}`
	limited.statuses["/pdns_forward"] = http.StatusTooManyRequests
	refused := &server{
		transport: &http.Transport{}, urlscanBase: limitedServer.URL,
		robtexBase:           limitedServer.URL,
		certificateIndexList: certificateChainStub(limitedServer.URL),
	}
	refusedResult, err := refused.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "subdomains", Value: "example.test", ConfirmNetwork: true,
		Options: map[string]interface{}{"words": []interface{}{"no-such-name-for-tests"}},
	})
	if err != nil {
		t.Fatalf("subdomains transform on a limited index: %v", err)
	}
	joined := strings.Join(refusedResult.Warnings, " | ")
	if !strings.Contains(joined, "10 requests per hour") {
		t.Errorf("a rate-limited source did not name the limit: %v", refusedResult.Warnings)
	}
	if !strings.Contains(joined, "not read") {
		t.Errorf("a rate-limited source was reported as if it had answered nothing: %v", refusedResult.Warnings)
	}
}

// TestSubdomainsReadsTheThreatIntelligenceIndexes is the third source class, and
// the one that closed the measured comparison with subfinder.
//
// subfinder's JSON output records which source produced each name, and the ten
// names it found that nothing here found came from exactly three indexes, none of
// them certificate indexes: `thc` (a threat feed's own DNS sightings),
// `hudsonrock` (hostnames of
// machines caught by infostealers). A host that only ever appeared in an
// infostealer log has no certificate, no page scan and no live DNS record, so no
// amount of querying the sources we already had could have found it.
//
// The fixtures are the upstream's own contracts, read from its source rather than
// guessed: `thc` posts `{domain, page_state, limit}` and answers
// `domains[].domain`; `hudsonrock` GETs `urls-by-domain?domain=` and answers
// `data.employees_urls` / `data.clients_urls` as **full URLs**, so the host has to
// be parsed out of them. `sitedossier` GETs `/parentdomain/<domain>` and was
// page of hostnames.
func TestSubdomainsReadsTheThreatIntelligenceIndexes(t *testing.T) {
	fixtureServer, fixture := newPublicIndexFixture(t)
	fixture.bodies["/api/v1/lookup/subdomains"] = `{"comment":"Free Service!","processed_domain":"example.test",
		"matching_records":3,"domains":[
			{"domain":"example.test","last_seen_on":"2026-09-30"},
			{"domain":"gw.example.test","last_seen_on":"2024-12-11"},
			{"domain":"strelka.example.test","last_seen_on":"2024-12-11"}]}`
	fixture.bodies["/parentdomain/example.test"] = `<html><body>
		<a href="/v2.example.test"><b>next</b></a>beta.example.test
		www.english.example.test v2.example.test
		<span>not a hostname: example.test</span>
		</body></html>`
	fixture.bodies["/api/json/v2/osint-tools/urls-by-domain"] = `{"message":"...","data":{
		"employees_urls":[],
		"clients_urls":[
			{"occurrence":11,"type":"client","url":"https://engforum.example.test/index.php"},
			{"occurrence":3,"type":"client","url":"https://dev.example.test:8443/path"},
			{"occurrence":1,"type":"client","url":"https://elsewhere.test/x"}]}}`

	engine := &server{
		transport: &http.Transport{}, urlscanBase: fixtureServer.URL,
		robtexBase: fixtureServer.URL,
		passiveIntelBase: map[string]string{
			"thc": fixtureServer.URL, "hudsonrock": fixtureServer.URL,
		},
		certificateIndexList: certificateChainStub(fixtureServer.URL),
	}
	result, err := engine.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "subdomains", Value: "example.test", ConfirmNetwork: true,
		Options: map[string]interface{}{"words": []interface{}{"no-such-name-for-tests"}},
	})
	if err != nil {
		t.Fatalf("subdomains transform: %v", err)
	}
	names := map[string]bool{}
	for _, item := range result.Entities {
		if item.Type == "subdomain" {
			names[item.Identity] = true
		}
	}
	for _, want := range []string{
		"gw.example.test", "strelka.example.test", // thc
		"engforum.example.test", "dev.example.test", // hudsonrock, parsed out of a full URL
	} {
		if !names[want] {
			t.Errorf("%s is missing: a threat-intelligence index answered it and no other source could",
				want)
		}
	}
	// A host outside the zone is not a subdomain of anything here, and a port in
	// a URL is not part of the name.
	if names["elsewhere.test"] {
		t.Error("a name outside the zone was added as a subdomain")
	}
	for _, item := range result.Entities {
		if item.Type == "subdomain" && strings.Contains(item.Identity, ":") {
			t.Errorf("a URL's port was kept in the name: %q", item.Identity)
		}
	}
	// Each index is counted on its own, so "the run found more" can be traced to
	// the index that actually answered rather than to a total.
	// `sitedossier` тут немає: його ендпоінт `/parentdomain/<zone>` прибрано
	// 2026-10-03 після виміру — сервер живий, але цей шлях віддає 404 на
	// будь-який клієнтський агент. Лічильник лишається окремо по кожному
	// джерелу, тож зникнення одного з них видно, а не губиться у totals.
	for source, want := range map[string]int{"thc": 2, "hudsonrock": 2} {
		if got := result.Metadata["intel_"+source+"_names"]; got != want {
			t.Errorf("intel_%s_names = %v, want %d", source, got, want)
		}
	}

	// An index that refuses is a named refusal, not a silent zero: an empty
	// answer and a refused one are opposite claims about the same run.
	limitedServer, limited := newPublicIndexFixture(t)
	limited.bodies["/api/v1/lookup/subdomains"] = `{}`
	limited.statuses["/api/v1/lookup/subdomains"] = http.StatusTooManyRequests
	refused := &server{
		transport: &http.Transport{}, urlscanBase: limitedServer.URL,
		robtexBase: limitedServer.URL,
		passiveIntelBase: map[string]string{
			"thc": limitedServer.URL, "hudsonrock": limitedServer.URL,
		},
		certificateIndexList: certificateChainStub(limitedServer.URL),
	}
	refusedResult, err := refused.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "subdomains", Value: "example.test", ConfirmNetwork: true,
		Options: map[string]interface{}{"words": []interface{}{"no-such-name-for-tests"}},
	})
	if err != nil {
		t.Fatalf("subdomains transform with one index refusing: %v", err)
	}
	joined := strings.Join(refusedResult.Warnings, " | ")
	if !strings.Contains(joined, "thc") {
		t.Errorf("the index that refused was not named: %v", refusedResult.Warnings)
	}
	if !strings.Contains(joined, "missing rather than empty") {
		t.Errorf("a refused index was reported as if it had answered nothing: %v", refusedResult.Warnings)
	}
}

func urlscanScanFixture(host, apex, address, asn, server string) map[string]interface{} {
	return map[string]interface{}{
		"task": map[string]interface{}{"url": "https://" + host + "/", "domain": host, "time": "2026-09-01T10:00:00.000Z"},
		"page": map[string]interface{}{
			"url": "https://" + host + "/", "domain": host, "apexDomain": apex,
			"ip": address, "asn": asn, "server": server,
		},
		"stats": map[string]interface{}{"requests": 12},
	}
}

func urlscanSearchBody(scans []map[string]interface{}, total int) string {
	payload, _ := json.Marshal(map[string]interface{}{"results": scans, "total": total})
	return string(payload)
}

// certificateChainStub keeps the subdomain test offline: the certificate
// indexes are not what these tests are about, so they are pointed at a fixture
// that holds nothing.
func certificateChainStub(base string) func(string) []certificateSource {
	return func(string) []certificateSource {
		return []certificateSource{{
			name:   "fixture-empty",
			query:  base + "/cert?apex=",
			accept: "text/plain",
			page:   readLineNames,
		}}
	}
}

func TestUrlscanFeedsSubdomainDiscoveryForTheQueriedZoneOnly(t *testing.T) {
	fixtureServer, fixture := newPublicIndexFixture(t)
	// Three hits: two really under the zone, one belonging to somebody else.
	// urlscan's `domain:` field is a substring match, so the third is what a
	// real answer looks like and accepting it would invent a hierarchy.
	fixture.bodies["/api/v1/search/"] = urlscanSearchBody([]map[string]interface{}{
		urlscanScanFixture("www.example.test", "example.test", "203.0.113.10", "AS64500", "nginx"),
		urlscanScanFixture("cdn.example.test", "example.test", "203.0.113.11", "AS64500", "nginx"),
		urlscanScanFixture("newsdig.other.test", "other.test", "203.0.113.99", "AS64501", "nginx"),
	}, 5000)
	engine := &server{
		transport: &http.Transport{}, urlscanBase: fixtureServer.URL,
		certificateIndexList: certificateChainStub(fixtureServer.URL),
	}

	result, err := engine.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "subdomains", Value: "example.test", ConfirmNetwork: true,
		// One word that cannot resolve keeps the DNS phase out of the way.
		Options: map[string]interface{}{"words": []interface{}{"no-such-name-for-tests"}},
	})
	if err != nil {
		t.Fatalf("subdomains transform: %v", err)
	}
	names := map[string]bool{}
	origins := map[string]string{}
	for _, item := range result.Entities {
		if item.Type != "subdomain" {
			continue
		}
		names[item.Identity] = true
		origins[item.Identity] = fmt.Sprint(item.Provenance["source"])
	}
	for _, want := range []string{"www.example.test", "cdn.example.test"} {
		if !names[want] {
			t.Fatalf("name from the page-scan index is missing: %#v", names)
		}
		if origins[want] != "urlscan_public_search" {
			t.Fatalf("%s provenance = %q, want the index that actually saw it", want, origins[want])
		}
	}
	// The name outside the zone is not a subdomain of anything here.
	if names["newsdig.other.test"] {
		t.Fatalf("a host outside the zone was added as a subdomain: %#v", names)
	}
	// Both rejected and unread are visible, so a thin answer is never read as a
	// complete one.
	if result.Metadata["urlscan_names"] != 2 || result.Metadata["urlscan_read"] != 3 {
		t.Fatalf("urlscan metadata = %#v", result.Metadata)
	}
	if result.Metadata["urlscan_total"] != 5000 {
		t.Fatalf("urlscan_total = %v, want the size of the whole match", result.Metadata["urlscan_total"])
	}
	if result.Metadata["urlscan_outside_zone"] != 1 {
		t.Fatalf("urlscan_outside_zone = %v, want the rejected count", result.Metadata["urlscan_outside_zone"])
	}
	joined := strings.Join(result.Warnings, " | ")
	if !strings.Contains(joined, "outside example.test") {
		t.Fatalf("the zone filter is not reported: %#v", result.Warnings)
	}
}

func TestUrlscanRateLimitDoesNotFailSubdomainDiscovery(t *testing.T) {
	fixtureServer, fixture := newPublicIndexFixture(t)
	fixture.statuses["/api/v1/search/"] = http.StatusTooManyRequests
	engine := &server{
		transport: &http.Transport{}, urlscanBase: fixtureServer.URL,
		certificateIndexList: certificateChainStub(fixtureServer.URL),
	}
	result, err := engine.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "subdomains", Value: "example.test", ConfirmNetwork: true,
		Options: map[string]interface{}{"words": []interface{}{"no-such-name-for-tests"}},
	})
	if err != nil {
		t.Fatalf("one dead source must not fail the discovery: %v", err)
	}
	joined := strings.Join(result.Warnings, " | ")
	if !strings.Contains(joined, "rate limiting") {
		t.Fatalf("the failing source is not named: %#v", result.Warnings)
	}
	// A rate limit is not an empty index, so no count may claim the index answered.
	if _, present := result.Metadata["urlscan_names"]; present {
		t.Fatalf("a source that did not answer left counts behind: %#v", result.Metadata)
	}
}

func TestUrlscanSendsItsKeyOnlyWhenTheEnvironmentHasOne(t *testing.T) {
	t.Setenv("URLSCAN_API_KEY", "")
	fixtureServer, fixture := newPublicIndexFixture(t)
	fixture.bodies["/api/v1/search/"] = urlscanSearchBody(nil, 0)
	engine := &server{
		transport: &http.Transport{}, urlscanBase: fixtureServer.URL,
		certificateIndexList: certificateChainStub(fixtureServer.URL),
	}
	if _, err := engine.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "subdomains", Value: "example.test", ConfirmNetwork: true,
		Options: map[string]interface{}{"words": []interface{}{"no-such-name-for-tests"}},
	}); err != nil {
		t.Fatalf("anonymous discovery: %v", err)
	}
	fixture.mutex.Lock()
	anonymous := append([]string(nil), fixture.keys...)
	fixture.mutex.Unlock()
	for _, record := range anonymous {
		path, apiKey, xAPIKey := splitCredential(record)
		if path == "/api/v1/search/" && (apiKey != "" || xAPIKey != "") {
			t.Fatalf("a key header was sent with no key configured: %q", record)
		}
	}

	keyedServer, keyed := newPublicIndexFixture(t)
	keyed.bodies["/api/v1/search/"] = urlscanSearchBody(nil, 0)
	t.Setenv("URLSCAN_API_KEY", "fixture-key")
	keyedEngine := &server{
		transport: &http.Transport{}, urlscanBase: keyedServer.URL,
		certificateIndexList: certificateChainStub(keyedServer.URL),
	}
	if _, err := keyedEngine.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "subdomains", Value: "example.test", ConfirmNetwork: true,
		Options: map[string]interface{}{"words": []interface{}{"no-such-name-for-tests"}},
	}); err != nil {
		t.Fatalf("keyed discovery: %v", err)
	}
	keyed.mutex.Lock()
	sent := append([]string(nil), keyed.keys...)
	keyed.mutex.Unlock()
	found := false
	for _, record := range sent {
		path, apiKey, _ := splitCredential(record)
		if path != "/api/v1/search/" {
			continue
		}
		if apiKey != "fixture-key" {
			t.Fatalf("configured key was not sent to the index: %q", record)
		}
		found = true
	}
	if !found {
		t.Fatalf("the index was never asked: %#v", sent)
	}
}

func TestUrlscanPageSizeOptionReachesTheIndex(t *testing.T) {
	fixtureServer, fixture := newPublicIndexFixture(t)
	fixture.bodies["/api/v1/search/"] = urlscanSearchBody(nil, 900)
	engine := &server{
		transport: &http.Transport{}, urlscanBase: fixtureServer.URL,
		certificateIndexList: certificateChainStub(fixtureServer.URL),
	}
	if _, err := engine.runOSINTTransform(context.Background(), osintTransformInput{
		Transform: "subdomains", Value: "example.test", ConfirmNetwork: true,
		Options: map[string]interface{}{"size": float64(250), "words": []interface{}{"no-such-name-for-tests"}},
	}); err != nil {
		t.Fatalf("sized discovery: %v", err)
	}
	if !fixture.asked("size=250") {
		t.Fatalf("requested page size did not reach the index: %d requests", fixture.requestCount())
	}
}

// filescanTemplate is one reputation record the fixture serves for whatever
// identities the transform actually asked about.
const filescanTemplate = `{"overall_verdict":"malicious"}`

func TestFilescanMarksTheAddressesTheLookupJustProduced(t *testing.T) {
	fixtureServer, fixture := newPublicIndexFixture(t)
	fixture.bodies["/api/reputation/ip"] = filescanTemplate
	fixture.bodies["/api/reputation/domain"] = filescanTemplate
	engine := &server{transport: &http.Transport{}, filescanBase: fixtureServer.URL}
	client := &http.Client{Transport: &http.Transport{}}

	// The addresses are what a DNS lookup produced, so the identities are fixed
	// here: the offline resolver in TestMain answers NXDOMAIN for everything, and
	// a test that depended on real DNS would be a test of the resolver.
	addresses := []string{"203.0.113.10", "203.0.113.11"}
	ipVerdicts, err := engine.filescanVerdicts(context.Background(), client, "ip", addresses)
	if err != nil {
		t.Fatalf("address reputation: %v", err)
	}
	domainVerdicts, err := engine.filescanVerdicts(context.Background(), client, "domain", []string{"example.test"})
	if err != nil {
		t.Fatalf("domain reputation: %v", err)
	}

	result := &osintTransformResult{Entities: []transformEntity{
		{Type: "domain", Identity: "example.test", Properties: map[string]interface{}{"source": "dns_records"}},
		{Type: "ip", Identity: "203.0.113.10", Properties: map[string]interface{}{"source": "dns_records"}},
		{Type: "ip", Identity: "203.0.113.11", Properties: map[string]interface{}{"source": "dns_records"}},
	}}
	if filescanReputation(result, ipVerdicts, "ips_marked") != 2 {
		t.Fatalf("addresses marked = %d, want 2", result.Metadata["filescan_ips_marked"])
	}
	if filescanReputation(result, domainVerdicts, "domains_marked") != 1 {
		t.Fatalf("domains marked = %d, want 1", result.Metadata["filescan_domains_marked"])
	}
	marked := 0
	for _, item := range result.Entities {
		if item.Properties["filescan_verdict"] == nil {
			continue
		}
		marked++
		if item.Properties["filescan_flagged"] != true {
			t.Fatalf("%s flag = %v", item.Identity, item.Properties["filescan_flagged"])
		}
		if item.Properties["filescan_malicious"] != 1 || item.Properties["filescan_suspicious"] != 1 {
			t.Fatalf("%s tally = %#v", item.Identity, item.Properties)
		}
		if item.Provenance["filescan_ioc_type"] == nil {
			t.Fatalf("%s lost its provenance: %#v", item.Identity, item.Provenance)
		}
		// A verdict is somebody else's claim about a host, so it lands beside the
		// identity's own source and never replaces it: the address still came
		// from the DNS lookup.
		if item.Properties["source"] != "dns_records" {
			t.Fatalf("the verdict replaced the identity's own provenance: %#v", item.Properties)
		}
	}
	if marked != 3 {
		t.Fatalf("marked %d identities, want all three", marked)
	}
	// One request per kind, not one per identity: the batch endpoint is what
	// keeps this from being a loop whose size the operator has to guess.
	if fixture.requestCount() != 2 {
		t.Fatalf("reputation took %d requests, want one batch per kind: %#v", fixture.requestCount(), fixture.requests)
	}
	// An identity the index holds nothing for is left exactly as it was, so
	// "no public record" and "not asked" cannot look alike.
	untouched := &osintTransformResult{Entities: []transformEntity{
		{Type: "ip", Identity: "198.51.100.5", Properties: map[string]interface{}{"source": "dns_records"}},
	}}
	filescanReputation(untouched, ipVerdicts, "ips_marked")
	if untouched.Entities[0].Properties["filescan_verdict"] != nil {
		t.Fatalf("an identity with no record was marked anyway: %#v", untouched.Entities[0].Properties)
	}
}

func TestDNSRecordsReportsWhenNothingResolved(t *testing.T) {
	engine := &server{transport: &http.Transport{}}
	result := &osintTransformResult{}
	// The offline resolver in TestMain answers NXDOMAIN, which is the "nothing
	// resolved" branch: there is no identity to ask a reputation for, and the
	// run says so instead of asking anyway.
	if err := engine.runDNSRecords(context.Background(), result, osintTransformInput{
		Value: "no-such-host-for-tests.test", ConfirmNetwork: true,
	}); err != nil {
		t.Fatalf("dns_records transform: %v", err)
	}
	joined := strings.Join(result.Warnings, " | ")
	if !strings.Contains(joined, "no address resolved") {
		t.Fatalf("an unresolved host is not reported: %#v", result.Warnings)
	}
}

func TestFilescanSendsItsOwnKeyHeaderAndOmitsItOtherwise(t *testing.T) {
	t.Setenv("FILESCAN_API_KEY", "")
	fixtureServer, fixture := newPublicIndexFixture(t)
	fixture.bodies["/api/reputation/ip"] = filescanTemplate
	engine := &server{transport: &http.Transport{}, filescanBase: fixtureServer.URL}
	if _, err := engine.filescanVerdicts(context.Background(), &http.Client{Transport: &http.Transport{}}, "ip", []string{"203.0.113.10"}); err != nil {
		t.Fatalf("anonymous lookup: %v", err)
	}
	fixture.mutex.Lock()
	anonymous := append([]string(nil), fixture.keys...)
	fixture.mutex.Unlock()
	for _, record := range anonymous {
		path, apiKey, xAPIKey := splitCredential(record)
		if path == "/api/v1/search/" && (apiKey != "" || xAPIKey != "") {
			t.Fatalf("a key header was sent with no key configured: %q", record)
		}
	}

	keyedServer, keyed := newPublicIndexFixture(t)
	keyed.bodies["/api/reputation/ip"] = filescanTemplate
	t.Setenv("FILESCAN_API_KEY", "filescan-key")
	keyedEngine := &server{transport: &http.Transport{}, filescanBase: keyedServer.URL}
	if _, err := keyedEngine.filescanVerdicts(context.Background(), &http.Client{Transport: &http.Transport{}}, "ip", []string{"203.0.113.10"}); err != nil {
		t.Fatalf("keyed lookup: %v", err)
	}
	keyed.mutex.Lock()
	sent := append([]string(nil), keyed.keys...)
	keyed.mutex.Unlock()
	for _, record := range sent {
		_, apiKey, xAPIKey := splitCredential(record)
		// The vendor names it X-Api-Key; sending it as API-Key would look like it
		// worked and be ignored.
		if xAPIKey != "filescan-key" || apiKey != "" {
			t.Fatalf("filescan key was not sent as X-Api-Key: %q", record)
		}
	}
}

// The flag must follow the index's own verdict and not be derived from the
// report tally. Measured 2026-09-28 against the live index: 8.8.8.8 answers
// `no_threat` with 207 reports marked `malicious`, so a boolean computed from the
// counts would contradict the verdict printed right beside it.
func TestFilescanFlaggedFollowsTheVendorVerdictNotTheReportCounts(t *testing.T) {
	contradictory := `{"overall_verdict":"no_threat"}`
	fixtureServer, fixture := newPublicIndexFixture(t)
	// The fixture serves the template through batchAnswer, so the tally is
	// rebuilt per identity; this one has to be malicious reports instead.
	fixture.bodies["/api/reputation/ip"] = contradictory
	engine := &server{transport: &http.Transport{}, filescanBase: fixtureServer.URL}
	verdicts, err := engine.filescanVerdicts(context.Background(), &http.Client{Transport: &http.Transport{}}, "ip", []string{"203.0.113.10"})
	if err != nil {
		t.Fatalf("filescan lookup: %v", err)
	}
	verdict := verdicts["203.0.113.10"]
	if verdict.Overall != "no_threat" {
		t.Fatalf("the vendor verdict was not kept as received: %#v", verdict)
	}
	if verdict.flagged() {
		t.Fatalf("no_threat was read as a threat: %#v", verdict)
	}
	for _, threat := range []string{"malicious", "likely_malicious", "suspicious"} {
		if !(filescanVerdict{IOCValue: "x", Overall: threat}).flagged() {
			t.Fatalf("a verdict the index uses as a threat was read as one: %s", threat)
		}
	}
	if (filescanVerdict{Overall: ""}).flagged() || (filescanVerdict{Overall: "some_new_vendor_value"}).flagged() {
		t.Fatal("a verdict that is not a threat was read as one")
	}
}

func TestThePublicIndexesAreNoLongerSeparateTransforms(t *testing.T) {
	// The two APIs are sources inside `subdomains` and `dns_records`, not tools
	// the operator has to remember to run, so they must not be offered as their
	// own transforms. A registry entry here would put them back in the dialog.
	for _, item := range transformRegistry {
		if item["id"] == "urlscan_search" || item["id"] == "filescan_reputation" {
			t.Fatalf("%s is registered as a separate transform", item["id"])
		}
	}
	engine := &server{}
	for _, removed := range []string{"urlscan_search", "filescan_reputation"} {
		if _, err := engine.runOSINTTransform(context.Background(), osintTransformInput{
			Transform: removed, Value: "example.test", ConfirmNetwork: true,
		}); err == nil || !strings.Contains(err.Error(), "UNKNOWN_TRANSFORM") {
			t.Fatalf("%s is still dispatchable: %v", removed, err)
		}
	}
}
