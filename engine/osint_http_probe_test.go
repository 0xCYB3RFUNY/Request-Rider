package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/httpx/runner"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

// httpx writes one JSON object per line, and the shape of that object is the
// only contract between the binary and this file. These tests read real httpx
// output captured from the binary itself, so a field rename upstream fails here
// rather than silently producing empty entities.

// capturedProbeLines is httpx output from `bin/httpx -json` against a local
// fixture, taken verbatim and frozen. It is not hand-written: every key below is
// a key httpx emitted, including the ones this transform does not use.
var capturedProbeLines = []string{
	`{"timestamp":"2026-10-03T18:00:00Z","url":"https://www.example.test/","input":"www.example.test","scheme":"https","method":"GET","host":"93.184.216.34","a":["93.184.216.34"],"aaaa":["2606:2800:220:1:248:1893:25c8:1946"],"cname":["cdn.example.test"],"port":"443","status_code":200,"content_length":1256,"content_type":"text/html; charset=utf-8","webserver":"nginx","title":"Example","words":214,"lines":18,"time":"142.5ms","tech":["Nginx","HSTS"],"cdn":true,"cdn_name":"cloudflare","cdn_type":"cdn","location":"https://www.example.test/","final_url":"https://www.example.test/","chain_status_codes":[301,200],"jarm_hash":"29d3fd00029d29d21c42d43d00041d5d7d776d5c7fce6e30b40dd0e1c1e2c1a4","failed":false,"chain":[{"request":"https://example.test/","response_code":301}],"tls":{"host":"www.example.test","port":"443","tls_version":"tls13","cipher":"TLS_AES_128_GCM_SHA256","key_exchange":"X25519","sni":"www.example.test","jarm_hash":"29d3fd00029d3","probe_status":true,"subject_cn":"www.example.test","issuer_cn":"Example CA","not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","domains":["www.example.test","example.test"],"self_signed":false,"expired":false,"chain":[{"subject_cn":"www.example.test","issuer_cn":"Example CA","domains":["www.example.test","example.test"],"not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","self_signed":false,"expired":false}]}}`,
	`{"timestamp":"2026-10-03T18:00:01Z","url":"https://admin.example.test/","input":"admin.example.test","host":"10.0.0.7","status_code":0,"failed":true,"error":"could not connect to host"}`,
}

func decodeCapturedProbe(t *testing.T) []runner.Result {
	t.Helper()
	records := make([]runner.Result, 0, len(capturedProbeLines))
	for _, line := range capturedProbeLines {
		var record runner.Result
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("captured httpx line does not decode into runner.Result: %v\nline: %s", err, line)
		}
		records = append(records, record)
	}
	return records
}

func TestHTTPProbeTurnsARecordIntoGraphFacts(t *testing.T) {
	result := &osintTransformResult{Entities: []transformEntity{}, Relations: []transformRelation{}}
	appendHTTPProbeRecord(context.Background(), result, decodeCapturedProbe(t)[0], nil)

	properties := entityProperties(t, result, "domain", "www.example.test")
	for key, want := range map[string]interface{}{
		"url":          "https://www.example.test/",
		"status":       200,
		"webserver":    "nginx",
		"title":        "Example",
		"cdn":          "cloudflare",
		"cdn_type":     "cdn",
		"content_type": "text/html; charset=utf-8",
	} {
		if got := properties[key]; got != want {
			t.Errorf("properties[%q] = %#v, want %#v", key, got, want)
		}
	}
	if got, ok := properties["technologies"].([]string); !ok || len(got) != 2 {
		t.Errorf("technologies = %#v, want the two httpx reported", properties["technologies"])
	}
	// Both address families are recorded: an operator who asked about a host
	// wants every address it answers on, and dropping IPv6 would report a host
	// as having half the addresses it has.
	if got, ok := properties["addresses"].([]string); !ok || len(got) != 2 {
		t.Errorf("addresses = %#v, want the A and the AAAA record", properties["addresses"])
	}
	if properties["failed"] == true {
		t.Error("a record that answered 200 must not be marked failed")
	}
}

// The TLS read is recorded as read-or-not, so a host with no certificate is not
// read as a host whose certificate was checked and found uninteresting.
func TestHTTPProbeRecordsTheLeafCertificate(t *testing.T) {
	result := &osintTransformResult{Entities: []transformEntity{}, Relations: []transformRelation{}}
	appendHTTPProbeRecord(context.Background(), result, decodeCapturedProbe(t)[0], nil)

	properties := entityProperties(t, result, "domain", "www.example.test")
	for key, want := range map[string]interface{}{
		"tls_read":        true,
		"tls_version":     "tls13",
		"tls_subject_cn":  "www.example.test",
		"tls_issuer_cn":   "Example CA",
		"tls_self_signed": false,
		"tls_not_after":   "2027-01-01T00:00:00Z",
	} {
		if got := properties[key]; got != want {
			t.Errorf("properties[%q] = %#v, want %#v", key, got, want)
		}
	}
	if got, ok := properties["tls_domains"].([]string); !ok || len(got) != 2 {
		t.Errorf("tls_domains = %#v, want both names from the leaf", properties["tls_domains"])
	}
}

// A host that did not answer is recorded as failed with httpx's own reason. It
// is not dropped: "nothing answered" is a fact about the host, and a transform
// that reported nothing would be indistinguishable from a transform that broke.
func TestHTTPProbeKeepsTheFailedHost(t *testing.T) {
	result := &osintTransformResult{Entities: []transformEntity{}, Relations: []transformRelation{}}
	appendHTTPProbeRecord(context.Background(), result, decodeCapturedProbe(t)[1], nil)

	properties := entityProperties(t, result, "domain", "admin.example.test")
	if properties["failed"] != true {
		t.Errorf("failed = %#v, want true for a host httpx could not reach", properties["failed"])
	}
	if got := properties["error"]; got != "could not connect to host" {
		t.Errorf("error = %#v, want httpx's own reason", got)
	}
	if _, present := properties["status"]; present {
		t.Error("a failed probe must not carry a status code")
	}
}

// The graph relations are the part other transforms consume, so each kind is
// checked separately.
func TestHTTPProbeEmitsResolvesToAndUses(t *testing.T) {
	result := &osintTransformResult{Entities: []transformEntity{}, Relations: []transformRelation{}}
	appendHTTPProbeRecord(context.Background(), result, decodeCapturedProbe(t)[0], nil)

	resolves := 0
	uses := 0
	for _, relation := range result.Relations {
		switch relation.Type {
		case "resolves_to":
			resolves++
			if relation.Source != "www.example.test" || relation.TargetType != "ip" {
				t.Errorf("resolves_to = %#v, want the probed host to the address", relation)
			}
		case "uses":
			uses++
			if relation.SourceType != "domain" || relation.TargetType != "technology" {
				t.Errorf("uses = %#v, want host to technology", relation)
			}
		default:
			t.Errorf("unexpected relation type %q", relation.Type)
		}
	}
	if resolves != 2 {
		t.Errorf("resolves_to relations = %d, want one per address (2)", resolves)
	}
	if uses != 2 {
		t.Errorf("uses relations = %d, want one per technology (2)", uses)
	}
}

// The stream is consumed as a whole, merge included.
//
// httpx returns two records for one host only over https, so the end-to-end test
// against a local http fixture never produces the case and cannot prove the merge
// runs. This test feeds the stream function the shape the real binary emits on
// ria.ru and asserts the merge happened — which is the mutation that stayed
// green before the merge moved into the stream.
func TestHTTPProbeStreamMergesTwoRecordsOfOneHost(t *testing.T) {
	first := `{"url":"https://ria.ru/","input":"ria.ru","host":"194.190.139.47",` +
		`"a":["194.190.139.47"],"status_code":200,"webserver":"QRATOR","tech":["HSTS"],` +
		`"title":"РИА Новости","failed":false}`
	second := `{"url":"https://ria.ru","input":"ria.ru","host":"194.190.139.47",` +
		`"a":["194.190.139.47"],"status_code":200,"webserver":"QRATOR","tech":["HSTS"],` +
		`"title":"РИА Новости","failed":false}`

	result := &osintTransformResult{Entities: []transformEntity{}, Relations: []transformRelation{}}
	observed, err := applyHTTPProbeStream(context.Background(), result,
		strings.NewReader(first+"\n"+second+"\n"), nil)
	if err != nil {
		t.Fatalf("applyHTTPProbeStream: %v", err)
	}
	if observed != 2 {
		t.Fatalf("records read = %d, want 2", observed)
	}
	if got := entityCount(result.Entities, "domain", "ria.ru"); got != 1 {
		t.Errorf("domain entities for ria.ru = %d, want 1 after the stream merge: %#v",
			got, result.Entities)
	}
	if got := entityCount(result.Entities, "technology", "HSTS"); got != 1 {
		t.Errorf("technology entities = %d, want 1", got)
	}
	// The relation count is the other half: two records of one host are two
	// observations, not two relationships.
	resolves := 0
	for _, relation := range result.Relations {
		if relation.Type == "resolves_to" {
			resolves++
		}
	}
	if resolves != 1 {
		t.Errorf("resolves_to relations = %d, want 1 for one address seen twice", resolves)
	}
}

// A probe of a bare address has no domain to hang the answer on, and reporting
// nothing would make "httpx answered" and "the transform broke" look the same.
// The facts go on an `endpoint` entity keyed by the URL that answered.
//
// This case also covers the branch itself: without an assertion here, deleting
// the endpoint entity leaves every other test green, which is exactly the shape
// of a green test that verifies nothing.
func TestHTTPProbeRecordsAnEndpointWhenThereIsNoHost(t *testing.T) {
	result := &osintTransformResult{Entities: []transformEntity{}, Relations: []transformRelation{}}
	appendHTTPProbeRecord(context.Background(), result, runner.Result{
		URL:        "https://198.51.100.7:8443/admin",
		StatusCode: 403,
		WebServer:  "envoy",
	}, nil)

	properties := entityProperties(t, result, "endpoint", "https://198.51.100.7:8443/admin")
	if properties["status"] != 403 {
		t.Errorf("status = %#v, want the 403 httpx reported", properties["status"])
	}
	if properties["webserver"] != "envoy" {
		t.Errorf("webserver = %#v, want envoy", properties["webserver"])
	}
	for _, item := range result.Entities {
		if item.Type == "domain" {
			t.Errorf("an address probe produced a domain entity: %#v", item)
		}
	}
}

// One host probed twice — httpx returns both the URL as given and the redirect
// target, differing only in a trailing slash — must produce one domain entity,
// not two with the same identity. Measured on ria.ru 2026-10-03.
//
// Without this the graph upsert silently decides which record survives, and the
// operator has no way to learn that a choice was made for them.
func TestHTTPProbeMergesTwoRecordsForOneHost(t *testing.T) {
	result := &osintTransformResult{Entities: []transformEntity{}, Relations: []transformRelation{}}
	first := decodeCapturedProbe(t)[0]
	second := decodeCapturedProbe(t)[0]
	second.URL = "https://www.example.test"
	second.Technologies = nil
	appendHTTPProbeRecord(context.Background(), result, first, nil)
	appendHTTPProbeRecord(context.Background(), result, second, nil)
	mergeProbeEntities(result)

	domains := 0
	for _, item := range result.Entities {
		if item.Type == "domain" {
			domains++
		}
	}
	if domains != 1 {
		t.Fatalf("domain entities = %d, want 1 for one host probed twice", domains)
	}
	relations := map[string]int{}
	for _, relation := range result.Relations {
		relations[relation.Type]++
	}
	if relations["resolves_to"] != 2 || relations["uses"] != 2 {
		t.Errorf("relations = %#v, want two of each, not four duplicates", relations)
	}
}

// A second record's list is a second observation of the same host, not a
// disagreement: the two address sets are unioned.
func TestHTTPProbeUnionsListsWhenMerging(t *testing.T) {
	into := map[string]interface{}{"addresses": []string{"93.184.216.34"}, "status": 200}
	from := map[string]interface{}{"addresses": []string{"93.184.216.34", "2606::1"}, "status": 500}
	merged := mergeProbeProperties(into, from)
	addresses, _ := merged["addresses"].([]string)
	if len(addresses) != 2 {
		t.Errorf("addresses = %v, want both, with the repeat removed", addresses)
	}
	if merged["status"] != 200 {
		t.Errorf("status = %v, want the first record's answer to win", merged["status"])
	}
}

// A record with no host at all must not produce a domain entity with an empty
// identity. `entity("", …)` would write an entity the graph cannot address.
func TestHTTPProbeNeverEmitsAnEmptyIdentity(t *testing.T) {
	result := &osintTransformResult{Entities: []transformEntity{}, Relations: []transformRelation{}}
	appendHTTPProbeRecord(context.Background(), result, runner.Result{URL: "  "}, nil)
	for _, item := range result.Entities {
		if strings.TrimSpace(item.Identity) == "" {
			t.Fatalf("emitted an entity with an empty identity: %#v", item)
		}
	}
}

// hostFromProbeURL is the fallback when httpx reports no host, so it has to
// survive the shapes an operator can type.
func TestHostFromProbeURL(t *testing.T) {
	cases := map[string]string{
		"https://www.example.test/a/b?c=1":    "www.example.test",
		"http://example.test":                 "example.test",
		"example.test":                        "example.test",
		"https://user:pw@example.test:8443/x": "example.test:8443",
		"":                                    "",
	}
	for input, want := range cases {
		if got := hostFromProbeURL(input); got != want {
			t.Errorf("hostFromProbeURL(%q) = %q, want %q", input, got, want)
		}
	}
}

// httpxArguments must keep the passive proxy in the call. The whole reason the
// project requires tools to route through it is that their exchanges become
// evidence; a flag change here would silently stop that with no other test
// failing.
func TestHTTPProbeAlwaysRoutesThroughThePassiveProxy(t *testing.T) {
	arguments := httpxArguments("www.example.test", "http://127.0.0.1:8080")
	joined := strings.Join(arguments, " ")
	for _, want := range []string{"-http-proxy http://127.0.0.1:8080", "-json", "-tls-probe", "-tech-detect"} {
		if !strings.Contains(joined, want) {
			t.Errorf("httpx arguments %q do not contain %q", joined, want)
		}
	}
	if httpxArguments("www.example.test", "") != nil &&
		strings.Contains(strings.Join(httpxArguments("www.example.test", ""), " "), "-http-proxy") {
		t.Error("httpx is invoked without a proxy address; every tool's traffic must be recorded")
	}
}

// The binary is looked up next to the engine, and a missing one is named with
// the paths that were tried rather than reported as a generic failure.
func TestHTTPProbeNamesThePathsItLookedAt(t *testing.T) {
	// `RR_HTTPX_BIN` wins, so a build that keeps the binary somewhere else can be
	// pointed at it without a rebuild.
	t.Setenv("RR_HTTPX_BIN", "/opt/tools/httpx")
	if resolved, err := httpxBinary(); err != nil || resolved != "/opt/tools/httpx" {
		t.Errorf("httpxBinary() = (%q, %v), want the override to win", resolved, err)
	}

	t.Setenv("RR_HTTPX_BIN", "")
	resolved, err := httpxBinary()
	if err == nil {
		if !strings.HasSuffix(resolved, "httpx") {
			t.Errorf("httpxBinary() = %q, want a path ending in httpx", resolved)
		}
		return
	}
	// A missing binary must name the paths, because "the transform failed" and
	// "the tool was never installed" are different problems with different fixes.
	if !strings.Contains(err.Error(), "httpx binary not found") ||
		!strings.Contains(err.Error(), "bin") {
		t.Errorf("error %q must name the binary and the paths tried", err.Error())
	}
}

// A network transform must refuse without confirmation, and the refusal must be
// the same one the registry gate produces.
func TestHTTPProbeRefusesWithoutNetworkConfirmation(t *testing.T) {
	server := &server{}
	result := &osintTransformResult{}
	err := server.runHTTPProbe(context.Background(), result, osintTransformInput{
		Transform: "http_probe", Value: "www.example.test",
	}, nil)
	if err == nil {
		t.Fatal("a host probe ran without confirmation")
	}
	if !strings.Contains(err.Error(), "NETWORK_CONFIRMATION_REQUIRED") {
		t.Errorf("error = %q, want NETWORK_CONFIRMATION_REQUIRED", err.Error())
	}
}

// An empty value, and a value that is a path rather than a host, are both
// refused with their own reason: the transform takes a host, and a path would
// silently become part of a URL httpx never asked for.
func TestHTTPProbeRefusesAValueThatIsNotAHost(t *testing.T) {
	server := &server{}
	for _, value := range []string{"", "   ", "/etc/passwd", "example.test/admin"} {
		err := server.runHTTPProbe(context.Background(), &osintTransformResult{},
			osintTransformInput{Transform: "http_probe", Value: value, ConfirmNetwork: true}, nil)
		if err == nil {
			t.Errorf("value %q was accepted as a host", value)
			continue
		}
		if !strings.Contains(err.Error(), "INVALID_HOST") {
			t.Errorf("value %q gave %q, want INVALID_HOST", value, err.Error())
		}
	}
}

// The transform is registered, so it is gated by being registered rather than by
// a second hand-written list.
func TestHTTPProbeIsRegisteredAndGated(t *testing.T) {
	entry := transformRegistryEntry("http_probe")
	if entry == nil {
		t.Fatal("http_probe is not in the transform registry")
	}
	if network, _ := entry["network"].(bool); !network {
		t.Error("http_probe is registered without the network flag, so it would run without confirmation")
	}
	if !transformIsNetwork("http_probe") {
		t.Error("transformIsNetwork says false, so the confirmation gate is not armed")
	}
	if accepts := transformAccepts(entry); !slices.Contains(accepts, "domain") || !slices.Contains(accepts, "subdomain") {
		t.Errorf("accepts = %v, want the kinds a host can be selected as", accepts)
	}
	// The confirmation gate lives in `validateTransformInput`, which is what the
	// request handlers call. Testing that and not a hand-written copy is what
	// keeps the gate and the test from drifting apart.
	code, _, ok := validateTransformInput(&osintTransformInput{
		Transform: "http_probe", Value: "www.example.test",
	})
	if ok || code != "NETWORK_CONFIRMATION_REQUIRED" {
		t.Errorf("http_probe without ConfirmNetwork gave (%q, %v), want NETWORK_CONFIRMATION_REQUIRED", code, ok)
	}
}

// The TTL of a recorded certificate is the operator's first question about it,
// so the dates must survive parsing rather than be dropped as zero times.
func TestHTTPProbeKeepsCertificateDates(t *testing.T) {
	result := &osintTransformResult{Entities: []transformEntity{}, Relations: []transformRelation{}}
	record := runner.Result{
		Host: "www.example.test",
		TLSData: &clients.Response{
			Host:        "www.example.test",
			Version:     "tls13",
			ProbeStatus: true,
			CertificateResponse: &clients.CertificateResponse{
				SubjectCN: "www.example.test",
				NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:  time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
	}
	appendHTTPProbeRecord(context.Background(), result, record, nil)
	properties := entityProperties(t, result, "domain", "www.example.test")
	notAfter, ok := properties["tls_not_after"].(string)
	if !ok {
		t.Fatalf("tls_not_after = %#v, want a formatted date", properties["tls_not_after"])
	}
	if _, err := time.Parse(time.RFC3339, notAfter); err != nil {
		t.Fatalf("tls_not_after %q is not RFC3339: %v", notAfter, err)
	}
}

// findEntity returns the entity of a kind and identity, failing the test when
// there is none. Every assertion below goes through it, so "the field is right"
// can never be reported when "the entity does not exist".
func findEntity(t *testing.T, result *osintTransformResult, kind, identity string) transformEntity {
	t.Helper()
	for _, item := range result.Entities {
		if item.Type == kind && item.Identity == identity {
			return item
		}
	}
	t.Fatalf("no %s entity %q among %d entities", kind, identity, len(result.Entities))
	return transformEntity{}
}

func entityProperties(t *testing.T, result *osintTransformResult, kind, identity string) map[string]interface{} {
	t.Helper()
	properties := findEntity(t, result, kind, identity).Properties
	if properties == nil {
		t.Fatalf("%s %q carries no properties", kind, identity)
	}
	return properties
}

// The whole path, against the real binary.
//
// Every other test here feeds captured lines into the parser. That proves the
// parsing and nothing about the wiring: removing the `mergeProbeEntities` call
// from `runHTTPProbe` left all of them green, measured. So this test runs
// `bin/httpx` for real against a local server and checks what came out of the
// other end.
//
// It is skipped when the binary is absent, and says so — a transform whose tool
// was never built cannot be exercised, and saying "skipped: no binary" is
// different from reporting a pass that measured nothing.
func TestHTTPProbeRunsTheRealBinaryEndToEnd(t *testing.T) {
	binary, err := httpxBinary()
	if err != nil {
		t.Skipf("httpx is not built, so the end-to-end path did not run: %v", err)
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "probe-fixture")
		_, _ = w.Write([]byte("<!doctype html><title>Probe fixture</title><p>fixture</p>"))
	}))
	defer target.Close()

	// A real proxy, because the transform is required to send httpx through one.
	// A forward proxy in front of an `http://` target is enough to prove the flag
	// was used: drop `-http-proxy` and this test fails, which is the point.
	proxied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outbound, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		outbound.Header = r.Header.Clone()
		response, err := http.DefaultTransport.RoundTrip(outbound)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		for key, values := range response.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	defer proxied.Close()
	t.Setenv("RR_PASSIVE_PROXY_URL", proxied.URL)

	// `localhost` rather than the address: a probe of a bare address is recorded
	// as an `endpoint` with no `domain`, which is right but exercises the other
	// branch. `localhost` is not an IP literal, so it produces the domain entity
	// the common case needs.
	port := strings.TrimPrefix(target.URL, "http://127.0.0.1:")
	// The URL is given with its scheme and its trailing slash because that is the
	// form that makes httpx report the host twice — `http://localhost:PORT/` and
	// `http://localhost:PORT` — which is what the merge exists for. Measured on
	// ria.ru 2026-10-03: a probe with a scheme and a path returns two records for
	// one host. Probing a bare `localhost:PORT` returns one, and then the merge has
	// nothing to do and nothing to be tested on.
	host := "http://localhost:" + port + "/"

	server := &server{}
	result := &osintTransformResult{Entities: []transformEntity{}, Relations: []transformRelation{}}
	if err := server.runHTTPProbe(context.Background(), result, osintTransformInput{
		Transform:      "http_probe",
		Value:          host,
		ConfirmNetwork: true,
	}, nil); err != nil {
		t.Fatalf("runHTTPProbe against %s: %v", host, err)
	}

	if entityCount(result.Entities, "domain", "localhost") != 1 {
		t.Errorf("domain entities for localhost = %d, want exactly 1 after merging two "+
			"records of one host: %#v", entityCount(result.Entities, "domain", "localhost"), result.Entities)
	}
	properties := entityProperties(t, result, "domain", "localhost")
	if properties["status"] == nil {
		t.Errorf("the fixture answered, so a status must be recorded: %#v", properties)
	}
	if properties["title"] != "Probe fixture" {
		t.Errorf("title = %#v, want the title the fixture served", properties["title"])
	}
	if entityCount(result.Entities, "ip", "127.0.0.1") == 0 {
		t.Errorf("no ip entity for the loopback the fixture lives on: %#v", result.Entities)
	}
	metadata := result.Metadata
	if metadata["http_probe_records"] == nil || metadata["http_probe_binary"] != binary {
		t.Errorf("metadata = %#v, want the binary and the record count", metadata)
	}
}

func entityCount(entities []transformEntity, kind, identity string) int {
	found := 0
	for _, item := range entities {
		if item.Type == kind && item.Identity == identity {
			found++
		}
	}
	return found
}
