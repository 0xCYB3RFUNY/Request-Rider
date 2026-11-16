package active

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ppTarget is a merging server: it walks the query into a nested object and prints
// it, which is the shape upstream's markers are written for.
type ppTarget struct {
	// merge makes the server copy the parameter into a nested object and echo the
	// result. When false it prints the raw query string instead, which is what a
	// server that never merges looks like.
	merge bool
	// failNames makes the server answer 500 with a prototype-shaped message.
	failNames bool
}

func (p ppTarget) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.RawQuery
		if p.failNames && strings.Contains(query, "__proto__") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			// The wording is upstream's: the clause matches a fixed list of words, so
			// a fixture that used a different sentence would be testing nothing.
			_, _ = w.Write([]byte(`{"error":"Cannot read property 'x' of undefined"}`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		if !p.merge {
			_, _ = w.Write([]byte(`<html><body><p>plain server</p><form method="get">` +
				`<input name="q" value=""></form></body></html>`))
			return
		}
		// The merge: every `a[b][c]` key path becomes a nested object, so a
		// `__proto__[x]` path lands on the prototype rather than on the page.
		merged := mergeQuery(query)
		_, _ = w.Write([]byte(`<html><body><pre id="merged">` + merged +
			`</pre><form method="get"><input name="q" value=""></form></body></html>`))
	})
}

// mergeQuery renders the query as a nested JSON object, which is the observable
// consequence of the merge these probes are written for.
func mergeQuery(query string) string {
	var b strings.Builder
	b.WriteString("{")
	first := true
	for _, pair := range strings.Split(query, "&") {
		key, value, _ := strings.Cut(pair, "=")
		// The last segment of the key path is the key the application would set,
		// which is how a polluted key shows up in an answer that prints the object.
		if cut := strings.LastIndexAny(key, ".["); cut >= 0 {
			key = key[cut+1:]
		}
		key = strings.TrimSuffix(key, "]")
		if !first {
			b.WriteString(", ")
		}
		first = false
		b.WriteString(`"` + key + `":"` + value + `"`)
	}
	b.WriteString("}")
	return b.String()
}

func ppPoint(target string) Point {
	return Point{URL: target, Method: http.MethodGet, Param: "q",
		Values: map[string][]string{"q": {"hello"}}, Source: "query"}
}

func servePP(t *testing.T, server ppTarget) (*httptest.Server, *Transport) {
	t.Helper()
	httpServer := httptest.NewServer(server.handler(t))
	t.Cleanup(httpServer.Close)
	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	return httpServer, transport
}

// TestProtoPollutionReadsTheMarkersOwnAnswer is the first of upstream's three
// clauses, and the one that carries a tier: this run's marker comes back and the
// page did not have it before.
func TestProtoPollutionReadsTheMarkersOwnAnswer(t *testing.T) {
	server, transport := servePP(t, ppTarget{merge: true})
	findings := (ProtoPollution{}).Scan(context.Background(), transport, ppPoint(server.URL),
		&Response{StatusCode: http.StatusOK,
			Body: `<html><body><pre id="merged">{&quot;q&quot;:&quot;hello&quot;}</pre></body></html>`})
	if len(findings) == 0 {
		t.Fatal("no rows on a server that merges the probe's key path and prints the result")
	}
	row := findings[0]
	if row.Tier != TierVerified {
		t.Errorf("tier = %v, want verified: the marker came back and the baseline did not have it",
			row.Tier)
	}
	if !strings.Contains(row.Evidence, "marker") {
		t.Errorf("evidence = %q, want it to name what came back", row.Evidence)
	}
	// And to show the value: a row that says "the marker came back" without naming
	// it cannot be matched to the run that produced it, and the run's canary is the
	// only thing in the evidence that ties the two together.
	marker := ""
	if index := strings.Index(row.Evidence, "rrpp"); index >= 0 {
		marker = strings.Fields(row.Evidence[index:])[0]
		marker = strings.Trim(marker, ".,")
	}
	if !strings.Contains(row.Evidence, marker) || marker == "" {
		t.Errorf("evidence = %q, want this run's marker (%q) in the sentence", row.Evidence, marker)
	}
	if !strings.Contains(row.Payload, "__proto__") && !strings.Contains(row.Payload, "constructor") {
		t.Errorf("payload = %q, want the key path the probe wrote", row.Payload)
	}
	// The value the probe wrote travels with the key: a report that names the key and
	// drops the value cannot be re-fetched, and a re-fetchable row is the whole
	// contract `NewFinding` states for `Payload`.
	if !strings.Contains(row.Payload, "=") {
		t.Errorf("payload = %q, want the key and the value it wrote", row.Payload)
	}
	if row.PoCCurl == "" {
		t.Error("no PoC curl: a row a triager cannot re-fetch is not a finding")
	}
	if !strings.Contains(row.Remediation, "Object.create(null)") {
		t.Errorf("remediation = %q, want the merge-side fix", row.Remediation)
	}
	// The path family walks a different resource, so a run that sends it produces a
	// row whose endpoint is not the surface. That is upstream's third family and it
	// is the only one that is not a parameter, which is why it needs a baseline of
	// its own.
	elsewhere := false
	for _, other := range findings {
		if other.Endpoint != server.URL {
			elsewhere = true
		}
	}
	if !elsewhere {
		t.Errorf("no row for a path probe: %d row(s), all on the surface itself", len(findings))
	}
	// And a shape that pollutes a built-in instead of adding a key is settled by the
	// answer growing that key, not by an echo: the row must exist for it too.
	keys := 0
	for _, other := range findings {
		if strings.Contains(other.Evidence, "pollution key") {
			keys++
		}
	}
	if keys == 0 {
		t.Errorf("no behaviour row on a server that merges a key path and prints the result")
	}
}

// TestProtoPollutionStaysQuietWhereTheProbeChangesNothing is the half that keeps
// the detector off every server that echoes its query string.
func TestProtoPollutionStaysQuietWhereTheProbeChangesNothing(t *testing.T) {
	server, transport := servePP(t, ppTarget{merge: false})
	baseline := &Response{StatusCode: http.StatusOK,
		Body: `<html><body><p>plain server</p></body></html>`}
	if rows := (ProtoPollution{}).Scan(context.Background(), transport, ppPoint(server.URL),
		baseline); len(rows) != 0 {
		t.Fatalf("rows = %d on a server that never merges, want 0: %+v", len(rows), rows)
	}
	// And with no baseline the whole module refuses, like every other here.
	if rows := (ProtoPollution{}).Scan(context.Background(), transport, ppPoint(server.URL), nil); len(rows) != 0 {
		t.Errorf("rows = %d without a baseline, want 0", len(rows))
	}
}

// TestTheServerErrorClauseNeedsTheBaselineToHaveBeenHealthy is the clause upstream
// does not have, and it is the difference between a row and a site-wide false
// positive: a server that answers 500 with a prototype-shaped message to *every*
// request produces a prototype-pollution row on every parameter of the site if the
// clause only looks at the failing request.
func TestTheServerErrorClauseNeedsTheBaselineToHaveBeenHealthy(t *testing.T) {
	server, transport := servePP(t, ppTarget{merge: true, failNames: true})
	healthy := &Response{StatusCode: http.StatusOK, Body: `<html><body><p>ok</p></body></html>`}
	rows := (ProtoPollution{}).Scan(context.Background(), transport, ppPoint(server.URL), healthy)
	// This server both echoes the marker and fails on the prototype-shaped key, so
	// the clause under test is found by what its evidence says rather than by being
	// the first row.
	failed := 0
	for _, row := range rows {
		if strings.Contains(row.Evidence, "HTTP 500") {
			failed++
		}
	}
	if failed == 0 {
		t.Fatalf("no server-error row for a server that fails with a prototype-shaped message "+
			"only when probed: %d row(s) in total", len(rows))
	}
	// The same server, with a baseline that already failed: nothing here is new.
	broken := &Response{StatusCode: http.StatusInternalServerError,
		Body: "Cannot read property 'x' of undefined"}
	rows = (ProtoPollution{}).Scan(context.Background(), transport, ppPoint(server.URL), broken)
	for _, row := range rows {
		// The path family walks a *different* resource, and this module takes that
		// resource's own baseline rather than the surface's — so a failing path probe
		// is still a finding, and it is scoped to the rows that probed this surface.
		if row.Endpoint != server.URL {
			continue
		}
		if strings.Contains(row.Evidence, "HTTP 500") {
			t.Errorf("a server-error row was produced against a surface that already fails on "+
				"its own: %q", row.Evidence)
		}
	}
}

// TestTheTableIsUpstreamsTable is the transcription check for the two families this
// module sends: 14 shapes, in upstream's order, with the query family first.
func TestTheTableIsUpstreamsTable(t *testing.T) {
	if len(ppProbes) != 14 {
		t.Fatalf("probes = %d, want 14: upstream sends 10 query shapes, 3 form and 3 path "+
			"in prototype_pollution.rs, and a table that drifts from it loses a shape",
			len(ppProbes))
	}
	families := map[string]int{}
	for _, probe := range ppProbes {
		families[probe.name]++
		if probe.shape == "" {
			t.Errorf("a probe has no shape")
		}
		if !probe.inPath && !strings.ContainsAny(probe.shape, "[]") &&
			!strings.Contains(probe.shape, ".") && !strings.Contains(probe.shape, "%5B") {
			t.Errorf("%s: shape %q writes no key path at all", probe.name, probe.shape)
		}
	}
	if families["query"] != 10 || families["form"] != 1 || families["path"] != 3 {
		t.Errorf("families = %v, want 10 query, 1 form, 3 path", families)
	}
	// The three shapes that pollute a built-in rather than add a key cannot be
	// settled by an echo, and saying so in the table is what keeps them out of the
	// marker clause.
	for _, probe := range ppProbes {
		if probe.behaviourOnly && probe.value("marker") == "marker" {
			t.Errorf("%s/%s is marked behaviour-only yet writes the marker", probe.name, probe.shape)
		}
	}
	if !strings.Contains(ppNotPorted, "JSON") {
		t.Errorf("the not-ported note does not name the family it is about: %q", ppNotPorted)
	}
	// The JSON table is upstream's too: five shapes, two of them polluting a built-in.
	if len(ppJSONProbes) != 5 {
		t.Fatalf("json probes = %d, want 5: upstream's prototype_pollution.rs declares five "+
			"JSON bodies and a table that drifts from it loses a shape", len(ppJSONProbes))
	}
	for _, probe := range ppJSONProbes {
		if strings.Count(probe.body, "%s") != 1 {
			t.Errorf("%s: body %q must carry exactly one marker slot", probe.name, probe.body)
		}
		if !strings.HasPrefix(strings.TrimSpace(probe.body), "{") &&
			!strings.HasPrefix(strings.TrimSpace(probe.body), "[") {
			t.Errorf("%s: body %q is not a JSON document", probe.name, probe.body)
		}
	}
	if ppNotPorted == "" || !strings.Contains(ppNotPorted, "discover") {
		t.Errorf("the not-ported note does not say what is missing: %q", ppNotPorted)
	}
}

// TestTheJSONFamilyActuallyPostsAJSONBody is the transport half: a merge is a JSON
// body, and a probe that form-encodes it reaches a server that answers "415" and
// reports nothing — a family that looks ported and never runs.
func TestTheJSONFamilyActuallyPostsAJSONBody(t *testing.T) {
	seen := struct {
		contentType string
		body        string
		method      string
	}{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		seen.contentType = r.Header.Get("Content-Type")
		seen.body = string(raw)
		seen.method = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)
	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	body := strings.ReplaceAll(ppJSONProbes[0].body, "%s", "rrprobe")
	before := transport.Requests()
	if _, err := transport.DoBody(context.Background(), http.MethodPost, server.URL+"/api",
		[]byte(body), "application/json", false, nil); err != nil {
		t.Fatalf("DoBody: %v", err)
	}
	// The run's own request count has to include it: a probe that issued a request
	// the report cannot see is a footprint the operator is not shown.
	if transport.Requests() != before+1 {
		t.Errorf("requests = %d, want %d: a body the caller wrote is still a request the run spent",
			transport.Requests(), before+1)
	}
	if seen.contentType != "application/json" {
		t.Errorf("content-type = %q, want application/json", seen.contentType)
	}
	if seen.method != http.MethodPost {
		t.Errorf("method = %q, want POST", seen.method)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(seen.body), &parsed); err != nil {
		t.Fatalf("the server received %q, which is not JSON: %v", seen.body, err)
	}
	if _, ok := parsed["__proto__"]; !ok {
		t.Errorf("the body the server received is %s, which does not carry the key path", seen.body)
	}
}

// TestTheJSONFamilyFiresOnAServerThatMergesABody is the other half of the JSON
// family: a server that merges the posted object and prints it has answered, and a
// family that never fires is a family that looks ported and does nothing.
func TestTheJSONFamilyFiresOnAServerThatMergesABody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if len(raw) == 0 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		// The package's own `escapeHTML` helper: a second one here would be a second
		// answer to the same question in the same test binary.
		_, _ = w.Write([]byte(`<html><body><pre>` + escapeHTML(string(raw)) +
			`</pre><form method="get"><input name="q" value=""></form></body></html>`))
	}))
	t.Cleanup(server.Close)
	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	rows := (ProtoPollution{}).Scan(context.Background(), transport, ppPoint(server.URL),
		&Response{StatusCode: http.StatusOK,
			Body: `<html><body><pre>{"ok":true}</pre></body></html>`})
	jsonRows := 0
	for _, row := range rows {
		if strings.HasPrefix(row.Payload, "{") {
			jsonRows++
		}
	}
	if jsonRows == 0 {
		t.Fatalf("no JSON row on a server that merges the posted body: %d row(s) in total, "+
			"payloads %v", len(rows), payloadsOf(rows))
	}
}

func payloadsOf(rows []Finding) []string {
	var out []string
	for _, row := range rows {
		out = append(out, row.Payload)
	}
	return out
}

// TestAJSONProbeOnAServerThatIgnoresItProducesNoRow. The harvest gives one surface;
// a server that answers the page it would have sent anyway must not read the marker
// as a reflection, or every JSON-capable site becomes a critical.
func TestAJSONProbeOnAServerThatIgnoresItProducesNoRow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><p>same page whatever you post</p></body></html>`))
	}))
	t.Cleanup(server.Close)
	transport, err := NewTransport(http.DefaultTransport, Options{})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	rows := (ProtoPollution{}).Scan(context.Background(), transport, ppPoint(server.URL),
		&Response{StatusCode: http.StatusOK, Body: `<html><body><p>same page whatever you post</p></body></html>`})
	for _, row := range rows {
		if strings.HasPrefix(row.Payload, "{") {
			t.Errorf("a JSON row on a server that ignores the body: %q", row.Payload)
		}
	}
}
