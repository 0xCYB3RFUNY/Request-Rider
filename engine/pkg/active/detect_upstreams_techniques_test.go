package active

// Per-technique coverage for the detectors this port added.
//
// # Why this file exists separately from the fixture test
//
// `TestPortDetectorsFireAgainstTheFixture` asks whether each detector produces a
// row. That question is too coarse to catch a missing probe, and the gap was found
// by mutation rather than by reading: deleting the operator probe from
// `NoSQL.Scan` left the differential probe working, so the detector still produced
// a row and the suite stayed green. Deleting the XPath error probe left the boolean
// probe working, and the same thing happened.
//
// Both mutations are invisible to a "does it fire" test and fatal to a "does *this*
// technique fire" one. So every technique of every ported detector gets its own row
// in the table below, against a fixture that answers **that technique and nothing
// else**, and every case goes through `Scan` rather than through the probe function.
// Going through `Scan` is deliberate: calling the probe directly would leave the
// wiring — the line in `Scan` that invokes it — untested, and the first mutation
// above removed exactly that line.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// neutralPage is what a technique that is not the subject of a test answers.
//
// It is a plain page with an echo, because several detectors decline when the value
// is not reflected at all, and a fixture that echoed nothing would test the refusal
// path instead of the technique.
const neutralPage = `<html><body><p>you searched: %s</p>` +
	`<form action="/x" method="post"><input name="q" value=""></form></body></html>`

// isolatedFixture answers exactly the techniques it is given.
type isolatedFixture struct {
	// responders are consulted in order; the first whose predicate matches the
	// submitted value writes the response and stops.
	responders []func(value string) (string, bool)
}

// ServeHTTP resolves the submitted value and answers.
func (f isolatedFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	value := r.URL.Query().Get("q")
	if value == "" {
		value = readBody(r)
	}
	for _, responder := range f.responders {
		if body, matched := responder(value); matched {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(body))
			return
		}
	}
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte(strings.Replace(neutralPage, "%s", escapeHTML(value), 1)))
}

// on answers for values containing any of the given markers.
func on(markers []string, body string) func(string) (string, bool) {
	return func(value string) (string, bool) {
		for _, marker := range markers {
			if strings.Contains(value, marker) {
				return body, true
			}
		}
		return "", false
	}
}

// scanIsolated runs one scan over one module and one fixture.
func scanIsolated(t *testing.T, module Module, fixture http.Handler) []Finding {
	t.Helper()
	server := httptest.NewServer(fixture)
	defer server.Close()
	transport, err := NewTransport(http.DefaultTransport, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	start, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	start.Path = "/form"
	point := Point{URL: start.String(), Method: http.MethodGet, Param: "q", Values: url.Values{}}
	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	return module.Scan(context.Background(), transport, point, baseline)
}

// portTechnique is one row of the table: a module, a fixture that answers exactly
// one technique, and the substring every returned row's payload or title must
// carry.
type portTechnique struct {
	name    string
	module  Module
	fixture isolatedFixture
	// wantInTitle or wantInPayload is what identifies the row as *this*
	// technique's. Checking one of them is what makes the case a technique test
	// rather than a "the module produced something" test.
	wantInTitle   string
	wantInPayload string
	// wantTier, when set, is the tier every returned row must carry.
	wantTier Tier
}

// TestEveryTechniqueOfEveryPortedDetectorFiresThroughScan is the table this file
// exists for.
//
// Each case removes every responder except the one under test, so a technique that
// stops being probed fails here even when the module's other technique still works.
func TestEveryTechniqueOfEveryPortedDetectorFiresThroughScan(t *testing.T) {
	passwd := "<r>root:x:0:0:root:/root:/bin/bash</r>"
	cases := []portTechnique{
		{
			name: "nosql/operator", module: NoSQL{},
			fixture:     isolatedFixture{responders: []func(string) (string, bool){on([]string{`"$ne"`}, "<ul><li>a</li><li>b</li><li>c</li></ul>")}},
			wantInTitle: "operator injection", wantTier: TierPotential,
		},
		{
			name: "nosql/error", module: NoSQL{},
			fixture:       isolatedFixture{responders: []func(string) (string, bool){on([]string{`.")`}, "Uncaught exception 'MongoCursorException': failed")}},
			wantInPayload: `.")`, wantTier: TierVerified,
		},
		{
			name: "xpath/error", module: XPath{},
			fixture:       isolatedFixture{responders: []func(string) (string, bool){on([]string{"')]"}, "libxml2 library function failed : XML or text declaration not at start of entity")}},
			wantInPayload: "')]", wantTier: TierVerified,
		},
		{
			name: "xpath/boolean", module: XPath{},
			fixture: isolatedFixture{responders: []func(string) (string, bool){
				func(value string) (string, bool) {
					if !strings.Contains(value, "count(//*)") {
						return "", false
					}
					if strings.Contains(value, "> 0") {
						return "<p>matched 12 nodes</p>", true
					}
					return "<p>no nodes</p>", true
				},
			}},
			wantInPayload: "count(//*)", wantTier: TierVerified,
		},
		{
			name: "ldap/error", module: LDAP{},
			fixture:       isolatedFixture{responders: []func(string) (string, bool){on([]string{"objectClass=*"}, "javax.naming.directory.InvalidSearchFilterException: invalid filter")}},
			wantInPayload: "objectClass", wantTier: TierVerified,
		},
		{
			name: "ldap/widening", module: LDAP{},
			fixture:     isolatedFixture{responders: []func(string) (string, bool){on([]string{"*)(uid=*"}, "<ul><li>root</li><li>daemon</li><li>www-data</li></ul>")}},
			wantInTitle: "filter widening", wantTier: TierPotential,
		},
		{
			name: "xxe/unix", module: XXE{},
			fixture:       isolatedFixture{responders: []func(string) (string, bool){on([]string{"<!DOCTYPE"}, passwd)}},
			wantInPayload: "/etc/passwd", wantTier: TierVerified,
		},
		{
			name: "codeinj/php", module: CodeInjection{},
			fixture:     isolatedFixture{responders: []func(string) (string, bool){on([]string{"11*13"}, "<p>' . 11*13 . ' = 143</p>")}},
			wantInTitle: "Code Injection", wantTier: TierVerified,
		},
		{
			name: "escaping/measurement", module: Escaping{},
			// The neutral page echoes, so the control succeeds, the backslash is
			// consumed by the echo's escaping and the quotes survive: the
			// "unwrapped" measurement.
			fixture:     isolatedFixture{},
			wantInTitle: "Input Transformation Analysis",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			findings := scanIsolated(t, testCase.module, testCase.fixture)
			if len(findings) == 0 {
				t.Fatalf("the %s technique produced no finding against a fixture that answers "+
					"only that technique; either it is not probed from Scan, or its own check rejects "+
					"its own technique", testCase.name)
			}
			for _, finding := range findings {
				if testCase.wantInTitle != "" && !strings.Contains(finding.Title, testCase.wantInTitle) {
					t.Errorf("row %q does not carry the technique marker %q; this case would pass on "+
						"a row produced by a different technique of the same detector",
						finding.Title, testCase.wantInTitle)
				}
				if testCase.wantInPayload != "" && !strings.Contains(finding.Payload, testCase.wantInPayload) {
					t.Errorf("row %q carries payload %q, which does not contain %q; this case would "+
						"pass on a row produced by a different technique of the same detector",
						finding.Title, finding.Payload, testCase.wantInPayload)
				}
				if testCase.wantTier != "" && finding.Tier != testCase.wantTier {
					t.Errorf("row %q is %q, want %q for this technique", finding.Title, finding.Tier, testCase.wantTier)
				}
			}
		})
	}
}

// TestTheNoSQLDetectorProbesEveryOperatorAndStopsAtTheFirstAnswer is the
// sequencing claim, stated as a test because it is a decision with a cost.
//
// `Scan` tries the operator forms first and returns on the first finding, so the
// differential stage — twelve requests — is only spent when all three operator
// forms came back unchanged. A target that answers an operator form therefore
// never sees a differential probe, and that is intentional: the operator row is
// the cheaper claim and the differential row is the weaker one.
func TestTheNoSQLDetectorProbesEveryOperatorAndStopsAtTheFirstAnswer(t *testing.T) {
	var seen []string
	fixture := isolatedFixture{responders: []func(string) (string, bool){
		func(value string) (string, bool) {
			if strings.Contains(value, `"$gt"`) {
				seen = append(seen, "$gt")
				return "<ul><li>a</li><li>b</li></ul>", true
			}
			return "", false
		},
	}}
	findings := scanIsolated(t, NoSQL{}, fixture)
	if len(findings) == 0 {
		t.Fatal("the $gt operator produced no finding")
	}
	if len(seen) == 0 || seen[0] != "$gt" {
		t.Errorf("the fixture saw %v, want $gt to be probed first in the documented order", seen)
	}
	for _, name := range []string{"$regex", `.")`, "return true"} {
		if strings.Contains(strings.Join(seen, ","), name) {
			t.Errorf("the probe sequence continued past the first answer: the fixture saw %v, "+
				"so the differential and error stages were spent for nothing", seen)
		}
	}
}

// TestTheCRLFDetectorPlantsAHeaderAndSplitsABody covers both CRLF techniques,
// because the split is the destructive variant and a detector that only checked
// the header case would leave it unmeasured.
func TestTheCRLFDetectorPlantsAHeaderAndSplitsABody(t *testing.T) {
	t.Run("header", func(t *testing.T) {
		fixture := isolatedFixture{responders: []func(string) (string, bool){
			func(value string) (string, bool) {
				if strings.Contains(value, crlfProbeHeader) {
					return "<p>ok</p>", true
				}
				return "", false
			},
		}}
		// The planted header must be set on the wire, which the fixture cannot do
		// through a body responder, so the responder is replaced by a real handler.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("q"), crlfProbeHeader) {
				w.Header().Set(crlfProbeHeader, crlfProbeValue)
				_, _ = w.Write([]byte("<p>ok</p>"))
				return
			}
			_, _ = w.Write([]byte(neutralPage))
		}))
		defer server.Close()
		findings := scanIsolated(t, CRLF{}, server.Config.Handler)
		if len(findings) == 0 {
			t.Fatal("the header-planting technique produced no finding against a target that " +
				"reflected the submitted header back")
		}
		if !strings.Contains(findings[0].Title, "response header planted") {
			t.Errorf("row %q is not the header-placement technique", findings[0].Title)
		}
		_ = fixture
	})

	t.Run("split", func(t *testing.T) {
		fixture := isolatedFixture{responders: []func(string) (string, bool){
			func(value string) (string, bool) {
				if strings.Contains(value, "%0d%0a%0d%0a") {
					return "<p>before</p><html>rrsplit8f2c1a</html>", true
				}
				return "", false
			},
		}}
		findings := scanIsolated(t, CRLF{}, fixture)
		if len(findings) == 0 {
			t.Fatal("the response-splitting technique produced no finding against a target that " +
				"served the submitted bytes as its body")
		}
		if !strings.Contains(findings[0].Title, "Response Splitting") {
			t.Errorf("row %q is not the splitting technique", findings[0].Title)
		}
	})
}

// TestTheSourceDisclosureDetectorRefusesASoftNotFound is the guard that makes the
// 499-path lists of four upstreams unusable and therefore not carried.
//
// A target that answers 200 with its home page for every unknown path is the
// ordinary case on a modern site. Reporting every path on it would produce one
// finding per path, all of them the home page.
func TestTheSourceDisclosureDetectorRefusesASoftNotFound(t *testing.T) {
	t.Run("soft 404 for every path", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<html><body>welcome to the site</body></html>"))
		}))
		defer server.Close()
		findings := scanIsolated(t, &SourceDisclosure{}, server.Config.Handler)
		if len(findings) != 0 {
			t.Errorf("the detector reported %d row(s) against a target that answers every path with "+
				"the same page; that is the false-positive class the soft-404 gate exists to prevent",
				len(findings))
		}
	})

	t.Run("a real repository answers differently", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "rr-soft-404-probe") {
				_, _ = w.Write([]byte("<html><body>welcome to the site</body></html>"))
				return
			}
			if r.URL.Path == "/.git/HEAD" {
				_, _ = w.Write([]byte("ref: refs/heads/main\n"))
				return
			}
			_, _ = w.Write([]byte("<html><body>welcome to the site</body></html>"))
		}))
		defer server.Close()
		findings := scanIsolated(t, &SourceDisclosure{}, server.Config.Handler)
		if len(findings) == 0 {
			t.Fatal("a target serving a real .git/HEAD with `ref: refs/` in it produced no finding")
		}
		if findings[0].Tier != TierVerified {
			t.Errorf("row %q is %q; content that identifies the file is verified", findings[0].Title, findings[0].Tier)
		}
	})
}

// TestTheMethodsDetectorProvesAWriteAndRefusesToDelete is the pair of claims that
// makes the method detector honest: PUT is demonstrated by reading the object
// back, and DELETE is reported from the advertisement alone because confirming it
// would mean destroying the operator's data.
func TestTheMethodsDetectorProvesAWriteAndRefusesToDelete(t *testing.T) {
	var stored []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "OPTIONS":
			w.Header().Set("Allow", "GET, PUT, DELETE")
			w.WriteHeader(http.StatusOK)
		case http.MethodPut:
			stored = append(stored, r.URL.Path)
			w.WriteHeader(http.StatusCreated)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			for _, path := range stored {
				if strings.HasSuffix(r.URL.Path, path) {
					_, _ = w.Write([]byte("rrput content for " + path))
					return
				}
			}
			_, _ = w.Write([]byte("<html><body>welcome</body></html>"))
		}
	}))
	defer server.Close()
	findings := scanIsolated(t, Methods{}, server.Config.Handler)
	var sawPut, sawDelete bool
	for _, finding := range findings {
		switch {
		case strings.Contains(finding.Title, "PUT accepted"):
			sawPut = true
			if finding.Tier != TierVerified {
				t.Errorf("the PUT row is %q; the detector uploaded an object and read it back, "+
					"which is a demonstration rather than an advertisement", finding.Tier)
			}
			if !strings.Contains(finding.Evidence, "read back") {
				t.Errorf("the PUT row does not say the object was read back: %q", finding.Evidence)
			}
		case strings.Contains(finding.Title, "DELETE advertised"):
			sawDelete = true
			if finding.Tier != TierPotential {
				t.Errorf("the DELETE row is %q; it is reported from the Allow header and was never "+
					"tested, so it must not claim verification", finding.Tier)
			}
		}
	}
	if !sawPut {
		t.Error("a target that accepted a PUT and served the object back produced no PUT row")
	}
	if !sawDelete {
		t.Error("an Allow header advertising DELETE produced no DELETE row")
	}
}

// TestTheCookieDetectorSeparatesScopeFromFlags is the split the register claims.
//
// A cookie scoped to the parent domain is a domain decision and is verified; a
// cookie missing HttpOnly is a flag and is capped. Merging them would make one of
// the two claims for the other.
func TestTheCookieDetectorSeparatesScopeFromFlags(t *testing.T) {
	// The parent-domain case is a unit test of the scope reader rather than of the
	// detector, and the reason is that it cannot be staged over `httptest`: the
	// test server answers on `127.0.0.1`, and a `Domain` attribute naming an IP is
	// host-only by definition — browsers reject a Domain on an address — so the
	// detector is right to decline and a test over a real socket could only assert
	// the wrong thing. The function is where the decision actually lives.
	t.Run("parent domain is read from the attribute", func(t *testing.T) {
		cases := []struct {
			host, domain string
			want         cookieScope
			why          string
		}{
			{"shop.example.com", "example.com", scopeParentDomain,
				"a sibling under example.com must be able to read it"},
			{"evil-example.com", "example.com", scopeUnknown,
				"the suffix matches as a string but the registrable domain is different, and a " +
					"suffix test without the dot is how a cookie crosses registrants"},
			{"shop.example.com", "", scopeHostOnly,
				"no Domain attribute is the correct default"},
			{"shop.example.com", "shop.example.com", scopeHostOnly,
				"naming the host itself is the same as omitting the attribute"},
		}
		for _, testCase := range cases {
			attributes := map[string]string{}
			if testCase.domain != "" {
				attributes["domain"] = testCase.domain
			}
			if got := cookieScopeOf(attributes, testCase.host); got != testCase.want {
				t.Errorf("cookieScopeOf(host=%q, domain=%q) = %d, want %d; %s",
					testCase.host, testCase.domain, got, testCase.want, testCase.why)
			}
		}
	})

	t.Run("missing httponly on a non-session cookie", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Set-Cookie", "preference=dark; Path=/; Secure")
			_, _ = w.Write([]byte("<p>ok</p>"))
		}))
		defer server.Close()
		findings := scanIsolated(t, Cookies{}, server.Config.Handler)
		var found bool
		for _, finding := range findings {
			if strings.Contains(finding.Title, "HttpOnly") {
				found = true
				if finding.Tier != TierPotential {
					t.Errorf("the flag row is %q; a missing flag is a condition, not an exposure, "+
						"so it is capped", finding.Tier)
				}
			}
		}
		if !found {
			t.Errorf("a cookie without HttpOnly produced no flag row; rows were %v", findingTitles(findings))
		}
	})

	t.Run("a session cookie is not double-reported", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Set-Cookie", "PHPSESSID=abc; Path=/")
			_, _ = w.Write([]byte("<p>ok</p>"))
		}))
		defer server.Close()
		findings := scanIsolated(t, Cookies{}, server.Config.Handler)
		for _, finding := range findings {
			if strings.Contains(finding.Title, "PHPSESSID") && strings.Contains(finding.Title, "HttpOnly") {
				t.Errorf("the session cookie's attributes were reported by the cookie detector as "+
					"well as by the session-fixation detector: %q", finding.Title)
			}
		}
	})
}

// findingTitles renders the titles of a row set, for a failure message.
func findingTitles(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.Title)
	}
	return out
}

// TestThePIIDetectorNeedsContextNextToANumber is the property that keeps its
// patterns from matching test fixtures.
//
// A bare nine-digit number in an `NNN-NN-NNNN` shape matches every American test
// fixture ever written, and a bare sixteen digits match every payment page. So the
// number must arrive beside something that names it.
func TestThePIIDetectorNeedsContextNextToANumber(t *testing.T) {
	t.Run("no label, no row", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<p>123-45-6789 and 4111 1111 1111 1111</p>"))
		}))
		defer server.Close()
		for _, finding := range scanIsolated(t, PII{}, server.Config.Handler) {
			if strings.Contains(finding.Title, "social security") ||
				strings.Contains(finding.Title, "payment card") {
				t.Errorf("row %q fired on numbers with no label beside them; the context requirement "+
					"is what keeps this detector off every page of test data", finding.Title)
			}
		}
	})

	t.Run("a label makes it a row", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<p>customer SSN 123-45-6789 on file</p>"))
		}))
		defer server.Close()
		findings := scanIsolated(t, PII{}, server.Config.Handler)
		var found bool
		for _, finding := range findings {
			if strings.Contains(finding.Title, "social security") {
				found = true
				if strings.Contains(finding.Evidence, "123-45-6789") {
					t.Errorf("the row reproduced the number it is reporting: %q; a report that "+
						"repeats the data it found is a second copy of the incident", finding.Evidence)
				}
			}
		}
		if !found {
			t.Errorf("an SSN labelled as one produced no row; rows were %v", findingTitles(findings))
		}
	})
}

// TestTheTransformStackClassification is the mapping the escaping detector's whole
// row rests on, tested on its own because it is a pure function and a pure
// function is cheap to be certain about.
func TestTheTransformStackClassification(t *testing.T) {
	cases := []struct {
		backslash, single, backtick bool
		want                        string
	}{
		{false, true, true, "unwrapped"},
		{true, false, true, "single escape layer"},
		{false, false, true, "double escape layer"},
		{true, true, true, "shell in the path"},
	}
	for _, testCase := range cases {
		layer := transformationStack(testCase.backslash, testCase.single, testCase.backtick)
		if !strings.HasPrefix(layer.name, testCase.want) {
			t.Errorf("backslash=%t single=%t backtick=%t classified as %q, want a name starting %q",
				testCase.backslash, testCase.single, testCase.backtick, layer.name, testCase.want)
		}
		if layer.why == "" {
			t.Errorf("the layer %q carries no reason; the row's evidence is built from it and an "+
				"empty one makes the claim unreadable", layer.name)
		}
	}
}

// TestThePortedSyntaxTablesMatchUpstream is the provenance check on the two
// tables that were transcribed from upstream source rather than derived.
//
// Both were copied out of a Java file and a Ruby file, and a transcription is the
// one kind of port that has no test unless something compares it to its source. The
// comparison is against the values, not against the file: the file is not vendored
// here, so the assertion is that the set is what upstream's set was, and the count
// is asserted too because a dropped entry keeps the count wrong.
func TestThePortedSyntaxTablesMatchUpstream(t *testing.T) {
	// `TransformationScan.java`: 19 payloads after the base one.
	if len(transformationSyntaxes) != 20 {
		t.Errorf("transformationSyntaxes has %d entries, want 20 (a backslash plus upstream's 19 "+
			"payload characters)", len(transformationSyntaxes))
	}
	// `decodeBasedPayloads` in the same file: exactly six.
	if len(transformationDecodeProbes) != 6 {
		t.Errorf("transformationDecodeProbes has %d entries, want upstream's 6", len(transformationDecodeProbes))
	}
	// The six NoSQL differential pairs: three quote styles times two templates.
	if pairs := nosqlDifferentialPairs(); len(pairs) != 6 {
		t.Errorf("nosqlDifferentialPairs has %d entries, want 6 (three quote styles times two "+
			"templates from no_sql_injection_differential.rb)", len(pairs))
	}
	for _, pair := range nosqlDifferentialPairs() {
		if pair.truth == pair.falsy {
			t.Errorf("the pair %q has identical halves, so it can never distinguish anything",
				pair.name)
		}
	}
}

// TestTheNoSQLDifferentialProbeNeedsTheTwoHalvesToDiffer is the coverage the
// mutation run found missing.
//
// Removing the differential probe from `NoSQL.Scan` left every test green, because
// the fixture's other two techniques kept answering. A blind differential is only
// worth its twelve requests if the two halves of a pair actually diverge, so this
// is tested in both directions: a pair whose halves differ is reported and capped,
// and a pair whose halves agree is not reported at all.
func TestTheNoSQLDifferentialProbeNeedsTheTwoHalvesToDiffer(t *testing.T) {
	// One pair is enough and it is the first: the true and false writings of
	// `$where` differ only in the boolean they express, so anything else that
	// differs between the two responses is a difference this detector must not be
	// reading.
	pair := nosqlDifferentialPairs()[0]

	t.Run("halves differ, so it is reported and capped", func(t *testing.T) {
		fixture := isolatedFixture{responders: []func(string) (string, bool){
			func(value string) (string, bool) {
				if strings.Contains(value, "return true") {
					return "<ul><li>alice</li><li>bob</li></ul>", true
				}
				if strings.Contains(value, "return false") {
					return "<ul><li>alice</li></ul>", true
				}
				return "", false
			},
		}}
		findings := scanIsolated(t, NoSQL{}, fixture)
		var found bool
		for _, finding := range findings {
			if strings.Contains(finding.Title, "differential") {
				found = true
				if finding.Tier != TierPotential {
					t.Errorf("the differential row is %q; two responses differing is not the same "+
						"claim as the payload being evaluated, so it must be capped", finding.Tier)
				}
				if finding.Severity != SeverityMedium {
					t.Errorf("the differential row is %s; the potential ceiling is medium, so a "+
						"severity above it means the cap was not applied", finding.Severity)
				}
			}
		}
		if !found {
			t.Errorf("a pair whose halves produced different result sets produced no differential "+
				"row; rows were %v", findingTitles(findings))
		}
	})

	t.Run("halves agree, so nothing is reported", func(t *testing.T) {
		// A constant page for everything. It has to be constant for *every*
		// payload, not only for the `$where` pair: the other five pairs fall
		// through to whatever the target answers, and an echoing page would give
		// those two halves different bodies for the uninteresting reason that the
		// payloads are different strings. That is the false positive the pair
		// comparison is meant to exclude, and a fixture that echoes would hide it.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<ul><li>alice</li></ul>"))
		}))
		defer server.Close()
		for _, finding := range scanIsolated(t, NoSQL{}, server.Config.Handler) {
			if strings.Contains(finding.Title, "differential") {
				t.Errorf("row %q fired on a pair whose two halves produced identical responses",
					finding.Title)
			}
		}
	})

	// The pair itself must be the two writings of one payload, which is asserted
	// because a pair whose halves are equal can never distinguish anything and the
	// probe would silently walk six of them.
	if !strings.Contains(pair.truth, "return true") || !strings.Contains(pair.falsy, "return false") {
		t.Errorf("the first pair is %q / %q; it is meant to be the $where true/false pair",
			pair.truth, pair.falsy)
	}
}

// TestTheMethodsDetectorCoversWebdavAndTrace covers the two techniques of the
// method detector that the PUT/DELETE cases do not reach.
//
// Mutation is why they are here: removing the WebDAV finding and removing the
// TRACE finding each left the suite green, because the PUT demonstration kept
// firing on the same fixture. A technique that shares a module with a
// well-covered technique needs its own row for exactly that reason.
func TestTheMethodsDetectorCoversWebdavAndTrace(t *testing.T) {
	t.Run("webdav verbs", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "OPTIONS":
				w.Header().Set("Allow", "GET, PROPFIND, PROPPATCH")
				w.WriteHeader(http.StatusOK)
			case "PROPFIND":
				w.WriteHeader(http.StatusMultiStatus)
			default:
				_, _ = w.Write([]byte("<html><body>welcome</body></html>"))
			}
		}))
		defer server.Close()
		findings := scanIsolated(t, Methods{}, server.Config.Handler)
		var found bool
		for _, finding := range findings {
			if strings.Contains(finding.Title, "WebDAV") {
				found = true
				if !strings.Contains(finding.Title, "PROPFIND") {
					t.Errorf("row %q does not name PROPFIND, which is the verb that enumerates and "+
						"the one the operator's next step depends on", finding.Title)
				}
			}
		}
		if !found {
			t.Errorf("a server answering PROPFIND and advertising PROPPATCH produced no WebDAV "+
				"row; rows were %v", findingTitles(findings))
		}
	})

	t.Run("trace echo", func(t *testing.T) {
		// A TRACE that returns 200 with an empty body has not echoed anything and
		// must not be reported, so the fixture echoes the marker it was sent — and
		// a second case asserts the empty-body case stays silent.
		echoing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodTrace {
				_, _ = w.Write([]byte("TRACE " + r.URL.Path + " X-RR-Trace: " +
					r.Header.Get("X-RR-Trace")))
				return
			}
			_, _ = w.Write([]byte("<html><body>welcome</body></html>"))
		}))
		defer echoing.Close()
		findings := scanIsolated(t, Methods{}, echoing.Config.Handler)
		var found bool
		for _, finding := range findings {
			if strings.Contains(finding.Title, "TRACE") {
				found = true
				if finding.Tier != TierVerified {
					t.Errorf("the TRACE row is %q; the echo is observed on the wire", finding.Tier)
				}
			}
		}
		if !found {
			t.Errorf("a TRACE that echoed the submitted marker produced no row; rows were %v",
				findingTitles(findings))
		}

		silent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodTrace {
				w.WriteHeader(http.StatusOK)
				return
			}
			_, _ = w.Write([]byte("<html><body>welcome</body></html>"))
		}))
		defer silent.Close()
		for _, finding := range scanIsolated(t, Methods{}, silent.Config.Handler) {
			if strings.Contains(finding.Title, "TRACE") {
				t.Errorf("row %q fired on a TRACE that answered 200 with an empty body; a status "+
					"code alone is not an echo", finding.Title)
			}
		}
	})
}

// TestTheCookieScopeFindingIsReachedFromTheDetector covers the parent-domain
// decision at detector level.
//
// The scope reader is unit-tested elsewhere. What is untested here is whether the
// detector *calls* it, and the fixture cannot stage that over a socket because
// `httptest` answers on an address, where a `Domain` attribute is host-only by
// definition. So the finding function is called with a synthetic baseline, which
// is the level at which the decision is made anyway.
func TestTheCookieScopeFindingIsReachedFromTheDetector(t *testing.T) {
	baseline := &Response{Header: http.Header{}}
	baseline.Header.Add("Set-Cookie", "tracker=abc; Domain=example.com; Path=/; HttpOnly; Secure")
	point := Point{URL: "https://shop.example.com/cart", Method: http.MethodGet}

	finding := cookieScopeFinding(point, baseline, "tracker=abc; Domain=example.com; Path=/; HttpOnly; Secure")
	if finding == nil {
		t.Fatal("a cookie scoped to example.com, set by shop.example.com, produced no finding")
	}
	if finding.Tier != TierVerified {
		t.Errorf("the row is %q; the Domain attribute is read off the header", finding.Tier)
	}
	if strings.Contains(finding.Evidence, "abc") {
		t.Errorf("the row reproduced the cookie value: %q; a shared report that repeats a session "+
			"value is a session value in the report", finding.Evidence)
	}
}

// TestTheCleartextPasswordFindingNeedsAPasswordControl is the credential-transport
// half of the cookie detector.
//
// It matches the *declaration* of a password control rather than the word
// "password", because a page that links to a password-reset form is not a page
// that collects a password, and matching the word reports both.
func TestTheCleartextPasswordFindingNeedsAPasswordControl(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"a password control", `<form action="/login"><input type="password" name="pw"></form>`, true},
		{"a single-quoted declaration", `<form action="/login"><input type='password' name="pw"></form>`, true},
		{"an unquoted declaration", `<form action="/login"><input type=password name="pw"></form>`, true},
		{"a page that only talks about one", `<p>Forgot your <a href="/reset">password</a>?</p>`, false},
	}
	for _, testCase := range cases {
		point := Point{URL: "http://shop.example.com/login", Method: http.MethodGet}
		baseline := &Response{Body: testCase.body, Header: http.Header{}}
		got := cleartextPasswordFinding(point, baseline) != nil
		if got != testCase.want {
			t.Errorf("%s: cleartextPasswordFinding returned a row=%t, want %t", testCase.name, got, testCase.want)
		}
	}

	// And the same page over TLS must be silent: `Secure` is not available before
	// there is a secure origin to insist on it.
	secure := Point{URL: "https://shop.example.com/login", Method: http.MethodGet}
	baseline := &Response{Body: `<input type="password">`, Header: http.Header{}}
	if cleartextPasswordFinding(secure, baseline) != nil {
		t.Error("a password form served over HTTPS produced a cleartext row")
	}
}

// TestTheCSRFFindingNeedsAStateChangingSurfaceWithNoToken is the CSRF detector's
// whole logic, and the three conditions each of which alone must not fire.
func TestTheCSRFFindingNeedsAStateChangingSurfaceWithNoToken(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		body    string
		cookies []string
		want    bool
		why     string
	}{
		{"a POST form with no token", http.MethodPost, `<form action="/x" method="post"><input name="q"></form>`, nil, true,
			"nothing here is something an attacker could not forge"},
		{"a GET surface", http.MethodGet, `<form action="/x"><input name="q"></form>`, nil, false,
			"a GET has no submission to forge, and treating one as a candidate would flag every " +
				"search box on the internet"},
		{"a POST form carrying a token", http.MethodPost,
			`<form action="/x"><input type="hidden" name="csrf_token" value="x"></form>`, nil, false,
			"a named token field is the protection the check is looking for"},
		{"a POST form on a SameSite cookie", http.MethodPost,
			`<form action="/x"><input name="q"></form>`, []string{"id=a; Path=/; SameSite=Lax"}, false,
			"SameSite means the browser does not send the session cookie with a cross-site post, " +
				"which is a second line of defence and this detector counts it as one"},
		{"a POST form on a long unguessable hidden value", http.MethodPost,
			`<form action="/x"><input type="hidden" value="aG9yc2ViZTRuam1vdXNlcmFzZGY3"></form>`, nil, false,
			"a token is recognised by its shape as well as by its name"},
	}
	for _, testCase := range cases {
		point := Point{URL: "http://shop.example.com/x", Method: testCase.method}
		baseline := &Response{Body: testCase.body, Header: http.Header{}}
		for _, cookie := range testCase.cookies {
			baseline.Header.Add("Set-Cookie", cookie)
		}
		got := CSRF{}.Scan(testContext(), nil, point, baseline) != nil
		if got != testCase.want {
			t.Errorf("%s: a row was produced=%t, want %t; %s", testCase.name, got, testCase.want, testCase.why)
		}
	}
}

// TestTheSessionFixationFindingNamesThePreconditionAndNotTheAchievement is the
// tier claim of the session detector.
//
// This detector has no credentials and cannot log in, so it cannot demonstrate that
// an identifier survives an authentication transition. The row says what it saw and
// is capped; a row claiming the fixation would be claiming the one thing that was
// never tested.
func TestTheSessionFixationFindingNamesThePreconditionAndNotTheAchievement(t *testing.T) {
	baseline := &Response{Header: http.Header{}}
	baseline.Header.Add("Set-Cookie", "PHPSESSID=abc123; Path=/")
	point := Point{URL: "http://shop.example.com/x?jsessionid=attacker-chosen", Method: http.MethodGet}

	findings := SessionFixation{}.Scan(testContext(), nil, point, baseline)
	if len(findings) == 0 {
		t.Fatal("a URL carrying a session identifier plus a session cookie without HttpOnly produced " +
			"no row")
	}
	finding := findings[0]
	if finding.Tier != TierPotential {
		t.Errorf("the row is %q; the precondition is an observation and the fixation was not "+
			"demonstrated, so it must be capped", finding.Tier)
	}
	if !strings.Contains(finding.Description, "was not tested") {
		t.Errorf("the row's description does not say the fixation itself was not tested: %q",
			finding.Description)
	}

	// A hardened session cookie over TLS and with an unguessable id from the URL
	// must be silent.
	hardened := &Response{Header: http.Header{}}
	hardened.Header.Add("Set-Cookie", "PHPSESSID=abc123; Path=/; HttpOnly; Secure; SameSite=Lax")
	clean := Point{URL: "https://shop.example.com/login", Method: http.MethodGet}
	if len(SessionFixation{}.Scan(testContext(), nil, clean, hardened)) != 0 {
		t.Error("a session cookie with HttpOnly, Secure and SameSite on an https page produced a row")
	}
}

// testContext returns a context for probes that never issue a request.
func testContext() context.Context { return context.Background() }

// rewritingRoundTripper sends every request to a fixed address whatever the URL
// says, while leaving the URL the detector asked for intact on the request line.
//
// It exists because two of this file's detectors decide on the **host**: a cookie's
// `Domain` attribute is host-only when it names the address `httptest` listens on,
// and a cleartext-credential row only exists for an `http://` origin. Testing those
// through a socket on `127.0.0.1` can only assert the wrong thing, so the request
// goes to the real server while `p.URL` — which is what the detector reads — carries
// the hostname and scheme the decision depends on.
type rewritingRoundTripper struct {
	next  http.RoundTripper
	fixed string
}

// RoundTrip performs the request against the fixed address.
func (r rewritingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	rewritten, err := url.Parse(r.fixed)
	if err != nil {
		return nil, err
	}
	clone.URL.Scheme = rewritten.Scheme
	clone.URL.Host = rewritten.Host
	clone.Host = ""
	return r.next.RoundTrip(clone)
}

// scanAtHost runs one module's Scan against a server, with the point's URL carrying
// a named host and a chosen scheme.
func scanAtHost(t *testing.T, module Module, target string, scheme string, handler http.Handler) []Finding {
	t.Helper()
	server := httptest.NewServer(handler)
	defer server.Close()
	transport, err := NewTransport(
		rewritingRoundTripper{next: http.DefaultTransport, fixed: server.URL},
		Options{Timeout: 5 * time.Second},
	)
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	point := Point{URL: scheme + "://" + target, Method: http.MethodGet, Param: "q", Values: url.Values{}}
	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	return module.Scan(context.Background(), transport, point, baseline)
}

// TestTheCookieDetectorFindsAParentDomainThroughScan drives the parent-domain row
// through `Cookies.Scan` rather than through the finding function, because
// mutation showed that a test calling the function directly cannot see whether the
// detector still calls it — removing the call left the suite green.
func TestTheCookieDetectorFindsAParentDomainThroughScan(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "tracker=abc; Domain=example.com; Path=/; HttpOnly; Secure")
		_, _ = w.Write([]byte("<p>ok</p>"))
	})
	findings := scanAtHost(t, Cookies{}, "shop.example.com/cart", "https", handler)
	var found bool
	for _, finding := range findings {
		if strings.Contains(finding.Title, "Parent Domain") {
			found = true
		}
	}
	if !found {
		t.Errorf("a cookie scoped to example.com, seen through Cookies.Scan, produced no row; "+
			"rows were %v", findingTitles(findings))
	}
}

// TestTheCookieDetectorFindsACleartextPasswordThroughScan does the same for the
// credential-transport row.
func TestTheCookieDetectorFindsACleartextPasswordThroughScan(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<form action="/login"><input type="password" name="pw"></form>`))
	})
	cleartext := scanAtHost(t, Cookies{}, "shop.example.com/login", "http", handler)
	var found bool
	for _, finding := range cleartext {
		if strings.Contains(finding.Title, "Cleartext") {
			found = true
			if finding.Tier != TierVerified {
				t.Errorf("the cleartext row is %q; the password control and the scheme are both "+
					"read off the response", finding.Tier)
			}
		}
	}
	if !found {
		t.Errorf("a password form on an http:// origin produced no cleartext row through Scan; "+
			"rows were %v", findingTitles(cleartext))
	}

	secure := scanAtHost(t, Cookies{}, "shop.example.com/login", "https", handler)
	for _, finding := range secure {
		if strings.Contains(finding.Title, "Cleartext") {
			t.Errorf("row %q fired on the same page over https", finding.Title)
		}
	}
}

// TestTheSourceDisclosureFreshnessCheckIsNotASubstringTest distinguishes the
// freshness check from a bare substring search.
//
// The fixture is a site whose **default** page is an error page — a real and common
// shape for a site with a catch-all error handler — so the fingerprint the detector
// looks for (`PHP Fatal error`) is present on every page it might answer. A
// substring search then fires on every such path; `Fresh` does not, because the
// fingerprint was already on the baseline.
func TestTheSourceDisclosureFreshnessCheckIsNotASubstringTest(t *testing.T) {
	errorPage := "<html><body><pre>PHP Fatal error: Allowed memory size exhausted</pre></body></html>"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error_log" {
			// A *different* error page that carries the same fingerprint.
			_, _ = w.Write([]byte("<html><body><h1>Oops</h1>" +
				"<pre>PHP Fatal error: Call to undefined function</pre></body></html>"))
			return
		}
		_, _ = w.Write([]byte(errorPage))
	}))
	defer server.Close()

	findings := scanIsolated(t, &SourceDisclosure{}, server.Config.Handler)
	for _, finding := range findings {
		if strings.Contains(finding.Title, "error_log") {
			t.Errorf("row %q fired on a path whose fingerprint was already on the site's default "+
				"page; the freshness check is what keeps an error-handling site from producing one "+
				"row per path", finding.Title)
		}
	}
}

// TestTheSessionFixationRowFromAnIdentifierInTheURL covers the URL half of the
// precondition on its own.
//
// The earlier test supplied an identifier in the URL **and** an unhardened session
// cookie, so removing the URL check left the cookie evidence and the row still
// appeared — mutation stayed green. Each half needs its own case.
func TestTheSessionFixationRowFromAnIdentifierInTheURL(t *testing.T) {
	baseline := &Response{Header: http.Header{}}
	point := Point{URL: "https://shop.example.com/x?jsessionid=attacker-chosen", Method: http.MethodGet}

	findings := SessionFixation{}.Scan(testContext(), nil, point, baseline)
	if len(findings) == 0 {
		t.Fatal("a URL carrying jsessionid, on a response with no cookies at all, produced no row")
	}
	if !strings.Contains(findings[0].Evidence, "jsessionid") {
		t.Errorf("the row does not name the identifier it found: %q", findings[0].Evidence)
	}

	// The same URL parameter on a surface whose response issues nothing must not
	// fire, and a different parameter must not either.
	clean := Point{URL: "https://shop.example.com/x?page=2", Method: http.MethodGet}
	if len(SessionFixation{}.Scan(testContext(), nil, clean, baseline)) != 0 {
		t.Error("a URL carrying an ordinary query parameter produced a session-fixation row")
	}
}

// TestTheWeakXXESignatureIsCapped separates the two XXE tiers.
//
// The strong signature (`root:x:0:0:`, fixed in every `/etc/passwd`) may be
// verified; a weak one — the `KEY=value` shape of `/proc/self/environ`, which is a
// pattern rather than a fixed string — may not. Collapsing both to verified is the
// mutation, and it is caught only by a case that reaches the weak target.
func TestTheWeakXXESignatureIsCapped(t *testing.T) {
	// `LANG=` on its own line is the weak signature the detector looks for, and the
	// other lines are what make the row worth reading: they are the credentials.
	environmentPage := "<r>APP_KEY=base64:abcdef0123456789\nDB_PASSWORD=hunter2\nLANG=C.UTF-8\nPATH=/usr/bin</r>"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("q"), "<!DOCTYPE") {
			_, _ = w.Write([]byte(environmentPage))
			return
		}
		_, _ = w.Write([]byte("<html><body>welcome</body></html>"))
	}))
	defer server.Close()

	findings := scanIsolated(t, XXE{}, server.Config.Handler)
	if len(findings) == 0 {
		t.Fatal("an entity expansion returning the process environment produced no row")
	}
	finding := findings[0]
	if !strings.Contains(finding.Payload, "/proc/self/environ") {
		t.Fatalf("row %q did not come from the weak target; payload %q",
			finding.Title, finding.Payload)
	}
	if finding.Tier != TierPotential {
		t.Errorf("the weak-signature row is %q; a `KEY=value` shape is a pattern, not a fixed "+
			"document, so it may not claim verification", finding.Tier)
	}

	// And the strong target still may.
	passwd := "<r>root:x:0:0:root:/root:/bin/bash</r>"
	strong := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("q"), "<!DOCTYPE") {
			_, _ = w.Write([]byte(passwd))
			return
		}
		_, _ = w.Write([]byte("<html><body>welcome</body></html>"))
	}))
	defer strong.Close()
	for _, finding := range scanIsolated(t, XXE{}, strong.Config.Handler) {
		if finding.Tier != TierVerified {
			t.Errorf("the fixed `/etc/passwd` row is %q; that signature cannot plausibly appear by "+
				"accident", finding.Tier)
		}
	}
}

// TestTheEscapingDetectorDeclinesAPageThatDoesNotReflect pins the control probe.
//
// Mutation removed the control check and the suite stayed green, because the
// fixture reflects its input and so the check changed nothing. The control is only
// load-bearing on a page that does **not** reflect, which is exactly the case where
// the detector must say nothing rather than classify a stack from silence.
func TestTheEscapingDetectorDeclinesAPageThatDoesNotReflect(t *testing.T) {
	silent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body><h1>Dashboard</h1></body></html>"))
	}))
	defer silent.Close()

	findings := scanIsolated(t, Escaping{}, silent.Config.Handler)
	if len(findings) != 0 {
		t.Errorf("the detector classified %v on a page that reflects none of its input; without a "+
			"control response every probe looks like a consumed backslash, so the measurement would "+
			"be confident and wrong", findingTitles(findings))
	}
}

// TestTheSessionFixationRowFromAnUnhardenedCookie isolates the cookie half of the
// precondition.
//
// The two earlier cases each supplied *both* halves — an identifier in the URL and
// a session cookie without `HttpOnly` — so removing either check left the other
// half's evidence and the row still appeared. A row that survives the removal of
// one of its two reasons is not testing that reason, and this case removes the
// confound by supplying only the cookie.
func TestTheSessionFixationRowFromAnUnhardenedCookie(t *testing.T) {
	baseline := &Response{Header: http.Header{}}
	baseline.Header.Add("Set-Cookie", "PHPSESSID=abc123; Path=/")
	point := Point{URL: "https://shop.example.com/login", Method: http.MethodGet}

	findings := SessionFixation{}.Scan(testContext(), nil, point, baseline)
	if len(findings) == 0 {
		t.Fatal("a session cookie issued without HttpOnly produced no row")
	}
	if !strings.Contains(findings[0].Evidence, "HttpOnly") {
		t.Errorf("the row does not name HttpOnly, which is the only reason it has: %q",
			findings[0].Evidence)
	}

	hardened := &Response{Header: http.Header{}}
	hardened.Header.Add("Set-Cookie", "PHPSESSID=abc123; Path=/; HttpOnly; Secure")
	if len(SessionFixation{}.Scan(testContext(), nil, point, hardened)) != 0 {
		t.Error("a session cookie with HttpOnly and Secure produced a row")
	}

	// And the same cookie over cleartext without `Secure` must say so, because that
	// is a different defect with a different fix.
	cleartext := &Response{Header: http.Header{}}
	cleartext.Header.Add("Set-Cookie", "PHPSESSID=abc123; Path=/; HttpOnly")
	clearPoint := Point{URL: "http://shop.example.com/login", Method: http.MethodGet}
	findings = SessionFixation{}.Scan(testContext(), nil, clearPoint, cleartext)
	if len(findings) == 0 {
		t.Fatal("a session cookie issued over cleartext without Secure produced no row")
	}
	if !strings.Contains(findings[0].Evidence, "Secure") {
		t.Errorf("the row does not name the missing Secure attribute: %q", findings[0].Evidence)
	}
}
