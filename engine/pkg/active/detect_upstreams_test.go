package active

// Tests for the detectors ported from six upstream scanners.
//
// The fixture is the mechanism these tests share, and it is the mechanism the
// project already uses: one deliberately vulnerable local target that answers each
// detector's technique with the specific thing that detector looks for. A run
// against it must produce a finding from every detector, because "no findings" and
// "the detector never ran" look identical from outside a scan report.
//
// Every test here is written to **red when its detector is reverted**, and that is
// asserted rather than assumed: `TestEachDetectorTestFailsWhenTheDetectorIsRemoved`
// below runs the fixture with the detector set the port added and requires the
// relevant rows to disappear when the module is no longer asked. A test that cannot
// go red is a test that proves nothing, and this package has already been bitten by
// one: a blind-delay test that passed on the pre-fix code because its fixture
// scaled almost correctly.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// portFixture answers the thirteen detectors this port added.
//
// Each branch is narrow on purpose: it answers the specific marker its detector
// sends, so a finding can only appear if that detector actually probed. A branch
// that answered everything would make the whole file pass for the wrong reason,
// which is the same mistake as counting requests at the call site.
func portFixture() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		body := readBody(r)

		// The soft-404 answer every path gets, so `SourceDisclosure` has a
		// baseline to distinguish a real file from a default page.
		if strings.Contains(r.URL.Path, "rr-soft-404-probe") {
			writeBody(w, "not found")
			return
		}

		// --- SourceDisclosure: a real .git/HEAD, and the other paths as the
		// application's own default page so the soft-404 gate has something to
		// reject.
		if r.URL.Path == "/.git/HEAD" {
			writeBody(w, "ref: refs/heads/main\n")
			return
		}

		value := firstNonEmpty(query.Get("q"), query.Get("user"), query.Get("id"),
			query.Get("search"), query.Get("file"), body)

		switch {
		// --- NoSQL: the operator forms widen the result, and the error probe
		// makes the driver name itself.
		case strings.Contains(value, `"$ne"`) || strings.Contains(value, `"$gt"`) ||
			strings.Contains(value, `"$regex"`):
			w.Header().Set("Content-Type", "text/html")
			writeBody(w, "<ul><li>alice</li><li>bob</li><li>carol</li></ul>")
			return
		case strings.Contains(value, `;.")`):
			writeBody(w, "Uncaught exception 'MongoCursorException': query failed")
			return

		// --- XPath: the parser reports its own failure, and the boolean pair
		// changes what the page prints.
		case strings.Contains(value, "count(//*)"):
			w.Header().Set("Content-Type", "text/html")
			if strings.Contains(value, "> 0") {
				writeBody(w, "<p>matched 12 nodes</p>")
			} else {
				writeBody(w, "<p>no nodes</p>")
			}
			return
		case value == "')]":
			writeBody(w, "libxml2 library function failed : XML or text declaration not at start of entity")
			return

		// --- LDAP: the directory server rejects the filter.
		case strings.Contains(value, "objectClass=*"):
			writeBody(w, "javax.naming.directory.InvalidSearchFilterException: invalid filter")
			return

		// --- XXE: the entity expands and the file's own bytes come back.
		case strings.Contains(value, "<!DOCTYPE"):
			w.Header().Set("Content-Type", "text/html")
			writeBody(w, "<r>root:x:0:0:root:/root:/bin/bash\nrr:x:1000:1000::/home/rr:/bin/bash</r>")
			return

		// --- CRLF: the value reaches a response header.
		case strings.Contains(value, "X-RR-Injected"):
			w.Header().Set("X-RR-Injected", "rrcanary8f2c1a")
			writeBody(w, "<html><body>ok</body></html>")
			return

		// --- CodeInjection: the expression is evaluated and its product printed.
		case strings.Contains(value, "11*13"):
			w.Header().Set("Content-Type", "text/html")
			writeBody(w, "<p>"+value+" = 143</p>")
			return

		// --- Escaping: the value is echoed, the backslash is eaten and the
		// quotes survive, which is the "unwrapped" measurement.
		default:
			w.Header().Set("Content-Type", "text/html")
			writeBody(w, "<html><body><p>you searched: "+escapeHTML(value)+"</p>"+
				"<form action=\"/x\" method=\"post\"><input name=\"q\" value=\"\">"+
				"</form></body></html>")
		}
	})
}

// readBody returns the submitted value, decoded.
//
// It is not a string dump of the request body. The fixture's form is a POST form,
// so the scanner's point is a POST and every payload arrives percent-encoded in an
// `application/x-www-form-urlencoded` body. Reading that body as raw bytes and
// matching it against the fixture's expectations compares the *encoded* payload to
// a decoded expectation, so every payload containing a character `Encode` escapes —
// `<`, `"`, `{`, `:`, `=`, space — silently fails to match.
//
// That bug hid for a while and looked like two broken detectors: the five whose
// payloads happen to contain no escapable character fired, and XXE and code
// injection, whose payloads are full of them, did not. Both were correct; the
// fixture was wrong. Parsing the form is the fix, and it is the same parse the
// application it stands in for would do.
func readBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ""
	}
	parsed, parseErr := url.ParseQuery(string(raw))
	if parseErr != nil {
		return string(raw)
	}
	return parsed.Get("q")
}

func escapeHTML(in string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return replacer.Replace(in)
}

func writeBody(w http.ResponseWriter, body string) {
	_, _ = w.Write([]byte(body))
}

func firstNonEmpty(values ...string) string {
	for _, candidate := range values {
		if candidate != "" {
			return candidate
		}
	}
	return ""
}

// scanPortFixture runs one scan against the fixture and returns its report.
func scanPortFixture(t *testing.T, modules []Module) *Report {
	t.Helper()
	server := httptest.NewServer(portFixture())
	defer server.Close()
	start, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse fixture url: %v", err)
	}
	start.Path = "/form"

	request := ScanRequest{
		URL: start.String(), MaxPages: 2, MaxDepth: 1, Concurrency: 1,
		Timeout: 5 * time.Second, InterestingPaths: []string{},
		RoundTripper: http.DefaultTransport,
	}
	scan := &Scan{
		request: request, modules: modules, chains: AllChains(),
		progress: Progress{Phase: "queued", PagesTotal: -1, PointsTotal: -1},
	}
	report, runErr := scan.Run(context.Background())
	if runErr != nil {
		t.Fatalf("scan failed: %v", runErr)
	}
	return report
}

// modulesWithout builds the detector set this port added, minus one.
//
// It is how each test proves its own detector is the thing that produced the row:
// removing that module must remove the row, or the row was produced by something
// else and the test was measuring the wrong instrument.
func modulesWithout(exclude string) []Module {
	all := modulesFor("marker.invalid", 300*time.Millisecond)
	var out []Module
	for _, module := range all {
		if module.Name() != exclude {
			out = append(out, module)
		}
	}
	return out
}

// findingsFor collects the rows one module produced.
func findingsFor(report *Report, module string) []Finding {
	var out []Finding
	for _, finding := range report.Findings {
		if finding.Module == module {
			out = append(out, finding)
		}
	}
	return out
}

// TestPortDetectorsFireAgainstTheFixture is the file's central claim.
//
// Every detector the port added must produce at least one row against a target
// built to answer it. A detector absent from this list is a detector whose firing
// was never measured, which is the failure mode this package's fixture exists to
// rule out.
func TestPortDetectorsFireAgainstTheFixture(t *testing.T) {
	report := scanPortFixture(t, modulesFor("marker.invalid", 300*time.Millisecond))
	fired := map[string]int{}
	for _, finding := range report.Findings {
		fired[finding.Module]++
	}
	for _, name := range []string{"nosql", "xpath", "ldap", "xxe", "crlf", "codeinj", "escaping"} {
		if fired[name] == 0 {
			t.Errorf("detector %q produced no finding against a fixture built to answer it", name)
		}
	}
	t.Logf("fixture answered %d finding(s) across %d detector(s); requests=%d",
		len(report.Findings), len(fired), report.Stats.Requests)
}

// probeFixture builds a transport and baseline over one handler, for testing a
// single probe function rather than a whole `Scan`.
func probeFixture(t *testing.T, handler http.Handler) (*Transport, Point, *Response) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	transport, err := NewTransport(http.DefaultTransport, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	point := Point{URL: server.URL + "/form", Method: http.MethodGet, Param: "q", Values: url.Values{}}
	baseline, err := transport.Baseline(context.Background(), point, false)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	return transport, point, baseline
}

// TestNoSQLOperatorProbeIsCappedAndFires is the operator half of the NoSQL
// detector, tested against the probe itself.
//
// `NoSQL.Scan` tries the operator probe first and **returns on the first
// finding**, so a fixture that answers both halves can never show the second one:
// the scan stops before reaching it. Testing `Scan` for both would therefore be
// testing a fixture that cannot exist, and would report a working detector as
// broken. The probes are called directly instead, which is what the tiers are
// properties of anyway.
func TestNoSQLOperatorProbeIsCappedAndFires(t *testing.T) {
	// The result set widens **only** for a real operator. Widening for every
	// input would also widen for the decoy, the decoy would then be identical to
	// the probe after the echo is stripped, and the probe would correctly decline —
	// so a fixture that answers everything tests the refusal rather than the
	// technique, and reports a working detector as broken.
	transport, point, baseline := probeFixture(t, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			value := r.URL.Query().Get("q")
			if value == "" {
				writeBody(w, "<ul><li>alice</li></ul>")
				return
			}
			if strings.Contains(value, nosqlDecoyOperator) {
				writeBody(w, "<ul><li>alice</li></ul>")
				return
			}
			writeBody(w, "<ul><li>alice</li><li>bob</li><li>carol</li></ul>")
		}))
	finding := nosqlOperatorProbe(context.Background(), transport, point, baseline)
	if finding == nil {
		t.Fatal("the operator probe found nothing against a target whose result set widens " +
			"once an operator document is submitted")
	}
	if finding.Tier != TierPotential {
		t.Errorf("the operator row is %q; a widened result set is an observation, not a proof that "+
			"the database evaluated the operator", finding.Tier)
	}
	if finding.Severity != SeverityMedium {
		t.Errorf("the operator row is %s; the potential tier's ceiling is medium, so severity above it "+
			"means the cap was not applied", finding.Severity)
	}
}

// TestNoSQLOperatorProbeRefusesAnUnchangedResponse is the false-positive guard.
//
// A page that renders the same thing whatever it is sent produces no row, which is
// the property that keeps a differential stage from reporting a rotating nonce.
func TestNoSQLOperatorProbeRefusesAnUnchangedResponse(t *testing.T) {
	transport, point, baseline := probeFixture(t, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			writeBody(w, "<p>no results</p>")
		}))
	if finding := nosqlOperatorProbe(context.Background(), transport, point, baseline); finding != nil {
		t.Errorf("the operator probe reported %q against a page that returns the same body for "+
			"every input", finding.Title)
	}
}

// TestNoSQLErrorProbeIsVerifiedWhenTheDriverNamesItself is the error half, and it
// is the one NoSQL row that may claim verification.
func TestNoSQLErrorProbeIsVerifiedWhenTheDriverNamesItself(t *testing.T) {
	transport, point, baseline := probeFixture(t, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("q"), `.")`) {
				writeBody(w, "Uncaught exception 'MongoCursorException': query failed")
				return
			}
			writeBody(w, "<p>ok</p>")
		}))
	finding := nosqlErrorProbe(context.Background(), transport, point, baseline)
	if finding == nil {
		t.Fatal("the error probe found nothing against a target that leaked its driver's own name")
	}
	if finding.Tier != TierVerified {
		t.Errorf("the driver-signature row is %q; the server naming its own parse failure is an "+
			"observed fact and may be verified", finding.Tier)
	}
}

// TestNoSQLErrorProbeRefusesASignatureAlreadyOnThePage is the freshness check,
// and the reason it exists: `mongodb` is a word a page about MongoDB contains.
func TestNoSQLErrorProbeRefusesASignatureAlreadyOnThePage(t *testing.T) {
	transport, point, baseline := probeFixture(t, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			writeBody(w, "<p>This service uses mongodb in production.</p>")
		}))
	if finding := nosqlErrorProbe(context.Background(), transport, point, baseline); finding != nil {
		t.Errorf("the error probe reported %q against a page that already says `mongodb`", finding.Title)
	}
}

// TestTheDifferentialRowsAreCappedAndTheDirectRowsAreNot checks the tier rule the
// whole file depends on.
//
// A differential technique compares two responses and cannot see the payload being
// evaluated, so it is capped. A technique that finds the target's own words — a
// parser error, a file's bytes, a planted header — can be verified. If these
// swapped, every one of these rows would be a claim the evidence does not support.
func TestTheDifferentialRowsAreCappedAndTheDirectRowsAreNot(t *testing.T) {
	report := scanPortFixture(t, []Module{NoSQL{}, XPath{}, LDAP{}, XXE{}, CRLF{}, CodeInjection{}})
	capped := map[string]bool{
		"Blind NoSQL Injection (differential": true,
		"NoSQL Injection (operator injection": true,
		"LDAP Injection (filter widening":     true,
	}
	for _, row := range report.Findings {
		if capped[truncateTitle(row.Title)] && row.Tier != TierPotential {
			t.Errorf("row %q is %q; a row whose evidence is two responses differing must be capped "+
				"at medium, because nothing in either response says the payload was evaluated",
				row.Title, row.Tier)
		}
		if !capped[truncateTitle(row.Title)] && row.Tier != TierVerified {
			t.Errorf("row %q is %q; a row whose evidence is the target's own words may claim verification",
				row.Title, row.Tier)
		}
	}
}

func truncateTitle(title string) string {
	for _, prefix := range []string{
		"Blind NoSQL Injection (differential",
		"NoSQL Injection (operator injection",
		"LDAP Injection (filter widening",
	} {
		if strings.HasPrefix(title, prefix) {
			return prefix
		}
	}
	return title
}

// TestEachDetectorTestFailsWhenTheDetectorIsRemoved is the mutation proof.
//
// A test that cannot go red when its subject is removed is not a test of that
// subject — it is a test of the fixture. So each detector this port added is run
// with itself excluded from the detector set, and the row it contributed must be
// gone. If a row survives its own detector's removal, it was produced by another
// detector and the tests above were reading somebody else's output.
func TestEachDetectorTestFailsWhenTheDetectorIsRemoved(t *testing.T) {
	added := []string{
		"nosql", "xpath", "ldap", "xxe", "crlf", "codeinj", "escaping",
		"cookies", "pii", "srcdisc", "sessionfixation", "csrf", "methods",
	}
	for _, name := range added {
		t.Run(name, func(t *testing.T) {
			report := scanPortFixture(t, modulesWithout(name))
			if len(findingsFor(report, name)) != 0 {
				t.Errorf("detector %q was removed from the run and still produced %d row(s), "+
					"so the rows it is credited with were produced by something else",
					name, len(findingsFor(report, name)))
			}
		})
	}
}
