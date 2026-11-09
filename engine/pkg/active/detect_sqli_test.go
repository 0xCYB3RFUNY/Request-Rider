package active

// Tests for the SQL injection detector.
//
// The fixture is a real HTTP server whose behaviour is switched per test, not a
// mocked transport. A detector's failure mode is overwhelmingly about the
// response it accepts, and a mock that returns whatever the test hands it will
// happily agree with a detector that accepts anything. The server here
// reproduces the specific shapes that make this detector wrong: a page that
// already prints a database error, a page that is slow on both arms of a
// boolean pair, and a 200 that changed for a reason other than a UNION.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// sqliFixture is a server whose SQL behaviour is defined by the test.
type sqliFixture struct {
	// handler decides the response for one request. The parameter value it
	// receives is passed as the second argument.
	handler func(param string) (status int, body string)
	// requests records every parameter value the server saw, in order.
	requests []string
}

func newSQLiFixture(t *testing.T, handler func(param string) (int, string)) (*Transport, Point) {
	t.Helper()
	fixture := &sqliFixture{handler: handler}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("id")
		fixture.requests = append(fixture.requests, value)
		status, body := fixture.handler(value)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	transport := mustTransport(t)
	// The log is registered here rather than returned, because twenty tests
	// already call this helper with two results and changing its signature to
	// hand back a third would rewrite all of them for no gain. A test that wants
	// to read the requests takes the newest fixture through `sqliFixtureFor`.
	sqliRequestLogs = append(sqliRequestLogs, fixture)
	return transport, Point{
		URL: server.URL, Method: http.MethodGet, Param: "id",
		Values: url.Values{"id": {"1"}},
	}
}

// baselineOf takes the surface's unmodified response, failing the test if the
// request could not be made at all.
func baselineOf(t *testing.T, transport *Transport, p Point) *Response {
	t.Helper()
	resp, err := transport.Baseline(context.Background(), p, false)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	return resp
}

func (m SQLi) probe(t *testing.T, transport *Transport, p Point) []Finding {
	t.Helper()
	return m.Scan(context.Background(), transport, p, baselineOf(t, transport, p))
}

func titles(findings []Finding) string {
	var out []string
	for _, f := range findings {
		out = append(out, f.Title)
	}
	return strings.Join(out, " | ")
}

// A quoted value that produces a database diagnostic is a verified finding:
// the diagnostic is new, so the injection caused it.
func TestSQLiReportsErrorBasedInjection(t *testing.T) {
	transport, point := newSQLiFixture(t, func(param string) (int, string) {
		if strings.Contains(param, "'") {
			return 200, `<div>You have an error in your SQL syntax near ''' at line 1</div>`
		}
		return 200, `<div>Item 1</div>`
	})
	findings := (SQLi{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want exactly 1", titles(findings))
	}
	finding := findings[0]
	if finding.Tier != TierVerified {
		t.Errorf("tier = %q, want %q: a new database diagnostic is proof", finding.Tier, TierVerified)
	}
	if finding.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical", finding.Severity)
	}
	if finding.Capped {
		t.Error("a verified finding was reported as capped")
	}
	if !strings.Contains(finding.Evidence, "you have an error") {
		t.Errorf("evidence = %q, want the fingerprint the finding rests on", finding.Evidence)
	}
	if finding.PoCCurl == "" {
		t.Error("no reproduction attached; a finding nobody can rerun gets closed")
	}
}

// The page already printed that error before the scanner touched it. Reporting
// SQL injection here would be a false positive on every parameter the
// application has, and it is the exact failure the baseline guard exists to
// prevent.
func TestSQLiIgnoresFingerprintAlreadyOnThePage(t *testing.T) {
	transport, point := newSQLiFixture(t, func(param string) (int, string) {
		// The baseline itself contains the MySQL diagnostic, as an app with a
		// "last failed query" panel would.
		return 200, `<p>Last failed query: you have an error in your SQL syntax</p><div>Item 1</div>`
	})
	findings := (SQLi{}).probe(t, transport, point)
	if len(findings) != 0 {
		t.Fatalf("findings = %v, want none: the fingerprint was already on the page", titles(findings))
	}
}

// A page that differs slightly for every request is not evidence of injection.
// A differential detector that accepts "changed" rather than "changed in the way
// a condition would change it" reports every dynamic page as blind SQLi.
func TestSQLiRejectsUnstructuredDifference(t *testing.T) {
	transport, point := newSQLiFixture(t, func(param string) (int, string) {
		// Every response differs from the last, but no condition is being
		// evaluated: the difference is a rotating counter.
		return 200, fmt.Sprintf(`<div>Item 1, request %d</div>`, time.Now().UnixNano())
	})
	findings := (SQLi{}).probe(t, transport, point)
	for _, finding := range findings {
		if strings.Contains(finding.Title, "Boolean") {
			t.Fatalf("reported a boolean differential on a page that simply varies: %q", finding.Title)
		}
	}
}

// Both arms returning the same wrong page is a syntax error, not a condition.
// Requiring the true arm to resemble the baseline is what separates them.
func TestSQLiRejectsBooleanPairWhereBothArmsError(t *testing.T) {
	transport, point := newSQLiFixture(t, func(param string) (int, string) {
		if strings.Contains(param, "AND") || strings.Contains(param, "&&") {
			return 500, `<h1>Internal Server Error</h1>`
		}
		return 200, `<div>Item 1</div>`
	})
	findings := (SQLi{}).probe(t, transport, point)
	for _, finding := range findings {
		if strings.Contains(finding.Title, "Boolean") {
			t.Fatalf("reported a boolean differential where both arms failed identically: %q", finding.Title)
		}
	}
}

// A working boolean condition: the true arm matches the baseline and the false
// arm does not. It is reported, and it is a *potential* — no data was
// extracted, only the ability to extract was shown.
func TestSQLiReportsBooleanDifferentialAsPotential(t *testing.T) {
	long := strings.Repeat("<p>filler content to make the document long enough to score</p>", 12)
	transport, point := newSQLiFixture(t, func(param string) (int, string) {
		if strings.Contains(param, "1'='2") || strings.Contains(param, "1=2") || strings.Contains(param, "2<1") {
			return 200, `<div>No results</div>` + long
		}
		if strings.Contains(param, "'") {
			return 200, `<div>Item 1</div>` + long
		}
		return 200, `<div>Item 1</div>` + long
	})
	findings := (SQLi{}).probe(t, transport, point)
	var boolean *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "Boolean") {
			boolean = &findings[i]
		}
	}
	if boolean == nil {
		t.Fatalf("findings = %v, want a boolean differential", titles(findings))
	}
	if boolean.Tier != TierPotential {
		t.Errorf("tier = %q, want %q: a condition was shown, no data was taken", boolean.Tier, TierPotential)
	}
	if boolean.Severity.Rank() > SeverityMedium.Rank() {
		t.Errorf("severity = %q, want at most medium for a potential", boolean.Severity)
	}
	if !boolean.Capped {
		t.Error("capped flag not set, so the downgrade is invisible in the report")
	}
}

// The upstream test accepted "status 200" as proof of a UNION, which any page
// that answered 200 with a slightly different body satisfies. A UNION is only
// accepted here when the response grew without a database diagnostic.
func TestSQLiDoesNotTreatAny200AsUnion(t *testing.T) {
	transport, point := newSQLiFixture(t, func(param string) (int, string) {
		// A 200 that differs from the baseline, carries no diagnostic, and is
		// not longer: a rotated banner, an ad slot, a timestamp.
		if strings.Contains(param, "UNION") {
			return 200, `<div>Item 1</div><span>promo</span>`
		}
		return 200, `<div>Item 1</div>`
	})
	findings := (SQLi{}).probe(t, transport, point)
	for _, finding := range findings {
		if strings.Contains(finding.Title, "UNION") {
			t.Fatalf("reported a UNION from a plain 200: %q (evidence %q)", finding.Title, finding.Evidence)
		}
	}
}

func TestSQLiReportsUnionWhenResponseGrows(t *testing.T) {
	transport, point := newSQLiFixture(t, func(param string) (int, string) {
		if strings.Contains(param, "UNION SELECT") {
			// A working UNION: extra columns come back, no diagnostic.
			return 200, `<div>Item 1</div>` + strings.Repeat("<td></td>", 4)
		}
		return 200, `<div>Item 1</div>`
	})
	findings := (SQLi{}).probe(t, transport, point)
	var union *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "UNION") {
			union = &findings[i]
		}
	}
	if union == nil {
		t.Fatalf("findings = %v, want a UNION finding", titles(findings))
	}
	if !strings.Contains(union.Evidence, "columns") {
		t.Errorf("evidence = %q, want the column count the PoC depends on", union.Evidence)
	}
}

// A wrong column count produces a diagnostic, and that is not a result.
func TestSQLiIgnoresUnionThatOnlyErrors(t *testing.T) {
	transport, point := newSQLiFixture(t, func(param string) (int, string) {
		if strings.Contains(param, "UNION SELECT") {
			return 200, `you have an error in your SQL syntax near 'NULL' at line 1`
		}
		return 200, `<div>Item 1</div>`
	})
	findings := (SQLi{}).probe(t, transport, point)
	for _, finding := range findings {
		if strings.Contains(finding.Title, "UNION") {
			t.Fatalf("reported a UNION whose only symptom was a database error: %q", finding.Title)
		}
	}
}

// The UNION probe only applies where the application already treats the value as
// a number. Firing it at a date field generates a syntax error and learns
// nothing, at the target's expense.
func TestSQLiSkipsUnionOnNonNumericSurface(t *testing.T) {
	transport, point := newSQLiFixture(t, func(param string) (int, string) {
		return 200, `<div>Item 1</div>`
	})
	point.Values = url.Values{"id": {"2026-09-29"}}
	baseline := baselineOf(t, transport, point)
	if unionProbe(context.Background(), transport, point, baseline) != nil {
		t.Fatal("probed UNION on a non-numeric value")
	}
	if !numericBaseline(Point{Param: "id", Values: url.Values{"id": {"42"}}}) {
		t.Error("numericBaseline rejected an integer")
	}
	if numericBaseline(Point{Param: "id", Values: url.Values{"id": {""}}}) {
		t.Error("numericBaseline accepted an empty value")
	}
	if numericBaseline(Point{Param: "id", Values: url.Values{"id": {"2026-09-29"}}}) {
		t.Error("numericBaseline accepted a date")
	}
}

// The first technique that answers ends the probe. Twelve payloads against a
// parameter that already leaked an error is twelve requests that prove nothing
// and cost the target something.
func TestSQLiStopsAfterFirstTechniqueThatAnswers(t *testing.T) {
	transport, point := newSQLiFixture(t, func(param string) (int, string) {
		if strings.Contains(param, "'") {
			return 200, `you have an error in your SQL syntax near '''`
		}
		return 200, `<div>Item 1</div>`
	})
	findings := (SQLi{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want 1", titles(findings))
	}
}

// A cancelled run must produce no finding rather than a partial one.
func TestSQLiReportsNothingOnCancellation(t *testing.T) {
	transport, point := newSQLiFixture(t, func(param string) (int, string) {
		return 200, `you have an error in your SQL syntax`
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A cancelled context legitimately fails the baseline too, so the failure is
	// the expected outcome here rather than a broken fixture.
	baseline, _ := transport.Baseline(ctx, point, false)
	if baseline != nil {
		t.Fatal("baseline succeeded on a cancelled context")
	}
	if findings := (SQLi{}).Scan(ctx, transport, point, baseline); len(findings) != 0 {
		t.Fatalf("findings = %v, want none on a cancelled run", titles(findings))
	}
}

func TestSQLiIdentifiesEngines(t *testing.T) {
	cases := map[string]string{
		`you have an error in your SQL syntax`:   "MySQL",
		`Unclosed quotation mark after the char`: "MSSQL",
		`unterminated quoted string at or near`:  "PostgreSQL",
		`ORA-01756`:                              "Oracle",
		`SQLite3::query: near "x": syntax error`: "SQLite",
	}
	body := ""
	for fragment := range cases {
		body += fragment
	}
	transport, point := newSQLiFixture(t, func(param string) (int, string) {
		if strings.Contains(param, "'") {
			return 200, body
		}
		return 200, `<div>Item 1</div>`
	})
	findings := (SQLi{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want 1", titles(findings))
	}
	// The engine named must be one the fingerprint table knows, and it must be
	// named by its engine name rather than by the pattern that matched: a
	// report that says "you have an error in your SQL syntax" instead of
	// "MySQL" leaves the reader to do the identification themselves.
	known := map[string]bool{"MySQL": true, "MSSQL": true, "PostgreSQL": true, "Oracle": true, "SQLite": true}
	matched := false
	for engine := range known {
		if strings.Contains(findings[0].Title, engine) {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("title = %q, want one of MySQL/MSSQL/PostgreSQL/Oracle/SQLite named", findings[0].Title)
	}
}

// TestSQLiColumnRangeIsBounded keeps the ladder a ladder.
//
// The bounds moved when the ladder did: it used to start at 3 and stop at 8,
// because a two-column result was read as a coincidence and a table wider than
// eight was rare enough to be worth the run. It is now the whole range, because a
// detector that stops early reports "no UNION" on a table that has 31 columns.
// What did not change is the point of the test — the counts have to be usable
// column counts, strictly increasing, and still bounded, since an unbounded walk
// turns one parameter into an unbounded number of requests against a host that
// did not agree to any of them.
func TestSQLiColumnRangeIsBounded(t *testing.T) {
	if len(unionColumnCounts) == 0 {
		t.Fatal("no column counts configured")
	}
	for i, columns := range unionColumnCounts {
		if columns < 1 {
			t.Fatalf("column count %d at %d is not a column count", columns, i)
		}
		if i > 0 && columns <= unionColumnCounts[i-1] {
			t.Fatalf("column counts are not increasing: %v", unionColumnCounts)
		}
		if columns > 30 {
			t.Fatalf("column count %d exceeds the documented range", columns)
		}
	}
	if strconv.Itoa(unionColumnCounts[0]) != "1" {
		t.Errorf("range starts at %d, want 1: the ladder is the whole range", unionColumnCounts[0])
	}
}

// The time-based and column-count fixtures below reproduce a target rather than
// mocking a transport: a server that waits when the payload asks it to wait, and
// a server that complains when the ordinal runs past its last column. Both
// behaviours are the ones a real engine has, and a detector's failure mode here
// is overwhelmingly about the response it accepts — so a mock that returned
// whatever the test handed it would agree with a detector that accepts anything.

// askedDelay reads how long a payload asked the database to wait, the way an
// engine would read it: the number inside the named function, or the clock field
// of a `WAITFOR DELAY`. It returns false for a payload that asks for nothing.
func askedDelay(param, function string) (time.Duration, bool) {
	at := strings.Index(strings.ToUpper(param), strings.ToUpper(function))
	if at < 0 {
		return 0, false
	}
	rest := strings.TrimSpace(param[at+len(function):])
	// `0:00:05` — the clock's own terminator is followed by whatever closed the
	// statement, so the seconds field is read up to its first non-digit rather
	// than parsed whole. A trailing `-- -` would make the field unparseable and
	// the fixture would stop sleeping, which is a broken measurement rather than
	// a passing one. The space is trimmed before the prefix is tested: the
	// payload carries a space before `DELAY`, and testing the prefix against
	// untrimmed text silently refuses every clock literal.
	if strings.HasPrefix(strings.ToUpper(rest), "DELAY") {
		rest = strings.Trim(strings.TrimSpace(rest[len("DELAY"):]), "'")
		parts := strings.Split(rest, ":")
		if len(parts) != 3 {
			return 0, false
		}
		digits := parts[2]
		for i, r := range digits {
			if r < '0' || r > '9' {
				digits = digits[:i]
				break
			}
		}
		seconds, err := strconv.Atoi(digits)
		if err != nil {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	end := strings.IndexAny(rest, ")'\" ")
	if end < 0 {
		return 0, false
	}
	seconds, err := strconv.ParseFloat(rest[:end], 64)
	if err != nil {
		return 0, false
	}
	return time.Duration(seconds * float64(time.Second)), true
}

// sleepyPage waits for whatever the payload asked for, up to a cap.
//
// The cap exists so a test can assert *which* number was sent without paying for
// it: a probe that asks for two seconds and gets two hundred milliseconds is
// still evidence about the payload, and it is the difference between a test that
// takes two seconds and one that takes none.
func sleepyPage(cap time.Duration) func(string) (int, string) {
	return func(param string) (int, string) {
		if asked, ok := askedDelay(param, "SLEEP("); ok && asked > 0 {
			if asked > cap {
				asked = cap
			}
			time.Sleep(asked)
		}
		return 200, "<html><body><table><tr><td>alice</td></tr></table></body></html>"
	}
}

// An injected delay that the database actually waits out is a finding, and the
// evidence names both the delay that arrived and the one that was requested.
func TestSQLiReportsATimeBasedDelay(t *testing.T) {
	// The cap has to clear the *doubled* arm, not just the delay asked for. The
	// technique now fires the same spelling twice — once for the operator's
	// number and once for twice it — and a fixture that quietly clipped the long
	// arm would make the two increments equal, which is exactly the shape of the
	// slow page the second measurement exists to refuse. The fixture was wrong
	// here first, and the finding disappeared for a reason that had nothing to do
	// with the finding.
	transport, point := newSQLiFixture(t, sleepyPage(2*time.Second))
	findings := SQLi{BlindDelay: 400 * time.Millisecond}.probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("want exactly one finding, got %d: %s", len(findings), titles(findings))
	}
	got := findings[0]
	if !strings.Contains(got.Title, "Time-Based Blind") {
		t.Errorf("title does not name the technique: %q", got.Title)
	}
	if got.Tier != TierPotential {
		t.Errorf("tier is %q: a delay is consistent with an executed function and with a slow target", got.Tier)
	}
	if !strings.Contains(got.Payload, "SLEEP(") {
		t.Errorf("payload %q does not carry the delay that was sent", got.Payload)
	}
	// The control arm is part of the evidence, not an implementation detail, so
	// the report has to show it: without the comparison the number is just a
	// slow response.
	if !strings.Contains(got.Evidence, "without a delay") {
		t.Errorf("evidence does not report the control arm: %q", got.Evidence)
	}
	// A control arm can come back faster than the baseline, and the report has to
	// read that way rather than printing a negative duration: "-116ms" is a
	// number nobody can act on and looks like a broken measurement.
	if strings.Contains(got.Evidence, "-") && strings.Contains(got.Evidence, "came back -") {
		t.Errorf("evidence prints a negative control cost: %q", got.Evidence)
	}
	if !strings.Contains(got.Evidence, "came back") {
		t.Errorf("evidence does not state the control arm's cost: %q", got.Evidence)
	}
}

// A page that is slow whatever the payload is the case this technique exists to
// refuse. Every request costs the same, so the increment is zero and there is
// nothing to attribute.
func TestSQLiDoesNotCreditAPageThatIsSlowWhateverThePayload(t *testing.T) {
	transport, point := newSQLiFixture(t, func(string) (int, string) {
		time.Sleep(300 * time.Millisecond)
		return 200, "<html><body><table><tr><td>alice</td></tr></table></body></html>"
	})
	findings := SQLi{BlindDelay: 400 * time.Millisecond}.probe(t, transport, point)
	if len(findings) != 0 {
		t.Fatalf("a constantly slow page produced %d findings: %s", len(findings), titles(findings))
	}
}

// A syntax error that happens to be slow is a refusal, not an executed function.
// The diagnostic is the same string the error technique looks for, so this also
// proves the two techniques cannot be credited for each other's evidence.
func TestSQLiDoesNotCreditADelayThatArrivesWithADiagnostic(t *testing.T) {
	transport, point := newSQLiFixture(t, func(param string) (int, string) {
		if asked, ok := askedDelay(param, "SLEEP("); ok && asked > 0 {
			time.Sleep(400 * time.Millisecond)
			return 200, "<html>You have an error in your SQL syntax near 'SLEEP'</html>"
		}
		return 200, "<html><body><table><tr><td>alice</td></tr></table></body></html>"
	})
	findings := SQLi{BlindDelay: 400 * time.Millisecond}.probe(t, transport, point)
	for _, got := range findings {
		if strings.Contains(got.Title, "Time-Based Blind") {
			t.Fatalf("a slow syntax error was credited as a delay: %q", got.Evidence)
		}
	}
}

// The control arm has teeth of its own: when the same spelling without a delay
// is *also* slow, the slowness came from the payload being present rather than
// from the function it calls, and nothing here may be credited.
func TestADelayOnlyCountsWhenTheSameSpellingWithoutItIsPrompt(t *testing.T) {
	transport, point := newSQLiFixture(t, func(param string) (int, string) {
		// Every payload that names the function is slow, delay or not.
		if strings.Contains(strings.ToUpper(param), "SLEEP(") {
			time.Sleep(300 * time.Millisecond)
		}
		return 200, "<html><body><table><tr><td>alice</td></tr></table></body></html>"
	})
	findings := SQLi{BlindDelay: 400 * time.Millisecond}.probe(t, transport, point)
	for _, got := range findings {
		if strings.Contains(got.Title, "Time-Based Blind") {
			t.Fatalf("credited a delay whose control arm was equally slow: %q", got.Evidence)
		}
	}
}

// Without a measured baseline there is nothing to compare against, and a fixed
// threshold is the guess the whole technique refuses to make.
func TestSQLiRefusesATimeBasedDelayWithoutABaseline(t *testing.T) {
	transport, point := newSQLiFixture(t, sleepyPage(300*time.Millisecond))
	findings := SQLi{BlindDelay: 400 * time.Millisecond}.Scan(
		context.Background(), transport, point, nil)
	for _, got := range findings {
		if strings.Contains(got.Title, "Time-Based Blind") {
			t.Fatalf("credited a delay with no baseline: %q", got.Evidence)
		}
	}
}

// A whole-second clock cannot be asked for half a second, and sending `0:0:0`
// asks for no delay at all — which would read as a fast response and prove
// nothing. The engines that cannot spell the duration must not be tried at all.
//
// The doubling arm does not change this contract, and the reason it is checked
// is that it could have: the long arm is a second duration, and the temptation
// is to let it widen what may be asked. It may not. If the operator said 400 ms,
// a doubled arm may be 800 ms and not a whole second, because the engine that
// cannot spell 400 ms cannot spell 800 ms either and the pair is skipped there
// rather than rounded up to something the operator never chose.
func TestASubSecondDelaySkipsTheEnginesThatCannotSpellIt(t *testing.T) {
	transport, point := newSQLiFixture(t, sleepyPage(300*time.Millisecond))
	(SQLi{BlindDelay: 400 * time.Millisecond}).probe(t, transport, point)
	fixture := sqliFixtureFor(t, transport, point)
	sawFractionalPair := false
	for _, asked := range fixture.requests {
		upper := strings.ToUpper(asked)
		if strings.Contains(upper, "WAITFOR DELAY") {
			t.Fatalf("asked SQL Server for a fraction of a second: %q", asked)
		}
		if strings.Contains(upper, "DBMS_LOCK.SLEEP") {
			t.Fatalf("asked Oracle for a fraction of a second: %q", asked)
		}
		// SQLite is priced in bytes, so a fraction is spellable there and asking
		// for one is correct. What must never happen is a rounded *up* to a whole
		// second: the operator said 400 ms, and a blob sized for a second is a
		// quarter-gigabyte of somebody else's memory that nobody asked for.
		if blob := strings.ToLower(asked); strings.Contains(blob, "randomblob(") {
			size, err := strconv.Atoi(blob[strings.Index(blob, "randomblob(")+len("randomblob(") : strings.Index(blob, ")")])
			if err != nil {
				t.Fatalf("unreadable blob size in %q", asked)
			}
			ceiling := int(float64(2*400*time.Millisecond/time.Millisecond) *
				sqliteBlobBytesPerMillisecond)
			if size > ceiling {
				t.Fatalf("asked SQLite for %d bytes against a ceiling of %d for a 400ms delay: %q",
					size, ceiling, asked)
			}
		}
		if strings.Contains(upper, "SLEEP(0.8)") {
			sawFractionalPair = true
		}
	}
	if !sawFractionalPair {
		t.Error("the doubled arm never asked for 0.8s: the scaling pair is not being measured")
	}
}

// The dialects are separate because no single expression parses on more than one
// of them: a target that runs none of them must not stop the walk at the first
// refusal.
func TestTheDelayWalkReachesTheEngineThatAnswersIt(t *testing.T) {
	transport, point := newSQLiFixture(t, func(param string) (int, string) {
		if asked, ok := askedDelay(param, "WAITFOR"); ok && asked > 0 {
			time.Sleep(asked)
			return 200, "<html><body><table><tr><td>alice</td></tr></table></body></html>"
		}
		return 200, "<html><body><table><tr><td>alice</td></tr></table></body></html>"
	})
	findings := SQLi{BlindDelay: time.Second}.probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("want one finding from the engine that answers, got %d: %s",
			len(findings), titles(findings))
	}
	if !strings.Contains(findings[0].Title, "WAITFOR") {
		t.Errorf("finding does not name the engine whose spelling answered: %q", findings[0].Title)
	}
}

// The delay is a field the operator sets, and an unset field means the documented
// default — not a small number chosen by the detector.
func TestTheDelayIsTheOneTheOperatorSetAndZeroMeansTheDefault(t *testing.T) {
	transport, point := newSQLiFixture(t, sleepyPage(300*time.Millisecond))
	SQLi{}.probe(t, transport, point)
	fixture := sqliFixtureFor(t, transport, point)
	sawDefault := false
	for _, asked := range fixture.requests {
		if strings.Contains(asked, "SLEEP(") && !strings.Contains(asked, "SLEEP(0)") {
			if !strings.Contains(asked, "SLEEP("+delaySeconds(DefaultBlindDelay)+")") {
				t.Fatalf("unset field asked for something other than the default %s: %q",
					DefaultBlindDelay, asked)
			}
			sawDefault = true
		}
	}
	if !sawDefault {
		t.Error("no delay payload was sent at all")
	}
	// The fixture caps every wait, so the default delay never arrives and nothing
	// may be credited. This is the half of the contract that says the detector
	// does not shorten its own probe to make one succeed.
	findings := SQLi{}.probe(t, transport, point)
	for _, got := range findings {
		if strings.Contains(got.Title, "Time-Based Blind") {
			t.Fatalf("credited a delay the target never actually waited out: %q", got.Evidence)
		}
	}
}

// orderByDiagnostic answers with a database diagnostic when the *numeric* sort
// ordinal runs past the last column, and an ordinary page otherwise.
//
// The numeric form is the whole point of the fixture. `breakoutProbes` also
// carries quoted spellings — `1' ORDER BY 1--+` among them — and a fixture that
// complained about those too would be answered by the error technique before the
// ladder is ever walked, so the column-count tests would pass without ever
// reaching `orderByProbe`. Reacting only to `1 ORDER BY ` keeps the technique
// under test the one actually being measured.
func orderByDiagnostic(columns int) func(string) (int, string) {
	return func(param string) (int, string) {
		at := strings.Index(param, "1 ORDER BY ")
		if at >= 0 {
			tail := strings.Trim(param[at+len("1 ORDER BY "):], " -")
			digits := tail
			for i, r := range tail {
				if r < '0' || r > '9' {
					digits = tail[:i]
					break
				}
			}
			if ordinal, err := strconv.Atoi(digits); err == nil && ordinal > columns {
				return 500, "<html>You have an error in your SQL syntax near 'ORDER BY'</html>"
			}
		}
		return 200, "<html><body><table><tr><td>alice</td></tr></table></body></html>"
	}
}

// ORDER BY names the column count from the boundary between the last ordinal the
// statement accepts and the first it refuses, so the number in the report is
// measured rather than assumed.
func TestSQLiNamesTheColumnCountFromTheOrderByBoundary(t *testing.T) {
	transport, point := newSQLiFixture(t, orderByDiagnostic(3))
	findings := SQLi{}.probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("want exactly one finding, got %d: %s", len(findings), titles(findings))
	}
	got := findings[0]
	if !strings.Contains(got.Title, "ORDER BY") || !strings.Contains(got.Title, "3 columns") {
		t.Errorf("title does not carry the measured boundary: %q", got.Title)
	}
	if got.Tier != TierVerified {
		t.Errorf("tier is %q: a diagnostic that was not on the page is a shown fact", got.Tier)
	}
}

// A page that always prints a diagnostic carries no boundary — the string is in
// the baseline, so it says nothing about any ordinal, and a count read from it
// would be a number invented by the detector.
func TestSQLiRefusesAColumnCountOnAPageThatAlwaysPrintsTheDiagnostic(t *testing.T) {
	transport, point := newSQLiFixture(t, orderByDiagnostic(0))
	for _, got := range (SQLi{}).probe(t, transport, point) {
		if strings.Contains(got.Title, "ORDER BY") {
			t.Fatalf("named a column count from a diagnostic the page always prints: %q", got.Evidence)
		}
	}
}

// The ladder has to stop: a refusal at the very first ordinal means the count is
// below the ladder, not that it is zero.
func TestSQLiRefusesAColumnCountWhenTheFirstOrdinalIsRefused(t *testing.T) {
	transport, point := newSQLiFixture(t, orderByDiagnostic(-1))
	findings := (SQLi{}).probe(t, transport, point)
	for _, got := range findings {
		if strings.Contains(got.Title, "ORDER BY") {
			t.Fatalf("named a column count below the ladder: %q", got.Title)
		}
	}
}

// sqliFixtureFor returns the request log of the fixture behind a transport.
//
// The fixture is reached through the server rather than kept by handle, because
// `newSQLiFixture` already exists and rewriting it to also return the log would
// change a helper twenty existing tests share. The log is read by asking the
// transport, which is the only side of the fixture the tests can see.
func sqliFixtureFor(t *testing.T, transport *Transport, p Point) *sqliFixture {
	t.Helper()
	logs := sqliRequestLogs
	if len(logs) == 0 {
		t.Fatal("no request log was recorded for this fixture")
	}
	return logs[len(logs)-1]
}

// sqliRequestLogs holds the log of each fixture in creation order.
var sqliRequestLogs []*sqliFixture

// A fixed amount of slowness is not a delay that scales with the request.
//
// This is the test that came out of a live `.ru` target, and it is the reason the
// rule below exists. The measurement there was: `pg_sleep(1)` answered in 8.2s
// against a baseline of 868ms, so the increment was 7.3s against a one-second
// request and the old rule credited it. Nothing was injected — the page is
// simply slow, and it was slow once. `WAITFOR DELAY '0:0:1'` did the same at
// 608ms. Both were reported as SQL injection on a site that had none.
//
// The old rule asked "is this slower than the baseline, by roughly what I asked
// for". This one asks "is this slower **in proportion** to what I asked for":
// the increment at half the request must be roughly half the increment at the
// full request. A page that is slow by a fixed amount fails that, because its
// increments are equal; a database that waited out the request does not.
func TestADelayThatDoesNotScaleWithTheRequestIsNotADelay(t *testing.T) {
	// The page's cost is fixed and does not read the number in the payload: any
	// request that carries a delay waits the same 1050ms whatever delay was
	// asked for, and a request that carries none waits 600ms.
	//
	// Those two numbers are chosen so that the *old* rule cannot refuse them.
	// The increment is 450ms against a requested 800ms, and the old threshold
	// for that request is `800 - margin` with the margin capped at half — so
	// 400ms, and 450ms clears it. Only the pairing catches this: the long arm
	// waits exactly as long as the short one, the difference between the two
	// increments is zero, and a database that had really waited would have made
	// the second one measurably longer.
	const (
		idle      = 600 * time.Millisecond
		withDelay = 1050 * time.Millisecond
	)
	transport, point := newSQLiFixture(t, func(param string) (int, string) {
		if asked, ok := askedDelay(param, "SLEEP("); ok && asked > 0 {
			time.Sleep(withDelay)
		} else {
			time.Sleep(idle)
		}
		return 200, "<html><body><table><tr><td>alice</td></tr></table></body></html>"
	})
	for _, got := range (SQLi{BlindDelay: 800 * time.Millisecond}).probe(t, transport, point) {
		if strings.Contains(got.Title, "Time-Based Blind") {
			t.Fatalf("credited a page whose slowness does not scale with the request: %q", got.Evidence)
		}
	}
}

// The pairing must not become a loophole: a page that really does wait has to
// survive it, and has to report the second measurement so a reader can check it.
func TestADelayThatScalesWithTheRequestIsStillCredited(t *testing.T) {
	transport, point := newSQLiFixture(t, sleepyPage(4*time.Second))
	findings := (SQLi{BlindDelay: 800 * time.Millisecond}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("want one finding from a page that really waits, got %d: %s",
			len(findings), titles(findings))
	}
	if !strings.Contains(findings[0].Evidence, "grows with the delay") {
		t.Errorf("evidence does not report the second measurement: %q", findings[0].Evidence)
	}
}
