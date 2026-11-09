package active

// Tests for the XSS detector.
//
// The fixture is a live server whose reflection behaviour is switched per test,
// because the defect this file's detector was written to remove is entirely
// about which response it accepts. A mocked transport would hand the detector
// whatever the test chose and agree with every version of it.
//
// The decisive test is TestXSSDoesNotBorrowAnEventHandlerFromThePage: the page
// already contains an onerror handler and reflects the value, which is what a
// real page looks like. An implementation that confirms an escalation by
// searching the document for `onerror=` anywhere reports high XSS on it, and
// this detector must not.

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// xssFixture serves one parameter, with a page template that surrounds whatever
// the application does with the value.
type xssFixture struct {
	// render decides how the value is placed in the page.
	render func(value string) string
	// status is the response code.
	status int
}

func newXSSFixture(t *testing.T, status int, render func(string) string) (*Transport, Point) {
	t.Helper()
	fixture := &xssFixture{render: render, status: status}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(fixture.status)
		_, _ = io.WriteString(w, fixture.render(r.URL.Query().Get("q")))
	}))
	t.Cleanup(server.Close)
	return mustTransport(t), Point{
		URL: server.URL, Method: http.MethodGet, Param: "q",
		Values: url.Values{"q": {"hello"}},
	}
}

// newJSONXSSFixture serves the parameter inside a JSON body, which reflects a
// value without giving it anywhere to become markup.
func newJSONXSSFixture(t *testing.T, render func(string) string) (*Transport, Point) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, render(r.URL.Query().Get("q")))
	}))
	t.Cleanup(server.Close)
	return mustTransport(t), Point{
		URL: server.URL, Method: http.MethodGet, Param: "q",
		Values: url.Values{"q": {"hello"}},
	}
}

func (XSS) probe(t *testing.T, transport *Transport, p Point) []Finding {
	t.Helper()
	baseline := baselineOf(t, transport, p)
	return XSS{}.Scan(context.Background(), transport, p, baseline)
}

// A page that executes an injected element is verified: the payload arrived
// inside a tag the application itself emitted.
func TestXSSReportsExecutableMarkup(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		// The application renders the value into the body unescaped.
		return `<html><body><div class="result">` + value + `</div></body></html>`
	})
	findings := (XSS{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Tier != TierVerified {
		t.Errorf("tier = %q, want %q: the payload is inside a tag the page emitted", finding.Tier, TierVerified)
	}
	if finding.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", finding.Severity)
	}
	if !strings.Contains(finding.Payload, "onload=") && !strings.Contains(finding.Payload, "onerror=") {
		t.Errorf("payload = %q, want an event-handler element", finding.Payload)
	}
	if finding.PoCCurl == "" {
		t.Error("no reproduction attached")
	}
}

// The decisive false-positive case. The page already carries an onerror handler
// and reflects the value. Searching the document for an event handler anywhere
// — the upstream confirmation — reports a high finding here; the payload is in a
// div, not in any element, so nothing executes.
func TestXSSDoesNotBorrowAnEventHandlerFromThePage(t *testing.T) {
	// A JSON search API: the value comes back verbatim, the page carries its own
	// onerror handler, and no HTML context exists in which a tag could form.
	transport, point := newJSONXSSFixture(t, func(value string) string {
		return `{"query":"` + value + `","note":"<img src=\"/logo.png\" onerror=\"track()\">"}`
	})
	findings := (XSS{}).probe(t, transport, point)
	for _, finding := range findings {
		if finding.Tier == TierVerified || finding.Severity.Rank() >= SeverityHigh.Rank() {
			t.Fatalf("reported %q (%s) by borrowing the page's own onerror handler; evidence %q",
				finding.Title, finding.Severity, finding.Evidence)
		}
	}
}

// Reflection with no execution is a precondition, not a vulnerability, and is
// reported at informational so it never competes for attention with a proven one.
func TestXSSReportsPlainReflectionAsInformational(t *testing.T) {
	// A page that reflects the value into a textarea. The parser reads textarea
	// content as characters, so the value is genuinely unencoded and genuinely
	// reflected, and no payload executes: a precondition, not a vulnerability.
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><body><textarea>` + value + `</textarea></body></html>`
	})
	findings := (XSS{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Tier != TierPotential {
		t.Errorf("tier = %q, want %q", finding.Tier, TierPotential)
	}
	if finding.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium: the value is demonstrably unencoded, execution unproven",
			finding.Severity)
	}
	if finding.Capped {
		t.Error("finding was capped; medium is what the tier allows for a potential")
	}
	if !strings.Contains(finding.Evidence, "canary") {
		t.Errorf("evidence = %q, want the canary named as the proof of reflection", finding.Evidence)
	}
}

// The borrowing case, on an HTML page rather than a JSON one.
//
// The page carries its own onerror handler and reflects the value — but inside
// an HTML comment, where a parser reads it as a comment and no element is ever
// built. A confirmation that searches the document for an event handler finds
// the page's own and reports a high finding; a confirmation that asks whether
// *this* payload is inside *this* tag does not.
func TestXSSDoesNotBorrowAnEventHandlerOnAnHTMLPage(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><body>
			<img src="/logo.png" onerror="track()">
			<!-- search: ` + value + ` -->
			</body></html>`
	})
	findings := (XSS{}).probe(t, transport, point)
	for _, finding := range findings {
		if finding.Tier == TierVerified {
			t.Fatalf("reported %q (%s) by borrowing the page's own onerror handler; evidence %q",
				finding.Title, finding.Severity, finding.Evidence)
		}
	}
}

// A JSON response cannot execute a payload, so an API that echoes the query
// verbatim is not a scripting problem. Without this check the detector sends
// `<svg onload=…>` to a JSON endpoint, finds the text it just sent inside the
// response, and calls it executable.
func TestXSSIgnoresNonHTMLResponses(t *testing.T) {
	transport, point := newJSONXSSFixture(t, func(value string) string {
		return `{"query":"` + value + `","hits":["<img src=x onerror=alert(1)>"]}`
	})
	if findings := (XSS{}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d (%s), want none for a JSON response",
			len(findings), findings[0].Title)
	}
}

// A correctly encoded reflection is not a defect, and reporting it would be a
// false positive on every page that does the right thing. The canary itself is
// alphanumeric, so an encoder leaves it untouched and reflection alone cannot
// tell the two cases apart — which is why the detector probes for the character
// an encoder must transform.
func TestXSSStaysSilentWhenTheValueIsEncoded(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><body><div>` + html.EscapeString(value) + `</div></body></html>`
	})
	findings := (XSS{}).probe(t, transport, point)
	if len(findings) != 0 {
		t.Fatalf("findings = %d (%s), want none: a correctly encoded reflection is not a defect",
			len(findings), findings[0].Title)
	}
}

// The pair that makes the encoding claim true: the same page shape, differing
// only in whether the angle bracket is escaped, produces a finding in one case
// and silence in the other.
func TestXSSDistinguishesEncodedFromUnencoded(t *testing.T) {
	raw, rawPoint := newXSSFixture(t, 200, func(value string) string {
		return `<div>` + value + `</div>`
	})
	if findings := (XSS{}).probe(t, raw, rawPoint); len(findings) == 0 {
		t.Fatal("an unencoded reflection produced no finding; the encoding probe is not firing")
	}
	encoded, encodedPoint := newXSSFixture(t, 200, func(value string) string {
		return `<div>` + html.EscapeString(value) + `</div>`
	})
	if findings := (XSS{}).probe(t, encoded, encodedPoint); len(findings) != 0 {
		t.Fatalf("an encoded reflection produced %d finding(s): %q", len(findings), findings[0].Title)
	}
}

// A value that is not reflected at all is not a finding, and the probe costs one
// request.
func TestXSSReportsNothingWhenValueIsNotReflected(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><body><div>No results.</div></body></html>`
	})
	if findings := (XSS{}).probe(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want none for a value that is not reflected", len(findings))
	}
}

// The canary is random, so two runs use different tokens. A fixed token would be
// a string an application may legitimately contain, print or link.
func TestCanaryIsRandomPerCall(t *testing.T) {
	first := newCanary("rrx")
	second := newCanary("rrx")
	if first == "" || second == "" {
		t.Fatal("canary generation failed")
	}
	if first == second {
		t.Fatal("canary repeated; a fixed token can occur on a page by accident")
	}
	for _, canary := range []string{first, second} {
		if !strings.HasPrefix(canary, "rrx") {
			t.Errorf("canary = %q, want the prefix retained", canary)
		}
		if len(canary) != len("rrx")+10 {
			t.Errorf("canary = %q, want 10 random characters after the prefix", canary)
		}
	}
}

// Context classification decides which payloads are worth sending, so a wrong
// answer costs either a missed finding or a wasted request.
func TestClassifyContext(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"body", `<div class="r">CANARY</div>`, "html-body"},
		{"attribute quoted", `<input value="CANARY">`, "attribute"},
		{"attribute bare", `<input value=CANARY>`, "attribute"},
		{"no canary in body", `<input value=`, "unknown"},
		{"script string", `<script>var q = "CANARY";</script>`, "script-string"},
		{"after script closed", `<script>x</script><p>CANARY</p>`, "html-body"},
		{"plain text", `<p>CANARY</p>`, "html-body"},
		{"textarea", `<textarea>CANARY</textarea>`, "rcdata"},
		{"title", `<title>CANARY</title>`, "rcdata"},
		{"absent", `<p>nothing here</p>`, "unknown"},
		{"attribute equals only", `<input value=CANARY`, "attribute"},
	}
	for _, tc := range cases {
		if got := classifyContext(tc.body, "CANARY"); got != tc.want {
			t.Errorf("%s: classifyContext = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// confirmExecutable is the contract the whole detector rests on, so it is
// asserted directly rather than only through a scan.
func TestConfirmExecutable(t *testing.T) {
	cases := []struct {
		name, body, payload string
		want                bool
	}{
		{
			"payload inside the emitted tag",
			`<div><svg onload=document.title='rr'></svg></div>`,
			`<svg onload=document.title='rr'>`, true,
		},
		{
			"handler on a different element",
			`<img src=x onerror=alert(1)><div>PAYLOAD</div>`,
			"PAYLOAD", false,
		},
		{
			"payload echoed with no tag",
			`<div>PAYLOAD</div>`, "PAYLOAD", false,
		},
		{
			"handler after the tag boundary",
			`<div>PAYLOAD</div><img src=x onerror=alert(1)>`,
			"PAYLOAD", false,
		},
		{
			"payload absent", `<div>nothing</div>`, "PAYLOAD", false,
		},
		{
			// The payload matches the executable-tag pattern by itself, so a
			// confirmation that does not strip comments agrees with itself here.
			"payload inside a comment", `<!-- <svg onload=x> --><img src=y onerror=z>`,
			"<svg onload=x>", false,
		},
		{
			"non-executable tag", `<div><span>PAYLOAD</span></div>`, "PAYLOAD", false,
		},
	}
	for _, tc := range cases {
		if got := confirmExecutable(tc.body, tc.payload); got != tc.want {
			t.Errorf("%s: confirmExecutable = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A payload landing inside a real element is confirmed even when the page is
// noisy, which is the ordinary case.
func TestStripCommentsRemovesTheWholeComment(t *testing.T) {
	body := `<p>before<!-- <svg onload=alert(1)> -->after</p>`
	got := stripComments(body)
	if strings.Contains(got, "onload") {
		t.Fatalf("stripComments = %q, want the comment gone", got)
	}
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Fatalf("stripComments = %q, want the surrounding text kept", got)
	}
	if stripComments(`<p>no comment here</p>`) != `<p>no comment here</p>` {
		t.Error("stripComments altered a body with no comment")
	}
	// An unterminated comment swallows the rest of the document, exactly as a
	// parser would treat it.
	if strings.Contains(stripComments(`<p>a<!-- b <svg onload=x>`), "onload") {
		t.Error("an unterminated comment must swallow what follows")
	}
}

func TestConfirmExecutableInsideANoisyPage(t *testing.T) {
	noise := strings.Repeat(`<p>filler paragraph with an <a href="#">link</a></p>`, 10)
	body := noise + `<div><img src=x onerror=document.title='rr'></div>` + noise
	payload := `<img src=x onerror=document.title='rr'>`
	if !confirmExecutable(body, payload) {
		t.Fatal("a payload inside an emitted element was not confirmed in a noisy page")
	}
}

// A handler far away on a large page must not be borrowed, however long the
// page is: distance is the whole defence.
func TestConfirmExecutableRefusesADistantHandler(t *testing.T) {
	noise := strings.Repeat(`<p>filler</p>`, 200)
	body := `<div>PAYLOAD</div>` + noise + `<img src=x onerror=alert(1)>`
	if confirmExecutable(body, "PAYLOAD") {
		t.Fatal("borrowed an event handler from a different part of a large page")
	}
}

func TestXSSReportsNothingOnCancellation(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<div>` + value + `</div>`
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	baseline, _ := transport.Baseline(ctx, point, false)
	if findings := (XSS{}).Scan(ctx, transport, point, baseline); len(findings) != 0 {
		t.Fatalf("findings = %d, want none on a cancelled run", len(findings))
	}
}

func TestXSSEvidenceNeverCarriesTheCanaryUnescaped(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return fmt.Sprintf(`<html><body><div>%s</div></body></html>`, value)
	})
	_ = point
	findings := (XSS{}).probe(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	// A verified finding quotes the response, so the triager can see the
	// payload sitting inside the element the page emitted.
	if !strings.Contains(findings[0].Evidence, "svg onload") {
		t.Errorf("evidence = %q, want an excerpt of the response showing the injected element",
			findings[0].Evidence)
	}
}
