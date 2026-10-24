package active

// Tests for the context-escape detector.
//
// The fixture is a live server whose reflection behaviour is decided per test,
// for the reason `detect_xss_test.go` gives: what this module accepts and
// rejects *is* the module, and a mocked transport would agree with every
// version of it.
//
// Three of these tests exist to fail against the plausible wrong implementations,
// not to pass against the right one:
//
//   - a JavaScript-string break must use the delimiter the application used, so a
//     value inside a single-quoted string is not reported by a double-quoted
//     payload that appears verbatim in the response and executes nothing;
//   - a payload echoed into the page's own markup is not a `javascript:` URI, so
//     the link rule must reject text that merely contains `href="javascript:`;
//   - a reflection inside `<script type="application/ld+json">` is data, not
//     code, and reporting it is the classic schema-block false positive.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func (XSSEscape) probeAt(t *testing.T, transport *Transport, p Point) []Finding {
	t.Helper()
	baseline := baselineOf(t, transport, p)
	return XSSEscape{}.Scan(context.Background(), transport, p, baseline)
}

// A value inside a textarea is character data, so the existing detector skips
// it. Closing the element first is XSSTRON's answer and it is the one this
// module carries.
func TestXSSEscapeBreaksOutOfTextarea(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><body><textarea name="q">` + value + `</textarea></body></html>`
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Tier != TierVerified {
		t.Errorf("tier = %q, want %q", finding.Tier, TierVerified)
	}
	if !strings.Contains(finding.Payload, "</textarea>") {
		t.Errorf("payload = %q, want the RCDATA close chain", finding.Payload)
	}
	if !strings.Contains(finding.Payload, "onerror=") {
		t.Errorf("payload = %q, want an event handler after the chain", finding.Payload)
	}
	if finding.PoCCurl == "" {
		t.Error("no reproduction attached")
	}
}

// The control for the test above: an application that escapes the value is not
// vulnerable, and reporting it would be a false positive on every correct page.
func TestXSSEscapeDoesNotReportEscapedTextarea(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><body><textarea name="q">` + escapeAttr(value) + `</textarea></body></html>`
	})
	if findings := (XSSEscape{}).probeAt(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: the value was HTML-escaped", len(findings))
	}
}

// A JavaScript string that the value landed in is terminated with its own
// delimiter.
func TestXSSEscapeTerminatesJavaScriptStringWithItsOwnQuote(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><body><script>var other = "https://example.test/"; var q = '` + value + `';</script></body></html>`
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Tier != TierVerified {
		t.Errorf("tier = %q, want %q", finding.Tier, TierVerified)
	}
	if !strings.HasPrefix(finding.Payload, "'") {
		t.Errorf("payload = %q, want a payload that starts with the single quote the page used", finding.Payload)
	}
	if !strings.Contains(finding.Evidence, "var q") {
		t.Errorf("evidence = %q, want the script line the payload landed in", finding.Evidence)
	}
}

// The decisive false-positive case for the rule above. The value is inside a
// single-quoted string and a double-quoted payload comes back verbatim — its `//`
// comments out the rest of the line and nothing runs. The naive implementation
// reports critical XSS here.
func TestXSSEscapeDoesNotTerminateStringWithTheWrongQuote(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><body><script>var q = '` + value + `';</script></body></html>`
	})
	// The wrong-delimiter payload does come back verbatim...
	payload := `"` + "-" + xsseProof + `//`
	resp, err := transport.Fire(context.Background(), point, point.Param, payload, false, nil)
	if err != nil || !strings.Contains(resp.Body, payload) {
		t.Fatalf("fixture does not reflect the wrong-delimiter payload: %v", err)
	}
	// ...and it must not be reported.
	for _, finding := range (XSSEscape{}).probeAt(t, transport, point) {
		if strings.HasPrefix(finding.Payload, `"`) {
			t.Fatalf("reported a break that never happened: %q", finding.Title)
		}
	}
}

// A schema.org block is parsed as JSON. A browser never executes it, so a
// finding there would be a critical row on a page that has nothing wrong with it.
func TestXSSEscapeIgnoresJSONScriptBlock(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><head><script type="application/ld+json">{"name":"` + value + `"}</script></head>` +
			`<body></body></html>`
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	for _, finding := range findings {
		// The block holds data, so no payload that *reads* it as JavaScript may be
		// reported: a string breakout there changes nothing, because nothing in a
		// schema.org block is executed.
		if !strings.Contains(finding.Payload, "</script>") {
			t.Errorf("reported %q as executable, but the block holds data and never parses it",
				finding.Payload)
		}
	}
}

// The control for the row above, and the reason the assertion above is not simply
// "no findings": the content of a `application/ld+json` block *is* raw text, so
// `</script>` ends the element and the markup after it is parsed by the browser.
// That is a different mechanism from a string breakout inside the block, and it is
// real — which is why the finding is allowed and only the in-band one is refused.
func TestXSSEscapeClosesTheJSONScriptElement(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><head><script type="application/ld+json">{"name":"` + value + `"}</script></head>` +
			`<body></body></html>`
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: closing the element reaches markup", len(findings))
	}
	if !strings.HasPrefix(findings[0].Payload, "</script><svg onload=") {
		t.Errorf("payload = %q, want the element close", findings[0].Payload)
	}
}

// A template literal is closed with its own backtick. The `'` and `"` payloads
// of an earlier version of this table did nothing here: they were read as text
// inside the literal, and the test that proved it was the one that counted.
func TestXSSEscapeClosesTheTemplateLiteralItFound(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return "<html><body><script>var q = `" + value + "`;</script></body></html>"
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.HasPrefix(findings[0].Payload, "`") {
		t.Errorf("payload = %q, want it to close the template literal with a backtick", findings[0].Payload)
	}
}

// A value inside `${…}` is in code, and the substitution's own `}` is still open:
// closing only the literal's backtick leaves the substitution unterminated, and
// the browser reads the rest of the line as part of the expression.
func TestXSSEscapeClosesTheSubstitutionBeforeTheLiteral(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return "<html><body><script>var q = `label: ${" + value + "}`;</script></body></html>"
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	payload := findings[0].Payload
	if !strings.HasPrefix(payload, "}`") {
		t.Errorf("payload = %q, want it to close the substitution and then the literal", payload)
	}
}

// A `javascript:` URI written into a link is a scripting problem even though it
// builds no element with an event handler.
func TestXSSEscapeReportsJavascriptURIInHref(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><body><a href="` + value + `">next</a></body></html>`
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Tier != TierVerified {
		t.Errorf("tier = %q, want %q", finding.Tier, TierVerified)
	}
	if !strings.Contains(finding.Payload, "javascript:") {
		t.Errorf("payload = %q, want a javascript: URI", finding.Payload)
	}
	if !strings.Contains(finding.Evidence, "href=") {
		t.Errorf("evidence = %q, want the attribute the page built", finding.Evidence)
	}
}

// The control for the rule above: the page documents the string itself and
// escapes whatever it is given, so no attribute is ever built from the input.
func TestXSSEscapeDoesNotReportJavascriptURIAsText(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><body><p>the string href=&quot;javascript:alert(1)&quot; is documented here; ` +
			`you typed: ` + escapeAttr(value) + `</p></body></html>`
	})
	if findings := (XSSEscape{}).probeAt(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: no attribute was built", len(findings))
	}
}

// An unquoted attribute value ends at a space, so a payload that opens with a
// double quote cannot escape it. This is the shape XSSTRON sends.
func TestXSSEscapeBreaksUnquotedAttributeValue(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><body><p title=` + value + ` class="c">text</p></body></html>`
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Payload, "onclick=") {
		t.Errorf("payload = %q, want the unquoted-attribute shape", findings[0].Payload)
	}
	if findings[0].Tier != TierVerified {
		t.Errorf("tier = %q, want %q", findings[0].Tier, TierVerified)
	}
}

// An unquoted href takes the scheme directly, so the javascript: rule applies
// without a quote anywhere in the exchange.
func TestXSSEscapeReportsJavascriptURIInUnquotedHref(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><body><a href=` + value + ` class="c">next</a></body></html>`
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.HasPrefix(findings[0].Payload, "javascript:") {
		t.Errorf("payload = %q, want a javascript: URI", findings[0].Payload)
	}
}

// A filter written against one spelling of a tag is not a control. This fixture
// drops exactly the string `<svg onload=`, which is the spelling the existing
// detector sends first; the slash-separator shape is what gets through.
func TestXSSEscapeReachesBodyThroughFilterSpecificSpelling(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		cleaned := strings.ReplaceAll(value, "<svg onload=", "")
		return `<html><body><div>` + cleaned + `</div></body></html>`
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Payload, "<svg/onload=") {
		t.Errorf("payload = %q, want the slash-separated spelling", findings[0].Payload)
	}
}

// A page that escapes everything is the common case and must stay silent.
func TestXSSEscapeIsSilentOnEscapedPage(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><body><div>` + escapeAttr(value) + `</div>` +
			`<script>var q = "` + escapeAttr(value) + `";</script></body></html>`
	})
	if findings := (XSSEscape{}).probeAt(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}

// A JSON endpoint reflects any string it is sent. There is no context to leave,
// so escalating against it is the false positive the whole HTML check exists for.
func TestXSSEscapeIsSilentOnJSONResponse(t *testing.T) {
	transport, point := newJSONXSSFixture(t, func(value string) string {
		return `{"echo":"` + value + `"}`
	})
	if findings := (XSSEscape{}).probeAt(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: a JSON document has no markup context", len(findings))
	}
}

// A parameter the page does not reflect is not an injection surface.
func TestXSSEscapeIsSilentWithoutReflection(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(string) string {
		return `<html><body><div>no user input here</div></body></html>`
	})
	if findings := (XSSEscape{}).probeAt(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}

// escapeAttr is the encoding an ordinary templating engine applies. It is
// spelled out here rather than reused from the fixtures so that a change to a
// shared helper cannot silently turn these controls into passes.
func escapeAttr(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&#34;",
		"'", "&#39;",
	)
	return replacer.Replace(value)
}

// Every payload the detector sends against a single-quoted JavaScript string
// must begin with that quote.
//
// This is the test that pins the delimiter rule itself rather than its result.
// Without it, removing the filter would still look correct: the correct payload
// is sent first and confirms, so the reported finding is the same either way and
// only the wasted requests differ — which is exactly the kind of change that
// reaches production unnoticed.
func TestXSSEscapeOnlySendsThePagesOwnQuote(t *testing.T) {
	var mu sync.Mutex
	var sent []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("q")
		mu.Lock()
		sent = append(sent, value)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w,
			`<html><body><script>var q = '`+value+`';</script></body></html>`)
	}))
	t.Cleanup(server.Close)
	transport := mustTransport(t)
	point := Point{URL: server.URL, Method: http.MethodGet, Param: "q", Values: url.Values{"q": {"hello"}}}
	_ = (XSSEscape{}).probeAt(t, transport, point)

	mu.Lock()
	defer mu.Unlock()
	if len(sent) < 2 {
		t.Fatalf("saw %d requests, want at least the baseline and one payload", len(sent))
	}
	for _, query := range sent[1:] {
		if isXSSEscapeProbePayload(query) {
			// The filter profile asks one question with every special character in
			// it, quotes included. That is the probe, not an escape attempt, and a
			// test that read it as one would be reading the detector's diagnostics
			// as its payload.
			continue
		}
		if !strings.ContainsAny(query, "'\"`<>=") {
			// The reflection probe itself carries an alphanumeric canary.
			continue
		}
		if !strings.HasPrefix(query, "'") {
			t.Fatalf("sent a payload the page's own quote cannot terminate: %q", query)
		}
	}
}

// The helpers carry the decisions the module makes, so they are tested directly:
// a fixture that exercises them end-to-end can pass for a reason that has
// nothing to do with the rule under test.
func TestXSSEscapeHelpers(t *testing.T) {
	cases := []struct {
		name string
		got  bool
		want bool
	}{
		{"javascript uri in href",
			javascriptURIAssigns(`<a href="`+`javascript:/*x*/`+`">`, `javascript:/*x*/`), true},
		{"javascript uri unquoted",
			javascriptURIAssigns(`<a href=`+`javascript:/*x*/`+` class=c>`, `javascript:/*x*/`), true},
		{"relative url carrying the scheme text",
			javascriptURIAssigns(`<a href="/go?q=`+`javascript:/*x*/`+`">`, `javascript:/*x*/`), false},
		{"scheme text in a paragraph",
			javascriptURIAssigns(`<p>use href="`+`javascript:/*x*/`+`" here</p>`, `javascript:/*x*/`), false},
		{"payload not in the response",
			javascriptURIAssigns(`<a href="javascript:">`, `javascript:/*x*/`), false},
		{"payload without the scheme",
			javascriptURIAssigns(`<a href="`+`/x`+`">`, `/x`), false},
		{"inside a tag", insideOpenTag(`<a title="VALUE`, strings.Index(`<a title="VALUE`, "VALUE")), true},
		{"after a closed tag", insideOpenTag(`<p>text VALUE`, strings.Index(`<p>text VALUE`, "VALUE")), false},
		{"in raw text, payload leaves it", insideRawTextElement(`<textarea>VALUE`,
			strings.Index(`<textarea>VALUE`, "VALUE"), `--></textarea><img src=x onerror=x>`), false},
		{"in raw text, payload stays", insideRawTextElement(`<textarea>VALUE`,
			strings.Index(`<textarea>VALUE`, "VALUE"), `<img src=x onerror=x>`), true},
		{"in raw text that already closed", insideRawTextElement(`<textarea>x</textarea>VALUE`,
			strings.Index(`<textarea>x</textarea>VALUE`, "VALUE"), `<img src=x onerror=x>`), false},
		{"inside plaintext, nothing closes it", insideRawTextElement(`<plaintext>VALUE`,
			strings.Index(`<plaintext>VALUE`, "VALUE"), `--></plaintext>`), true},
		{"text position", insideRawTextElement(`<p>VALUE`,
			strings.Index(`<p>VALUE`, "VALUE"), `<img src=x onerror=x>`), false},
		{"executable element injected",
			confirmInjectedElement(`<div>`+`<img src=x onerror=document.title='rrxe'>`+`</div>`,
				`<img src=x onerror=document.title='rrxe'>`), true},
		{"markup injected into an attribute",
			confirmInjectedElement(`<a href="`+`<img src=x onerror=x>`+`">`, `<img src=x onerror=x>`), false},
		{"markup injected into a comment",
			confirmInjectedElement(`<!--`+`<img src=x onerror=x>`+`-->`, `<img src=x onerror=x>`), false},
		{"payload without an event handler",
			confirmInjectedElement(`<div>`+`<b>bold</b>`+`</div>`, `<b>bold</b>`), false},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

// The delimiter is read from the characters around the reflection, not from the
// nearest quote in the document: a real page carries quotes of its own.
func TestXSSEscapeDelimiterIgnoresQuotesThatBelongToThePage(t *testing.T) {
	body := `<script>var api = "https://example.test/"; var q = 'CANARY';</script>`
	if got := jsStringDelimiter(body, "CANARY"); got != "'" {
		t.Errorf("delimiter = %q, want %q", got, "'")
	}
	if got := jsStringDelimiter("<script>var q = `CANARY`;</script>", "CANARY"); got != "`" {
		t.Errorf("backtick delimiter = %q, want %q", got, "`")
	}
	if got := jsStringDelimiter(`<script>var q = CANARY;</script>`, "CANARY"); got != "" {
		t.Errorf("code position delimiter = %q, want empty", got)
	}
}

// The handler name is the token the page had to accept, not the expression that
// follows it.
func TestXSSEscapeEventHandlerName(t *testing.T) {
	cases := map[string]string{
		`x id=clx onclick=document.title='rrxe'// `:       "onclick",
		`' id="clx" onclick="document.title='rrxe'//"" '`: "onclick",
		`<img src=x onerror=alert(1)>`:                    "onerror",
		`plain text`:                                      "",
	}
	for payload, want := range cases {
		if got := eventHandlerName(payload); got != want {
			t.Errorf("eventHandlerName(%q) = %q, want %q", payload, got, want)
		}
	}
}

// A script block holding data is not a code context, whatever the reflection did.
func TestXSSEscapeScriptTypeGatesTheStringBreak(t *testing.T) {
	if scriptIsExecutable(` type="module"`) != true {
		t.Error("a module script is code")
	}
	if scriptIsExecutable(` type="application/ld+json"`) != false {
		t.Error("a schema.org block is data")
	}
	if scriptIsExecutable(` type="text/babel"`) != true {
		t.Error("babel is transpiled into code")
	}
	if scriptIsExecutable(``) != true {
		t.Error("no type attribute means JavaScript")
	}
}

// ---------------------------------------------------------------------------
// The closer is computed from the script the application emitted, not chosen
// from a table. Each test below fails against the table version, because the
// table version's payload comes back in the response and runs nothing.
// ---------------------------------------------------------------------------

// `f('x')` — closing the string is not enough: the call is still open, so the
// statement the payload starts is swallowed as a further argument.
func TestXSSEscapeClosesTheCallAroundAString(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return "<html><body><script>render('" + value + "');</script></body></html>"
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.HasPrefix(findings[0].Payload, "')") {
		t.Errorf("payload = %q, want it to close the string and then the call", findings[0].Payload)
	}
	// The title names the construct, because a row that says only "closed"
	// sends the reader to look for the bug in the wrong place.
	if !strings.Contains(findings[0].Title, "single-quoted string") {
		t.Errorf("title = %q, want it to name the construct the closer belongs to", findings[0].Title)
	}
}

// The same argument for an object literal, which is the shape a template
// renderer and every JSON-in-a-attribute trick produce.
func TestXSSEscapeClosesAnObjectLiteralAroundAString(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return "<html><body><script>var cfg = {label: '" + value + "', id: 7};</script></body></html>"
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.HasPrefix(findings[0].Payload, "'}") {
		t.Errorf("payload = %q, want it to close the string and then the literal", findings[0].Payload)
	}
}

// A value in the script's code position that sits at the end of a line comment
// needs a newline, not a quote: everything up to the newline is discarded.
func TestXSSEscapeEndsALineComment(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		// The comment has to open before the reflection: a `//` written after it
		// comments out the payload, not the value.
		return "<html><body><script>// search term: " + value + "\nvar n = 1;</script></body></html>"
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.HasPrefix(findings[0].Payload, "\n;") {
		t.Errorf("payload = %q, want it to end the line comment with a newline, then the statement", findings[0].Payload)
	}
}

// A block comment swallows the same way, and its closer is two characters.
func TestXSSEscapeEndsABlockComment(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return "<html><body><script>var q = /*" + value + "*/ var n = 1;</script></body></html>"
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.HasPrefix(findings[0].Payload, "*/;") {
		t.Errorf("payload = %q, want it to end the block comment, then the statement", findings[0].Payload)
	}
}

// A `<style>` block is raw text, so a tag written into it is a declaration the
// parser never executes. The payload has to close the element first.
func TestXSSEscapeReportsStyleElementBreakout(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return "<html><head><style>body:before{content:'" + value + "'}</style></head><body></body></html>"
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Tier != TierVerified {
		t.Errorf("tier = %q, want %q", finding.Tier, TierVerified)
	}
	if !strings.Contains(finding.Payload, "</style>") {
		t.Errorf("payload = %q, want it to close the style element first", finding.Payload)
	}
	if !strings.Contains(finding.Payload, "onload=") {
		t.Errorf("payload = %q, want an event handler after the element close", finding.Payload)
	}
}

// A `style` attribute is a different context from a `<style>` element: the tag
// already exists, and the payload's job is to hand that tag a handler.
func TestXSSEscapeReportsStyleAttributeBreakout(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><body><div style="width:` + value + `">x</div></body></html>`
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Tier != TierVerified {
		t.Errorf("tier = %q, want %q", finding.Tier, TierVerified)
	}
	if !strings.HasPrefix(finding.Payload, `" onmouseover=`) {
		t.Errorf("payload = %q, want it to end the attribute and add a handler to the tag", finding.Payload)
	}
}

// The control for the two style rules: a page that has no style sheet must not
// be reported as if it had one. `textarea` is raw text as well, and its content
// is shown rather than parsed, so the escape that applies there is the element
// close and not `</style>`.
func TestXSSEscapeDoesNotInventAStyleSheet(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><body><textarea name="note">style: ` + value + `</textarea></body></html>`
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Payload, "</textarea>") {
		t.Errorf("payload = %q, want the RCDATA close chain", findings[0].Payload)
	}
	if !strings.HasPrefix(findings[0].Payload, "-->") {
		t.Errorf("payload = %q, want the raw-text close rather than a style-sheet close", findings[0].Payload)
	}
}

// TestJSBreakoutPlanReadsTheScriptsOwnText is the table behind the payload
// choice. Every row is a shape a real template emits; the closer is what has to
// be closed for the next characters to be code.
func TestJSBreakoutPlanReadsTheScriptsOwnText(t *testing.T) {
	cases := []struct {
		prefix     string
		wantCloser string
		wantName   string
	}{
		{"var q = '", "'", "single-quoted string"},
		{"var q = \"", "\"", "double-quoted string"},
		{"var q = `", "`", "template literal"},
		{"render('", "')", "single-quoted string"},
		{"var cfg = {label: '", "'}", "single-quoted string"},
		{"if (ok) { push([", "])}", "unclosed bracket"},
		{"var q = `label: ${", "}`", "template literal"},
		{"var q = ", "", "code position"},
		{"var q = 1 // ", "\n", "a line comment"},
		{"var q = 1 /* ", "*/", "a block comment"},
		{"var q = 'it\\'s '", "", "code position"},
	}
	for _, tc := range cases {
		closer, name := jsBreakoutPlan(tc.prefix)
		if closer != tc.wantCloser || name != tc.wantName {
			t.Errorf("jsBreakoutPlan(%q) = (%q, %q), want (%q, %q)",
				tc.prefix, closer, name, tc.wantCloser, tc.wantName)
		}
	}
}

// A long tail of open brackets is bounded, so a page that ships a minified
// script cannot make the scanner walk without end.
func TestJSBreakoutPlanBoundsTheBracketDepth(t *testing.T) {
	prefix := strings.Repeat("(", 4096)
	closer, name := jsBreakoutPlan(prefix)
	if strings.Count(closer, ")") != 256 {
		t.Errorf("closer holds %d parens, want the 256 the scanner is bounded to", strings.Count(closer, ")"))
	}
	if name != "unclosed bracket" {
		t.Errorf("name = %q, want %q", name, "unclosed bracket")
	}
}

// TestInStyleContextTellsTheTwoStyleContextsApart checks the rule that decides
// which of the two style escapes is even possible at a reflection point.
func TestInStyleContextTellsTheTwoStyleContextsApart(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{`<div style="width:VALUE">`, true},
		{`<div style='width:VALUE'>`, true},
		{`<style>body{content:'VALUE'}`, true},
		{`<textarea>style VALUE</textarea>`, false},
		{`<textarea>VALUE</textarea><p>style</p>`, false},
		{`<style>a{}</style><p>VALUE style</p>`, false},
		{`<div class="style">VALUE</div>`, false},
	}
	for _, tc := range cases {
		if got := inStyleContext(tc.body, strings.Index(tc.body, "VALUE")); got != tc.want {
			t.Errorf("inStyleContext(%q) = %v, want %v", tc.body, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// The filter profile, the regex literal, and the catalogue that answers a
// closer the scanner computed wrongly.
// ---------------------------------------------------------------------------

// A target that drops `<` and `>` cannot be reached by a markup payload, and the
// finding that survives is the `javascript:` URI — which contains neither. A
// detector that switched the whole surface off on the profile would report
// nothing where a real problem exists.
func TestXSSEscapeKeepsTheURIFindingWhenMarkupIsFiltered(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		stripped := strings.NewReplacer("<", "", ">", "").Replace(value)
		return `<html><body><a href="` + stripped + `">next</a></body></html>`
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: the URI payload needs no markup characters", len(findings))
	}
	if !strings.Contains(findings[0].Payload, "javascript:") {
		t.Errorf("payload = %q, want the javascript: URI", findings[0].Payload)
	}
}

// The control for the row above: with no filter at all the same page is reached
// by the markup payload too, so the profile is what changed the route and not the
// page.
func TestXSSEscapeReachesTheSamePageWithoutAProfile(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><body><a href="` + value + `">next</a></body></html>`
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Payload, "javascript:") {
		t.Errorf("payload = %q, want the javascript: URI", findings[0].Payload)
	}
}

// A profile is one request and reads only what came back *between* the markers:
// the page below repeats `<` elsewhere, and a detector that looked at the whole
// body would conclude `<` survived.
func TestXSSEscapeFilterReadsOnlyTheReflectedSegment(t *testing.T) {
	// The page carries real `<` and `>` in its own markup and escapes the
	// submitted value. A detector that looked for the characters anywhere in the
	// body would read the page's own tags as evidence that `<` survives, and would
	// then send markup payloads the application never emits — so this fixture is
	// the one that separates the two readings.
	transport, point := newXSSFixture(t, 200, func(value string) string {
		stripped := strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(value)
		return `<html><body><p class="lead"><b>guide</b> and <i>notes</i></p>` +
			`<a href="` + stripped + `">next</a></body></html>`
	})
	if findings := (XSSEscape{}).probeAt(t, transport, point); len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	filter := probeFilter(context.Background(), transport, point, baselineOf(t, transport, point))
	if filter.invalid == nil {
		t.Fatal("no profile: the probe request did not come back")
	}
	if !filter.invalid['<'] || !filter.invalid['>'] {
		t.Errorf("profile marks '<' invalid = %v, '>' invalid = %v, want both true: the page escaped them",
			filter.invalid['<'], filter.invalid['>'])
	}
}

// A payload whose characters the profile dropped must not be sent at all, which
// is visible in the request count rather than only in the finding.
func TestXSSEscapeDoesNotSendBlockedPayloads(t *testing.T) {
	var mu sync.Mutex
	var sent []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("q")
		mu.Lock()
		sent = append(sent, value)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		stripped := strings.NewReplacer("<", "", ">", "").Replace(value)
		_, _ = io.WriteString(w, `<html><body><p>`+stripped+`</p></body></html>`)
	}))
	t.Cleanup(server.Close)
	transport := mustTransport(t)
	point := Point{URL: server.URL, Method: http.MethodGet, Param: "q", Values: url.Values{"q": {"hello"}}}

	if findings := (XSSEscape{}).probeAt(t, transport, point); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: no payload survives the profile", len(findings))
	}

	mu.Lock()
	defer mu.Unlock()
	// The assertion is on *what was sent*, and on the characters rather than on
	// request shapes: the profile blocked `<` and `>`, so the claim under test is
	// that no payload carrying them went out. A shape list would be a weaker claim —
	// it passes for a payload that needs the blocked characters in a spelling the
	// list forgot, and `javascript:` in particular is *supposed* to be sent here,
	// because it contains neither.
	for _, query := range sent {
		if isXSSEscapeProbePayload(query) {
			continue
		}
		if strings.ContainsAny(query, "<>") {
			t.Errorf("sent %q although the profile marks '<' and '>' filtered", query)
		}
	}
}

// isXSSEscapeProbePayload reports whether a submitted value is the filter
// profile's probe rather than an escape payload.
//
// It is recognised by the markers `probeFilter` wraps its characters in, which is
// the same fact a reader of the request log has: one request carries every special
// character between two tokens and produces no finding by itself.
func isXSSEscapeProbePayload(query string) bool {
	batched := string(xsseProbeChars)
	start := strings.Index(query, batched)
	if start < 0 {
		return false
	}
	return strings.Contains(query[:start], "rro") &&
		strings.HasPrefix(query[start+len(batched):], "rrc")
}

// A regex literal before the reflection is not code, and treating it as code
// mis-balances the stack: the closer then contains a bracket the page never
// opened and the payload reflects without executing.
func TestJSBreakoutPlanClosesARegexLiteral(t *testing.T) {
	closer, name := jsBreakoutPlan(`if (x.test(/)/)) { var re = /^`)
	if closer != "/" || name != "a regex literal" {
		t.Errorf("jsBreakoutPlan = (%q, %q), want (%q, %q)", closer, name, "/", "a regex literal")
	}
	// A division is not a pattern: after `)` a `/` divides, so the string that
	// follows is still a string and that is what has to be closed.
	closer, name = jsBreakoutPlan(`var re = a / b; var q = '`)
	if closer != "'" || name != "single-quoted string" {
		t.Errorf("jsBreakoutPlan after a division = (%q, %q), want (%q, %q)", closer, name, "'", "single-quoted string")
	}
	// A character class may hold the delimiter.
	closer, _ = jsBreakoutPlan(`var re = /[/]/; var q = '`)
	if closer != "'" {
		t.Errorf("jsBreakoutPlan after a class holding a slash = (%q, ...), want the string close", closer)
	}
}

// The payload needs the statement separator: without it a closer that ends a call
// produces `render({…})document.title=…`, which reflects and executes nothing.
func TestXSSEscapeSeparatesTheStatement(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return "<html><body><script>render({label: '" + value + "', id: 7});</script></body></html>"
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.HasPrefix(findings[0].Payload, "'});") {
		t.Errorf("payload = %q, want the closer, then a statement separator", findings[0].Payload)
	}
}

// The catalogue: a script the scanner cannot read fully must still be answered by
// a fixed shape. The page below hides the reflection behind a construct the
// scanner mis-balances, and the finding has to come from the catalogue entry.
func TestXSSEscapeFallsBackToTheCatalogue(t *testing.T) {
	// The script is not JavaScript the scanner can read: the value sits inside a
	// `type="text/template"` block, which is data. The computed closer is therefore
	// not offered, and the entry that works is the one that never depended on the
	// script's syntax — closing the element and putting an element after it.
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return `<html><body><script type="text/template">render('` + value + `');</script></body></html>`
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: the catalogue is the safety net behind the computed closer", len(findings))
	}
	if !strings.Contains(findings[0].Title, "script element close") {
		t.Errorf("title = %q, want it to name the shape that worked", findings[0].Title)
	}
	if !strings.Contains(findings[0].Payload, "</script><svg onload=") {
		t.Errorf("payload = %q, want the element close plus an element: after </script> a JavaScript "+
			"statement is page text", findings[0].Payload)
	}
}

// The control for the row above: the same shape in an executable script is
// answered by the computed closer, so the fallback is not what made the finding.
func TestXSSEscapePrefersTheComputedCloserWhenTheScriptIsCode(t *testing.T) {
	transport, point := newXSSFixture(t, 200, func(value string) string {
		return "<html><body><script>render('" + value + "');</script></body></html>"
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.HasPrefix(findings[0].Payload, "');") {
		t.Errorf("payload = %q, want the computed closer first", findings[0].Payload)
	}
}

// A page that escapes the quote as `\"` is reached by a payload that opens with a
// backslash: the application's own escape then leaves a real closing quote.
func TestXSSEscapeAnswersABackslashEscapedQuote(t *testing.T) {
	// The page escapes every quote the payload brings, which is what makes the
	// plain closer fail: `"` arrives as `\"`, so the string never closes. A payload
	// that opens with a backslash turns the application's own escape into `\\"` —
	// a literal backslash and a real closing quote — and the finding comes from that
	// shape rather than from the first.
	transport, point := newXSSFixture(t, 200, func(value string) string {
		escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
		return "<html><body><script>var q = \"" + escaped + "\";</script></body></html>"
	})
	findings := (XSSEscape{}).probeAt(t, transport, point)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Title, "escaped") {
		t.Errorf("title = %q, want it to name the escaped-quote shape", findings[0].Title)
	}
	if !strings.HasPrefix(findings[0].Payload, `\"`) {
		t.Errorf("payload = %q, want it to open with the backslash that turns the page's escape into a "+
			"real closing quote", findings[0].Payload)
	}
}

// The catalogue is ordered and free of duplicates: the computed closer is not
// sent twice, and a closer that needs a filtered character is not sent at all.
func TestJSEscapeCatalogIsOrderedAndDeduplicated(t *testing.T) {
	entries := jsEscapeCatalog(`'}`, "single-quoted string", "'", xsseFilter{})
	if len(entries) == 0 {
		t.Fatal("no entries: the computed closer itself must be first")
	}
	if entries[0].name != "single-quoted string" {
		t.Errorf("first entry = %q, want the computed closer", entries[0].name)
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if seen[entry.payload] {
			t.Errorf("payload %q appears twice", entry.payload)
		}
		seen[entry.payload] = true
	}
	// `;` is what separates the statement, so every statement entry needs it. The
	// element close does not — it is markup, not a statement — and must survive, or
	// a profile that filters one punctuation character would blind the detector
	// completely.
	blocked := xsseFilter{invalid: map[rune]bool{';': true}}
	for _, entry := range jsEscapeCatalog("", "code position", "", blocked) {
		if !entry.markup && strings.Contains(entry.payload, ";") {
			t.Errorf("statement payload %q was sent although the profile marks ';' filtered", entry.payload)
		}
	}
	// The element close is the last entry and carries a tag: it is the shape that
	// does not depend on the script's syntax being readable at all.
	full := jsEscapeCatalog("", "code position", "", xsseFilter{})
	if len(full) == 0 {
		t.Fatal("catalogue is empty for a code position")
	}
	last := full[len(full)-1]
	if !last.markup || !strings.HasPrefix(last.payload, "</script><svg onload=") {
		t.Errorf("last entry = %+v, want the element close carrying an element", last)
	}
	for _, entry := range full {
		if entry.markup && !strings.Contains(entry.payload, "<svg onload=") {
			t.Errorf("markup entry %q carries no element", entry.payload)
		}
	}
}
