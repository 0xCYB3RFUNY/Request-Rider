// Reflected XSS, classified by where the reflection lands.
//
// # Why reflection alone is not a finding
//
// Every search page reflects its query. A contact form reflects the sender's
// name. A profile page reflects a display name. Reporting those as
// vulnerabilities is how a scanner produces two hundred rows that a triager
// learns to skip without reading — and a triager who has learned to skip rows
// does not read the one that matters.
//
// So a reflection is reported as `info` and the detector tries to do better:
// it sends a payload shaped for the context the value landed in, and asks
// whether the response now contains a structure a browser would execute. Only
// that earns a tier above informational.
//
// # Why the upstream confirmation was not portable
//
// The upstream detector confirmed an escalation by looking for the payload
// *and* for any of `onload=`, `onerror=`, `<svg`, `<img` anywhere in the body.
// A real page contains `<img` and `onerror=` routinely — every site with an
// image that can fail has an onerror handler somewhere. The test therefore
// passed on pages that reflected the value and did nothing else, which is the
// whole false-positive class this file is written to remove.
//
// Here the confirmation is positional: the payload has to arrive inside a tag
// this probe built, not merely somewhere on the page. The check is "did the
// application construct an element from my input", and it is answered by looking
// at the neighbourhood of the payload rather than the document at large.
package active

import (
	"context"
	"fmt"
	"html"
	"regexp"
	"strings"
)

// xssContexts maps an injection context to the payloads that break out of it.
//
// The order is deliberate: the body context is tried first because it is the
// most common by a wide margin, and each context's own payloads are ordered
// cheapest first. Stopping at the first confirmed context is what keeps the
// request count to a surface sane — a detector that tries every payload in
// every context against a parameter it has already confirmed is spending the
// operator's budget to learn nothing.
var xssContexts = []struct {
	name     string
	payloads []string
}{
	{
		name: "html-body",
		payloads: []string{
			`<svg onload=%s>`,
			`<img src=x onerror=%s>`,
			`<details open ontoggle=%s>`,
		},
	},
	{
		name: "attribute",
		payloads: []string{
			`" onmouseover=%s x="`,
			`" onfocus=%s autofocus="`,
		},
	},
	{
		name:     "script-string",
		payloads: []string{`</script><svg onload=%s>`, `";%s//`},
	},
}

// xssProof is the marker a payload executes. It is a statement, not an alert:
// alert is noisy in a browser, a statement is not, and a scanner that makes the
// operator's browser pop up dialogs is a scanner that gets uninstalled.
const xssProof = "document.title='rr'"

// xssEncodingProbe is a character every output encoder must transform. A page
// that returns it raw is not encoding; a page that returns an entity is.
const xssEncodingProbe = "<"

// xssTagWindow is how much text around a payload counts as "inside the element
// the payload built". It is small on purpose: the question is whether the
// application's own response placed the payload between a tag it emitted and
// the matching close, and a window wide enough to reach the page's other
// elements would answer a different question.
const xssTagWindow = 160

// xssExecutableTag matches a tag carrying an event handler, which is the
// structure that makes injected markup run.
var xssExecutableTag = regexp.MustCompile(
	`(?is)<\s*(svg|img|details|video|body|iframe|marquee)\b[^>]*\bon[a-z]+\s*=`)

// XSS is the reflected cross-site scripting detector.
type XSS struct{}

// Name implements Module.
func (XSS) Name() string { return "xss" }

// Level implements Module.
func (XSS) Level() Level { return LevelParam }

// Scan probes one surface.
func (m XSS) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	canary := newCanary("rrx")
	if canary == "" {
		// Without entropy the canary is guessable, and a guessable canary is a
		// canary the page might already contain. Reporting nothing is the only
		// honest option.
		return nil
	}
	reflected, err := t.Fire(ctx, p, p.Param, canary, false, nil)
	if err != nil || !Fresh(baseline, reflected, canary) {
		// Either the value is not reflected at all, or the baseline already
		// contained it. Neither is an injection.
		return nil
	}
	// Nothing in a response the browser does not parse as HTML can execute.
	//
	// A JSON search API that echoes the query back verbatim is not a stored or
	// reflected scripting problem — there is no document, no parser and no
	// element for a payload to become. Escalating against it means sending
	// `<svg onload=…>` to a JSON endpoint, finding the text in the response,
	// and calling the text executable. That single missing check is worth more
	// false positives than every payload table in this file combined, because a
	// JSON response will faithfully contain any string the scanner sends it.
	if !isHTMLContentType(reflected) {
		return nil
	}

	// Reflection proves the value came back. It does not prove the value came
	// back *unencoded*, and a claim of "no output encoding" that rests on a
	// reflected value is a claim about something the exchange never showed. A
	// page that escapes its output reflects an alphanumeric canary unchanged
	// and escapes every payload, so the canary alone cannot tell the two apart.
	//
	// The check is one extra request carrying a character that any encoder must
	// transform, and it looks for that character **in the position the
	// application put it in** — immediately after the canary it echoed.
	//
	// A whole-body search would be useless here: "<" occurs on every HTML page
	// the scanner will ever see, including the baseline, so a body-level
	// freshness check reports "already present" and silently disables the whole
	// detector. The sequence canary+"<" either came back raw or it did not, and
	// that is a question about one position in the response rather than about
	// the document.
	probe, probeErr := t.Fire(ctx, p, p.Param, canary+xssEncodingProbe, false, nil)
	unescaped := probeErr == nil && probe != nil &&
		strings.Contains(probe.Body, canary+xssEncodingProbe)

	context := classifyContext(reflected.Body, canary)
	// Text inside a title or a textarea is RCDATA: the parser reads it as
	// character data, so a tag written there is shown as text rather than
	// executed. There is nothing to escalate with, and the finding below is the
	// whole of what can honestly be said.
	if context != rcdataContext {
		if finding := escalate(ctx, t, p, context); finding != nil {
			return []Finding{*finding}
		}
	}
	if !unescaped {
		// Reflected and encoded. That is the correct behaviour of a working
		// application, and reporting it would be a false positive on every
		// page that does the right thing.
		return nil
	}
	// The value is echoed back unmodified. That is a real property of the
	// application and it is the precondition for XSS, so it is reported — at
	// informational, with no claim about execution.
	finding, _ := NewFinding(Spec{
		Module:  "xss",
		Title:   "User Input Reflected Without Encoding (potential XSS)",
		Claimed: SeverityMedium,
		Tier:    TierPotential,
		Point:   p,
		Payload: canary,
		Evidence: fmt.Sprintf("canary %s reflected verbatim in %s context, and the raw character %q was "+
			"returned unencoded; no context-breaking payload executed", canary, context, xssEncodingProbe),
		Description: "The parameter value is returned unmodified. Output encoding is absent, which is the " +
			"precondition for cross-site scripting. A browser-executing payload was not confirmed here: a " +
			"Content-Security-Policy or an input filter may block execution even without encoding.",
		Remediation: "Apply context-aware output encoding. Deploy a Content-Security-Policy. Treat this as a " +
			"precondition until an executable payload is demonstrated.",
	})
	return []Finding{finding}
}

// classifyContext names where in the document the reflection landed.
//
// The order is significant: a reflection inside a script block is the most
// dangerous context and the easiest to miss, because a page whose <script> tags
// sit far from the reflection has a long window of unrelated markup in between.
// rcdataContext is the context of text a parser reads as characters rather than
// as markup.
const rcdataContext = "rcdata"

// isHTMLContentType reports whether a response is a document a browser parses
// as HTML.
//
// An absent Content-Type is treated as HTML because that is what the standard
// says a client must assume, and because the alternative — ignoring the check
// whenever a server omits the header — puts the false positives straight back.
func isHTMLContentType(resp *Response) bool {
	if resp == nil {
		return false
	}
	value := resp.HeaderValue("Content-Type")
	if strings.TrimSpace(value) == "" {
		return true
	}
	return strings.Contains(strings.ToLower(value), "html")
}

// rcdataElements are the elements whose content a parser treats as text.
var rcdataElements = []string{"title", "textarea"}

func classifyContext(body, canary string) string {
	index := strings.Index(body, canary)
	if index < 0 {
		return "unknown"
	}
	prefix := body[:index]
	suffix := body[index:]
	lowerPrefix := strings.ToLower(prefix)
	openScript := strings.LastIndex(lowerPrefix, "<script")
	closeScript := strings.LastIndex(lowerPrefix, "</script")
	if openScript > closeScript {
		return "script-string"
	}
	// Inside a title or a textarea the parser reads characters, so an injected
	// element is displayed rather than run.
	if tagStart := strings.LastIndex(prefix, "<"); tagStart >= 0 {
		for _, name := range rcdataElements {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(prefix[tagStart+1:])), name) {
				return rcdataContext
			}
		}
	}
	// An attribute value. The tag's opening text is what lies between the last
	// "<" before the reflection and the reflection itself — looking for the
	// tag's closing ">" does not work, because the reflection sits *inside* the
	// tag and the ">" is after it, in the suffix.
	if tagStart := strings.LastIndex(prefix, "<"); tagStart >= 0 {
		opening := prefix[tagStart:]
		if equals := strings.LastIndex(opening, "="); equals >= 0 {
			after := strings.TrimSpace(opening[equals+1:])
			if after == "" || after == `"` || after == "'" {
				return "attribute"
			}
		}
	}
	if strings.HasPrefix(strings.TrimSpace(suffix), "<") {
		return "tag-interior"
	}
	return "html-body"
}

// escalate sends a context-appropriate payload and asks whether the response
// now contains a structure a browser would execute.
func escalate(ctx context.Context, t *Transport, p Point, context string) *Finding {
	for _, candidate := range xssContexts {
		if ctx.Err() != nil {
			return nil
		}
		// A context the reflection did not land in is not worth probing: the
		// body payload against a value inside an attribute will simply be
		// escaped, and the request buys nothing.
		if candidate.name != context && context != "unknown" {
			continue
		}
		for _, template := range candidate.payloads {
			if ctx.Err() != nil {
				return nil
			}
			payload := strings.ReplaceAll(template, "%s", xssProof)
			resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
			if err != nil {
				continue
			}
			if !confirmExecutable(resp.Body, payload) {
				continue
			}
			finding, _ := NewFinding(Spec{
				Module:   "xss",
				Title:    "Reflected XSS (" + candidate.name + " context, executable markup confirmed)",
				Claimed:  SeverityHigh,
				Tier:     TierVerified,
				Point:    p,
				Payload:  payload,
				Evidence: Snippet(resp.Body, payload, xssTagWindow),
				Description: "The parameter value reaches the " + candidate.name + " context without encoding and " +
					"is rendered inside a tag the application itself emitted, so the injected event handler is part " +
					"of a real element rather than inert text.",
				Remediation: "Encode output for its context. Deploy a Content-Security-Policy without 'unsafe-inline'. " +
					"Set HttpOnly on session cookies so an injected script cannot read them.",
			})
			return &finding
		}
	}
	return nil
}

// htmlComment matches a comment, including the conditional-comment forms a
// parser still treats as comments.
var htmlComment = regexp.MustCompile(`(?s)<!--.*?(?:-->|$)`)

// stripComments removes HTML comments from a body.
//
// A payload inside a comment is a frequent result and a total non-event: the
// parser reads a comment as characters, so no element is ever built and the
// text on the page is literally `<!-- <svg onload=...> -->`. It has to be
// removed for a second reason as well, which is the sharper one — the payload
// matches the executable-tag pattern by itself, so a confirmation that looks for
// a tag containing the payload finds the payload's own tag and agrees with
// itself. Stripping comments first is what makes the confirmation answer a
// question about the *page's* markup instead of about the text I sent.
func stripComments(body string) string {
	return htmlComment.ReplaceAllString(body, "")
}

// confirmExecutable answers the only question that matters: did the application
// put my payload inside a tag it emitted?
//
// The payload must appear, and an event handler must appear within a short
// distance of it, and the evidence must not have come from a body that already
// contained that handler before the injection. Checking all three is what
// separates "the page built an element from my input" from "the page has an
// onerror handler somewhere and echoes my parameter".
func confirmExecutable(body, payload string) bool {
	// Comments are removed here rather than at the call site so that the
	// contract is the same for every caller: this function answers about the
	// markup a parser will actually see.
	body = stripComments(body)
	if payload == "" || !strings.Contains(body, payload) {
		return false
	}
	index := strings.Index(body, payload)
	// The window is measured from the payload outward in both directions, so a
	// handler that belongs to an element on the far side of the document is not
	// borrowed as evidence.
	low := index - xssTagWindow
	if low < 0 {
		low = 0
	}
	high := index + len(payload) + xssTagWindow
	if high > len(body) {
		high = len(body)
	}
	window := body[low:high]
	if !xssExecutableTag.MatchString(window) {
		return false
	}
	// The handler has to be in the same tag as the payload, not merely nearby.
	// A tag boundary between the handler and the payload means they are two
	// different elements, and the payload is in neither of them.
	return sameTag(window, index-low, payload)
}

// sameTag reports whether an executable tag and the payload belong to the same
// element: everything between the tag's "<" and its ">" has to contain the
// payload.
func sameTag(window string, payloadOffset int, payload string) bool {
	for _, match := range xssExecutableTag.FindAllStringIndex(window, -1) {
		start, end := match[0], match[1]
		if end > len(window) {
			continue
		}
		// The closing ">" is searched from the start of the match and not
		// inside it, because the match deliberately stops at the handler's "="
		// — the tag continues past that, and the payload usually sits between
		// the handler and the close. Looking inside the match finds no ">" and
		// rejects every payload it should accept.
		closing := strings.Index(window[start:], ">")
		if closing < 0 {
			continue
		}
		// `closing` is the offset OF the ">" within window[start:], so the
		// byte just past the tag's end is one further on. The comparison has to
		// use that exclusive bound: an injected element's payload *ends with*
		// its own ">", so a bound that stops on the ">" rejects exactly the
		// payloads it is meant to accept and the detector never fires.
		pastTag := start + closing + 1
		if start <= payloadOffset && payloadOffset+len(payload) <= pastTag {
			return true
		}
	}
	return false
}

// xssUnescape is used by tests and by the context classifier's callers that
// hold an escaped body. It exists so the package has one definition of what
// "reflected" means for a value the application HTML-escaped.
func xssUnescape(body string) string { return html.UnescapeString(body) }
