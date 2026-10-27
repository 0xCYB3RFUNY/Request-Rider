package active

// XMLInjection asks what happens when XML metacharacters reach a document the
// server parses.
//
// Burp's check is `0x00100700` (XML injection). It is a different sink from XXE:
// XXE proves an external entity is *resolved*, while this one proves the parameter
// reaches a parser as markup. The two are reported separately because they are
// remediated differently — an XXE is a parser configuration, a markup insertion
// is an escaping decision — and because a page can have either without the other.
//
// Two signals, and neither is reflection alone. Reflection is what the XSS family
// measures; this module measures what the parser does:
//
//   - **the metacharacters arrive raw.** A value inserted into a document
//     without escaping shows up in the response as the same bytes that were sent:
//     `]]>` closing a CDATA section, `<!DOCTYPE` opening a declaration. A page
//     that escaped it answers `]]&gt;` and is not what this row is about.
//   - **the parser rejects it.** An error signature that the baseline did not
//     carry — a SAX message, a "not well-formed" line, a framework's own parse
//     failure — says the injected value changed how the document was read.
//
// The scope is the response's own content type, on purpose. Injecting XML
// markup into an HTML endpoint is the XSS family's question, and a module that
// asked it again would spend requests to re-report another detector's finding.

import (
	"context"
	"strings"
)

// XMLInjection is the XML markup-insertion probe.
type XMLInjection struct{}

// Name implements Module.
func (XMLInjection) Name() string { return "xml-injection" }

// Level implements Module.
func (XMLInjection) Level() Level { return LevelParam }

// xmlProbe is one metacharacter sequence and what it does to a document that
// parses it.
type xmlProbe struct {
	// payload is the exact value sent.
	payload string
	// effect is the structural claim, written so a reader of a report knows
	// what the sequence does to a document that parses it.
	effect string
	// errors are the parser messages this sequence is expected to provoke.
	// They are matched against the response, not against a fixed list of
	// "vulnerable" strings, because the message belongs to the target's parser.
	errors []string
}

// xmlProbes are the sequences, in the order the run tries them. They are a table
// rather than inline literals because each row is a distinct structural claim.
var xmlProbes = []xmlProbe{
	{
		payload: "]]>",
		effect:  "closes a CDATA section the document had open",
		errors:  []string{"not well-formed", "unexpected end of file", "mismatched tag"},
	},
	{
		payload: "<![CDATA[rr]]>",
		effect:  "opens and closes a CDATA section around the value",
		errors:  []string{"not well-formed"},
	},
	{
		payload: "<!DOCTYPE rr [<!ENTITY rr \"rr\")]>",
		effect:  "declares a document type with a malformed entity definition",
		errors:  []string{"not well-formed", "invalid xml", "xml declaration allowed only"},
	},
	{
		payload: "<rr xmlns=\"rr\"/>",
		effect:  "adds an element with its own namespace",
		errors:  []string{"not well-formed"},
	},
	{
		payload: "&rr;",
		effect:  "references an entity that may not be declared",
		errors:  []string{"undeclared entity", "reference to undeclared entity", "unbound prefix"},
	},
}

// xmlParserErrorMarkers are the messages an XML parser writes when the document
// it was handed is not valid. They are compared against the baseline rather than
// absented from it: a page that already carries one of these is a page that
// already has a parse problem, and this run is not measuring that.
var xmlParserErrorMarkers = []string{
	"not well-formed",
	"not well formed",
	"saxparseexception",
	"xml parsing error",
	"xml parse error",
	"invalid xml",
	"xml parser error",
	"undeclared entity",
	"reference to undeclared entity",
	"mismatched tag",
	"unexpected end of file",
	"xml declaration allowed only",
	"libxml error",
}

// isXMLResponse reports whether a response is a document this module reasons
// about. A body that opens with an XML declaration is one whatever the header
// says — a great many SOAP endpoints answer with the default type.
func isXMLResponse(resp *Response) bool {
	if resp == nil {
		return false
	}
	if strings.Contains(strings.ToLower(resp.HeaderValue("Content-Type")), "xml") {
		return true
	}
	return strings.HasPrefix(strings.TrimSpace(resp.Body), "<?xml")
}

// Scan injects the metacharacter sequences and reports what the parser did.
func (XMLInjection) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.StatusCode >= 400 || isPublicResource(p.URL) {
		return nil
	}
	if !isXMLResponse(baseline) {
		return nil
	}

	baselineErrors := xmlParserErrors(baseline.Body)

	var out []Finding
	for _, probe := range xmlProbes {
		resp, err := t.Fire(ctx, p, p.Param, probe.payload, false, nil)
		if err != nil || resp == nil {
			continue
		}
		if finding := xmlInjectionFinding(p, baseline, resp, probe, baselineErrors); finding != nil {
			out = append(out, *finding)
			// One row per surface: the sequences are variants of one claim, and
			// five rows that all say "the parameter reaches a parser" is a
			// report nobody reads.
			break
		}
	}
	return out
}

// xmlParserErrors returns which parser-error markers a body carries.
func xmlParserErrors(body string) map[string]bool {
	found := make(map[string]bool)
	lower := strings.ToLower(body)
	for _, marker := range xmlParserErrorMarkers {
		if strings.Contains(lower, marker) {
			found[marker] = true
		}
	}
	return found
}

// xmlInjectionFinding measures the two signals against the baseline.
func xmlInjectionFinding(p Point, baseline, resp *Response, probe xmlProbe, baselineErrors map[string]bool) *Finding {
	// Signal one: the sequence arrived raw. Escaping turns `>` into `&gt;`,
	// so a body carrying the same bytes that were sent was not escaped.
	if strings.Contains(resp.Body, probe.payload) && !strings.Contains(baseline.Body, probe.payload) {
		return xmlFinding(p, probe, "the injected markup reached the response unescaped",
			SeverityMedium, TierVerified,
			"The response carries the sequence `"+probe.payload+"` exactly as it was sent, so the "+
				"value is inserted into the document rather than encoded. A parameter that "+
				probe.effect+" is a parameter an attacker can close, rename or extend the "+
				"document with, and every parser downstream reads the result.",
			"Encode parameter values as text content (`&lt;` for `<`, `&gt;` for `>`) and never "+
				"build a document by concatenation. Where a document must be assembled, build it "+
				"through a library that owns the escaping.")
	}

	// Signal two: the parser says the document changed.
	fresh := xmlParserErrors(resp.Body)
	for _, expected := range probe.errors {
		if fresh[expected] && !baselineErrors[expected] {
			return xmlFinding(p, probe, "the parser rejected the injected markup",
				SeverityLow, TierPotential,
				"The response to the injected value carries a parser error (\""+expected+"\") "+
					"that the baseline did not. The value therefore changed how the document was "+
					"read, which is the definition of reaching a parser as markup: the sequence "+
					probe.effect+", and the parser noticed.",
				"Validate and parse the parameter as data before it becomes part of a document, "+
					"and answer an unparseable input with a validation message rather than the "+
					"parser's own error text, which names the stack for the caller.")
		}
	}
	return nil
}

// xmlFinding renders one row for one sequence.
func xmlFinding(p Point, probe xmlProbe, evidence string, claimed Severity, tier Tier, description, remediation string) *Finding {
	finding, _ := NewFinding(Spec{
		Module:      "xml-injection",
		Title:       "XML Injection: " + evidence,
		Claimed:     claimed,
		Tier:        tier,
		Point:       p,
		Payload:     probe.payload,
		Evidence:    evidence + ": `" + probe.payload + "` (" + probe.effect + ")",
		Description: description,
		Remediation: remediation,
	})
	return &finding
}
