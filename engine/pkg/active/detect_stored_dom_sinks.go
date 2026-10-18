package active

// storedDOMSinkRules are the twelve stored variants of the DOM-sink family.
//
// # Why these exist separately from `domSinkRules`
//
// `domSinkRules` answers the **DOM-based** and **reflected** questions with a
// static reading of the page's own code: a source the browser hands a script
// reaches a sink the application writes. That is a claim about the page as it is
// served, and it holds for those two variants.
//
// The stored variants are a different claim, and the static reading cannot make
// it: the question is whether *a value this run stored* ends up inside a sink.
// A page that ships `document.cookie = "…"` proves nothing about what happens to
// the string a visitor submitted last week, and a rule that reported the stored
// rows from the static reading alone would be claiming the class from the
// precondition — which is the state the register was corrected out of.
//
// So each rule here does what `StoredClass` does for the HTML families: submit a
// marker, re-read the pages, and require the marker to be **inside that family's
// sink expression**. `postMessage(…, '*')` still has to carry the marker, because
// a wildcard target with an application-chosen message is the finding and the
// wildcard alone is a different one.
//
// # Why the field names are not the family names
//
// Each rule submits into a field named after its family, and those names have to
// be distinguishable from each other by **containment** as well as by spelling:
// the field matcher takes the first declared name that contains what the rule
// asked for, so a field named `sinkdom` would have been selected by a rule asking
// for `sinkdomain` and would have left the DOM-data rule writing its marker into
// the wrong sink — which is measured, and cost eleven rows at once.
//
// # Why the payload is a plain token
//
// Each marker is an ordinary string with no syntax of its own. That is deliberate:
// a payload carrying a payload's syntax — a quote, a tag, a newline — would only
// demonstrate that the application echoed it, and the class here is decided by
// **which expression** it landed in, not by what it looks like. The one family
// whose defect is in the call rather than in the value, the wildcard
// `postMessage`, is still proven by the marker's presence in the message
// argument, which is what makes the wildcard dangerous.

import "strings"

// storedSinkRule is one stored DOM-sink family.
type storedSinkRule struct {
	// family is the `domSinkRules` family this stored variant belongs to. It is a
	// name rather than a pattern so the two tables cannot drift apart: a family
	// renamed in one and not the other would silently stop proving anything.
	family string
	// typeIndex is the original check's identifier.
	typeIndex string
	// claimed is the severity the proof supports.
	claimed Severity
	// field is the form field the marker is submitted into. It is namespaced per
	// family so that one rule's marker never lands in another rule's sink, which
	// would let a single write prove twelve rows.
	field string
	// marker is what is submitted.
	marker string
	// description and remediation are the class's own, in the same voice the rest
	// of the package reports in.
	description string
	remediation string
}

// storedSinkRules are the twelve, in the order of `domSinkRules` so the two
// tables read together.
var storedSinkRules = []storedSinkRule{
	{
		family: "Cookie Manipulation", typeIndex: "0x00500B02", claimed: SeverityHigh,
		field: "sinkcookie", marker: "rrsinkcookie",
		description: "A value this run stored is rendered into a `document.cookie` assignment. " +
			"The application writes what a client previously sent into the cookie jar, so anyone " +
			"who can place a value there sets a cookie for every later visitor — and a script on " +
			"the page reads the jar back on every load.",
		remediation: "Never build a cookie value from anything a client supplied. Read the " +
			"value from configuration, or hash it, and set the cookie where the server can " +
			"validate what goes into it.",
	},
	{
		family: "Ajax Request Header Manipulation", typeIndex: "0x00500C02", claimed: SeverityMedium,
		field: "sinkheader", marker: "rrsinkheader",
		description: "A value this run stored is rendered into an `XMLHttpRequest.setRequestHeader` " +
			"call. The header the request then carries is one a client chose, and the server " +
			"treats it as its own client's.",
		remediation: "Do not set a request header from stored data. Where a header is genuinely " +
			"required, choose it from a fixed set on the server and send the stored value in the " +
			"body instead.",
	},
	{
		family: "Link Manipulation", typeIndex: "0x00501002", claimed: SeverityMedium,
		field: "sinklink", marker: "rrsinklink",
		description: "A value this run stored is rendered into a `location.href` assignment. The " +
			"destination of a navigation is therefore chosen by whoever put the value there, and " +
			"this page's origin travels with it as the referrer.",
		remediation: "Allow-list the destinations a navigation may use, or turn the stored value " +
			"into a path on this origin before it reaches the script.",
	},
	{
		family: "Document Domain Manipulation", typeIndex: "0x00501102", claimed: SeverityMedium,
		field: "sinkdomain", marker: "rrsinkdomain",
		description: "A value this run stored is rendered into a `document.domain` assignment. A " +
			"relaxed document domain hands any sibling host a same-origin document to read and to " +
			"write, and the value that relaxed it was a client's.",
		remediation: "Do not set `document.domain`. If sibling documents need to talk, use " +
			"`postMessage` with an explicit target origin.",
	},
	{
		family: "DOM Data Manipulation", typeIndex: "0x00501202", claimed: SeverityHigh,
		field: "sinkmarkup", marker: "rrsinkmarkup",
		description: "A value this run stored is rendered into a DOM write — `innerHTML`, " +
			"`outerHTML`, `insertAdjacentHTML`. Markup the client supplied is parsed as markup on " +
			"every later load of the page.",
		remediation: "Use `textContent` for text, or escape the value before the assignment. A " +
			"DOM write with a stored value in it is the stored-XSS sink by another name.",
	},
	{
		family: "Client-Side XPath Injection", typeIndex: "0x00200362", claimed: SeverityMedium,
		field: "sinkxpath", marker: "rrsinkxpath",
		description: "A value this run stored is rendered into a `document.evaluate` call, so it " +
			"is an XPath expression against the page's own XML — chosen by whoever stored it.",
		remediation: "Do not build an XPath expression from stored data. Query with a fixed " +
			"expression and pass the varying part as a bound variable.",
	},
	{
		family: "Client-Side JSON Injection", typeIndex: "0x00200372", claimed: SeverityLow,
		field: "sinkjson", marker: "rrsinkjson",
		description: "A value this run stored is parsed as JSON by the page. The shape of every " +
			"field the page reads afterwards is the shape this string chose, and the page's own " +
			"code was written against a different one.",
		remediation: "Parse into a shape you validate before use, and reject a document whose " +
			"fields are not the ones the page expects.",
	},
	{
		family: "HTML5 Storage Manipulation", typeIndex: "0x00500F02", claimed: SeverityMedium,
		field: "sinkstorage", marker: "rrsinkstorage",
		description: "A value this run stored is written into `localStorage`. Storage is " +
			"origin-wide and persistent, so it is read back on every later load and is visible to " +
			"every script on the origin.",
		remediation: "Write only values the application controls into storage, and treat anything " +
			"read back out of it as untrusted input.",
	},
	{
		family: "Local File Path Manipulation", typeIndex: "0x00200352", claimed: SeverityMedium,
		field: "sinkfile", marker: "rrsinkfile",
		description: "A value this run stored is rendered into a local file reference, so the " +
			"browser is asked for a path on the visitor's disk that a client chose.",
		remediation: "Never build a file URL from stored data. Reference files by a name the " +
			"application maps, not by a path a visitor supplied.",
	},
	{
		family: "Denial of Service", typeIndex: "0x00500D02", claimed: SeverityLow,
		field: "sinkdos", marker: "rrsinkdos",
		description: "A value this run stored is rendered into an array size or a timer delay. " +
			"One page load now costs as much work as the stored string asked for.",
		remediation: "Bound the size and the delay in code, and validate anything that reaches " +
			"them. Neither belongs to a stored string.",
	},
	{
		family: "HTML5 Web Message Manipulation", typeIndex: "0x00500E02", claimed: SeverityMedium,
		field: "sinkmessage", marker: "rrsinkmessage",
		description: "A value this run stored is sent through `postMessage` with a wildcard " +
			"target origin, so the message reaches whichever origin the receiving document " +
			"actually lives on, whatever the sender meant.",
		remediation: "Name the target origin explicitly, and validate `event.origin` before " +
			"acting on anything a message carries.",
	},
	{
		family: "WebSocket URL Poisoning", typeIndex: "0x00200342", claimed: SeverityMedium,
		field: "sinksocket", marker: "rrsinksocket",
		description: "A value this run stored is rendered into a `WebSocket` constructor, so the " +
			"page opens a channel to an address a client chose — from inside the visitor's " +
			"session, with this origin's cookies on the first frame if the channel is same-origin.",
		remediation: "Connect only to an address from configuration, and refuse to open a socket " +
			"whose URL came from stored data.",
	},
}

// storedSinkFamily proves that a marker is inside one family's sink expression.
//
// It reuses the same patterns the static reader uses, which is the point: the two
// must agree about what a `document.cookie` assignment is, or the same page would
// be a finding in one row and not in another for no reason anyone could name.
func storedSinkFamily(body, family, marker string) bool {
	for _, rule := range domSinkRules {
		if rule.family != family {
			continue
		}
		for _, match := range rule.match.FindAllStringSubmatch(body, -1) {
			if strings.Contains(domSinkArgument(match), marker) {
				return true
			}
		}
	}
	return false
}

// storedSinkEvidence names the expression the value landed in, so the evidence
// line shows the sink rather than only the marker.
func storedSinkEvidence(body, family, marker string) string {
	for _, rule := range domSinkRules {
		if rule.family != family {
			continue
		}
		for _, match := range rule.match.FindAllStringSubmatch(body, -1) {
			if strings.Contains(domSinkArgument(match), marker) {
				return Snippet(body, strings.TrimSpace(match[0]), 200)
			}
		}
	}
	return Snippet(body, marker, 200)
}

// storedDOMSinkClassRules renders the twelve rules into the class table, so they
// share the write and read passes rather than costing one module each.
//
// The conversion happens here rather than in the table above because the two kinds
// of rule differ in shape: the class table's rules carry their own proof, and
// these carry a family name that the proof needs. Turning one into the other once,
// at the point where the table is built, keeps both tables readable.
func storedDOMSinkClassRules() []storedClassRule {
	out := make([]storedClassRule, 0, len(storedSinkRules))
	for _, rule := range storedSinkRules {
		rule := rule
		out = append(out, storedClassRule{
			class:       rule.family + " (stored DOM-based)",
			typeIndex:   rule.typeIndex,
			claimed:     rule.claimed,
			field:       rule.field,
			payload:     rule.marker,
			marker:      rule.marker,
			proves:      func(resp *Response) bool { return storedSinkFamily(resp.Body, rule.family, rule.marker) },
			evidence:    func(body string) string { return storedSinkEvidence(body, rule.family, rule.marker) },
			description: rule.description,
			remediation: rule.remediation,
		})
	}
	return out
}

// storedSinkFieldNames are the fields the twelve rules submit into, so the
// fixture can declare a form that carries all of them and no test has to guess
// which field a rule needed.
func storedSinkFieldNames() []string {
	out := make([]string, 0, len(storedSinkRules))
	for _, rule := range storedSinkRules {
		out = append(out, rule.field)
	}
	return out
}
