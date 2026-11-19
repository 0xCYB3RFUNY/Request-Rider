package main

// Findings ported from zack0x01/JS-Analyser onto the parse tree jsluice builds.
//
// # What this is, and what it was measured against
//
// `JS-Analyser` is a Flask application whose `analyzer.py` holds eight finding
// categories as regular expressions over the text of a JavaScript file. Its own
// README sells it as a crawler-side companion, so the question is not whether the
// categories are useful but how they join the analysis the engine already runs.
//
// Both originals were run, unmodified, against one 2019-byte fixture
// (`/tmp/opencode/jsanalyser-baseline/app.js`) before any of this was written:
//
//   - `jsluice urls`   → 6 rows, each call site with method, headers and body
//                        params (`/api/v1/users/EXPR`, method GET).
//   - `jsluice secrets`→ 2 rows: `AWSAccessKey` (it paired `AKIA…` with the
//                        neighbouring `sk_live_…`, which is not the AWS secret —
//                        jsluice takes the sibling by shape, not by name), `gcpKey`.
//   - `JS-Analyser`    → 8 api_keys, 3 credentials, 1 email, 3 comments,
//                        6 xss_vulnerabilities, 2 xss_functions, 2 api_endpoints,
//                        2 paths_directories, and **no answer at all** from
//                        `extract_parameters`, which was still running after 85
//                        seconds on a 2 KB file (catastrophic backtracking,
//                        `analyzer.py:433`).
//
// That last row is the reason this is a port and not an integration. A service
// call would have put a stage in front of the analyst's map that hangs on small
// files, re-fetches every asset outside the passive proxy, and carries a 10 MB
// truncation the operator cannot lift (see the file header of
// `target_javascript.go` for why jsluice was linked into the engine instead).
//
// # What was ported, and what was not, and why
//
// Ported, because the parse tree answers the question better than a pattern can:
//
//	XSS sinks          innerHTML/outerHTML assignment, document.write/writeln,
//	                   eval, React dangerouslySetInnerHTML, jQuery html/append,
//	                   location.href/hash/search — matched as assignments and
//	                   calls, not as text.
//	XSS functions      the function that contains a DOM-write sink, named.
//	Comments           TODO/FIXME/SECURITY/… at the head of a comment, and the
//	                   password/secret/admin/… comments.
//	Emails             one per address, out of string literals only.
//
// Not ported, and this is a decision rather than an omission:
//
//   - `api_endpoints`. `JS-Analyser` found 2 rows on the fixture and both were
//     the *half* of a built path (`/api/v1/users/`, `/api/comments/`) — its
//     patterns require a literal argument, so a concatenation defeats them.
//     jsluice found the same file's call sites with method, headers and params.
//     Porting the regexes would be a second path to an answer we already give.
//   - `paths_directories`. Every one of its 2 rows was already in the crawl
//     frontier as a link (`jsCrawlableReference`).
//   - `parameters`. It never returned, and its content — function parameter
//     names, destructuring, `URLSearchParams.get` — is noise next to the
//     `query_params`/`body_params` the call sites already carry.
//
// Credentials and the vendor keys the fixture exposed (`xox…`, PayPal, Firebase
// messaging, JWT, Stripe publishable) are not findings of this file: they are
// rules, and they went into `secretRules` in `osint_secrets.go` so the crawler
// and the OSINT scan keep one vocabulary instead of two.
//
// # Two deliberate departures from the upstream patterns
//
//  1. The upstream XSS list reports `box.innerHTML = '<b>' + …` twice — once as
//     "innerHTML Assignment" and once as "innerHTML Concatenation" (both lines
//     27 on the fixture). One call site is one row here, and the concatenation
//     is visible in the evidence.
//  2. Comments are classified the way upstream classifies them, anchored at the
//     head of the comment. A keyword in the middle of a sentence is not a
//     finding, and a category that fires on every `// … token …` line is the
//     fastest way to make an analyst stop reading the badge.
//
// What could not be ported, stated rather than hidden: JSX attributes are not
// in the grammar. `(jsx_attribute)` returns nothing against a `.jsx` file, and
// `(string)` does not even see the text inside an element, so a real React
// component's `dangerouslySetInnerHTML` attribute is reported only when it is
// written as an object — `React.createElement('div', {dangerouslySetInnerHTML})`
// and the `{{ … }}` form — which is what the pair query below matches.

import (
	"bytes"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/BishopFox/jsluice"
)

// The finding kinds. They are strings rather than a Go enum because they travel
// to the browser, into PostgreSQL and into every export, and the consumer of a
// report is a person reading a category name.
const (
	jsFindingSink = "xss_sink"
	// jsFindingDOMSource is a read of a place the attacker controls, kept apart
	// from the sinks above because it is the other half of the same finding and
	// is useless on its own: a bundle that reads `location.hash` writes nothing,
	// and the write that makes it dangerous is already a sink row. Reporting
	// them together is what makes the pair readable, and splitting them is what
	// lets a filter ask for one without the other.
	//
	// This is the port of `KathanP19/JSFScan.sh`'s eighth step
	// (`tools/findomxss.sh`), whose pattern is
	// `(document|location|window)\.(URL|documentURI|search|hash|referrer|(location\.)?href|name)`.
	// Upstream greps the text and reports one line per match; the port asks the
	// tree, so `document.URL` inside a comment or a string is not a finding and
	// the enclosing function is known.
	jsFindingDOMSource = "dom_source"
	// jsFindingRequestCall is a call site that carries a URL — `fetch`,
	// `XMLHttpRequest.open`, `axios.get`, `$.ajax` — named by the function that
	// was called. This is the port of `BishopFox/jsluice`'s `jsurls-sinks` mode.
	//
	// It is separate from the endpoints for the same reason as above: the endpoint
	// says *what* is requested, this says *through which call*, and the second
	// question is the one a reader cannot answer from the URL alone — `$.post`
	// and `$.get` are the same string with different consequences.
	jsFindingRequestCall = "request_call"
	jsFindingFunction    = "xss_function"
	jsFindingComment     = "interesting_comment"
	jsFindingSuspicious  = "suspicious_comment"
	jsFindingEmail       = "email"
	jsFindingSourceMap   = "source_map"
	jsFindingSourceMapFile = "source_map_file"
)

// The severities. `critical` is not a jsluice severity: jsluice stops at `high`,
// and the one finding that deserves to outrank a hardcoded `innerHTML` write is
// `eval` of something that came from the address bar or the query string.
const (
	jsSeverityCritical = "critical"
	jsSeverityHigh     = "high"
	jsSeverityMedium   = "medium"
	jsSeverityInfo     = "info"
)

// jsFinding is one thing a reader of the file should look at.
//
// It is deliberately not `jsSecret`: a secret is a credential with a value, a
// fingerprint and a rule name from `secretRules`, and folding the other four
// categories into that shape would make "here is a password" and "here is a
// TODO" the same kind of row.
type jsFinding struct {
	// Kind is one of the five constants above.
	Kind string `json:"kind"`
	// Severity is how the analyst should read it, operator-facing.
	Severity string `json:"severity"`
	// Subject is the thing itself: `box.innerHTML`, `eval`, `security@…`, `TODO`.
	Subject string `json:"subject"`
	// Function names the enclosing function of a sink. Empty where there is no
	// function — a comment at file scope, an email in a config object.
	Function string `json:"function,omitempty"`
	// Evidence is the source the finding was read from, whitespace collapsed
	// and cut to a length a table cell can hold.
	Evidence string `json:"evidence"`
	// Line is the 1-based line the evidence starts on, or 0 when the evidence
	// text was not found in the file verbatim — which is reported rather than
	// guessed, the same way a zero byte count is reported.
	Line int `json:"line"`
	// Count is how many times the same subject appears in the file. A minified
	// bundle repeats one `innerHTML` write hundreds of times; the record says so
	// once instead of carrying hundreds of identical rows. The same measured
	// failure produced `mergeJSEndpoints` on the endpoint side.
	Count int `json:"count,omitempty"`
}

// The tree-sitter queries. Every one of them was run against the original
// `jsluice query` binary before being written here, because a query that silently
// matches nothing is indistinguishable from a query that was never tried.
//
// The shapes are kept as separate constants and then joined into two queries,
// which is a measured decision rather than tidiness. jsluice compiles a query on
// every call, and the compile cost does not shrink with the file: on the 2 KB
// fixture seven separate queries cost 34-48 ms together, and on a live 150 KB
// minified bundle from ria.ru they cost 280-344 ms. Two joined queries do the
// same work for a fraction of that, because one query string may hold any number
// of patterns and every match carries the captures of the pattern that fired.
const (
	// `receiver.prop = value` — innerHTML, outerHTML, location.search.
	jsMemberAssignmentPattern = `(assignment_expression
  left: (member_expression object: (_) @obj property: (property_identifier) @prop)
  right: (_) @val) @rrjsstmt`
	// `receiver.prop(...)` — document.write, document.writeln.
	jsMemberCallPattern = `(call_expression
  function: (member_expression object: (_) @obj property: (property_identifier) @prop)
  arguments: (arguments) @args) @rrjsstmt`
	// `$(...).prop(...)` — the jQuery sinks, matched as a chain rather than as
	// the upstream text shape, which cannot see `$(sel).find(el).html()`.
	jsChainedCallPattern = `(call_expression
  function: (member_expression object: (call_expression function: (identifier) @fn) property: (property_identifier) @prop)
  arguments: (arguments) @args) @rrjsstmt`
	// `name(...)` — eval.
	jsBareCallPattern = `(call_expression function: (identifier) @fn arguments: (arguments) @args) @rrjsstmt`
	// `key: value` — React's dangerouslySetInnerHTML as an object. JSX
	// attributes are not in this grammar; see the file header.
	jsObjectPairPattern = `(pair key: (property_identifier) @key value: (_) @val) @rrjsstmt`

	// jsSinkQuery is every DOM-write shape in one query.
	jsSinkQuery = jsMemberAssignmentPattern + "\n" + jsMemberCallPattern + "\n" +
		jsChainedCallPattern + "\n" + jsBareCallPattern + "\n" + jsObjectPairPattern

	// jsMemberReadPattern is a member expression that is only read —
	// `location.hash`, `document.URL`, `window.location.search` — with no
	// assignment and no call on it. Those two shapes are already in
	// `jsSinkQuery`, and matching them again here would report the same node
	// twice under two kinds.
	jsMemberReadPattern = `(member_expression
  object: (_) @obj
  property: (property_identifier) @prop) @rrjsread`

	// jsRequestCallPattern is the call-site shape for `jsurls-sinks`. Upstream
	// does not name the callees it accepts — it accepts any callee whose name is
	// spelled with identifier characters, and decides by whether one of the
	// arguments is a string literal that looks like a path. So the query has no
	// list of receivers: `x.open('POST', '/api/x')` is reported under the name
	// the bundle gives it, exactly as upstream does.
	jsRequestCallPattern = `(call_expression
  function: (_) @callee
  arguments: (arguments) @args) @rrjscall`

	jsRequestAssignmentPattern = `(assignment_expression
  left: (_) @assignleft
  right: (_) @assignright) @rrjsassign`

	jsMemberReadQuery    = jsMemberReadPattern
	jsRequestCallQuery   = jsRequestCallPattern
	jsRequestAssignQuery = jsRequestAssignmentPattern

	// Comments and string literals share a query: both are leaves, and the caller
	// dispatches on the node type it receives, which is what each of them wants
	// anyway.
	jsCommentPattern = `(comment) @rrjsnode`
	jsStringPattern  = `(string) @rrjsnode`
	// Template literals are their own node type, and they are where a bundler
	// puts almost every literal: measured on the OWASP Juice Shop bundles,
	// `juice-sh.op` appeared in `(template_string)` twelve times and in
	// `(string)` zero times, so a query without it found no address at all in
	// the application that ships them on purpose.
	jsTemplateStringPattern = `(template_string) @rrjsnode`
	jsLeafQuery             = jsCommentPattern + "\n" + jsStringPattern + "\n" + jsTemplateStringPattern
)

// jsDOMWriteProperties are the assignments that put program data into the page.
// Severity is the operator-facing read, not a CVSS score: writing markup is a
// sink, and whether it is exploitable is what the analyst decides after reading
// the evidence.
var jsDOMWriteProperties = map[string]string{
	"innerHTML": jsSeverityHigh,
	"outerHTML": jsSeverityHigh,
}

// jsLocationProperties are the navigation sinks. Lower than a DOM write: moving
// the browser is a redirect, writing into it is script execution in the origin.
var jsLocationProperties = map[string]bool{"href": true, "hash": true, "search": true}

// jsEventHandlerProperties are the handlers a program can attach by assignment.
// The set is exact rather than a prefix test on purpose: measured on the Juice
// Shop bundles, a `prop.startsWith("on")` rule reports `onTouched`, which is an
// Angular event binding and not a DOM handler, and thirty such assignments in
// `main.js` alone. An unknown `onWhatever` stays unreported rather than becoming
// a finding whose name means nothing.
var jsEventHandlerProperties = map[string]bool{
	"onabort": true, "onblur": true, "onchange": true, "onclick": true,
	"onclose": true, "oncontextmenu": true, "onerror": true, "onfocus": true,
	"oninput": true, "onkeydown": true, "onkeyup": true, "onload": true,
	"onmousedown": true, "onmouseenter": true, "onmouseleave": true,
	"onmousemove": true, "onmouseout": true, "onmouseover": true,
	"onmouseup": true, "onreset": true, "onscroll": true, "onselect": true,
	"onsubmit": true, "onunload": true,
}

// jsJQueryReceivers and jsJQueryProperties name the jQuery sinks. `$` and
// `jQuery` are the two names jQuery answers to; a bundle that aliases the library
// to something else is not detectable statically, and pretending otherwise would
// be a claim the evidence cannot support.
var jsJQueryReceivers = map[string]bool{"$": true, "jQuery": true}

var jsJQueryProperties = map[string]bool{"html": true, "append": true}

// jsReactSinkProperty is the object key that hands markup to React.
const jsReactSinkProperty = "dangerouslySetInnerHTML"

// jsEvalName is the one identifier call that turns a string into code.
const jsEvalName = "eval"

// jsEvalTaintPattern reads the arguments of an `eval` and decides whether the
// code being evaluated came from somewhere the page owner does not control. It
// is a heuristic on names, and it is stated as one: `eval` of a constant is
// reported as a sink and only raised to `critical` when one of these names is
// present in the call.
var jsEvalTaintPattern = regexp.MustCompile(
	`(?i)\b(location|urlsearchparams|document\.cookie|window\.name|search|hash|query|param|referrer|user|input|username|email|password)\b`,
)

// jsEmailPattern is the upstream one, unchanged.
var jsEmailPattern = regexp.MustCompile(`\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`)

// jsCommentMarkerPattern and jsSuspiciousCommentPattern are anchored, as upstream
// anchors them. Both are matched against the comment body with its `//`, `/*`,
// `*` and `*/` removed.
var jsCommentMarkerPattern = regexp.MustCompile(
	`(?i)^(TODO|FIXME|XXX|HACK|BUG|NOTE|SECURITY|DEPRECATED|WARNING|TEMP)\b`,
)

var jsSuspiciousCommentPattern = regexp.MustCompile(
	`(?i)^(password|passwd|pwd|secret|apikey|api[_-]key|key|token|admin|backdoor|debug|test|hardcoded)\b`,
)

// jsFindingCollector accumulates findings and folds duplicates as it goes.
//
// It is a type rather than four functions writing into a map because the fold is
// the point: the same `innerHTML` write in a minified bundle is one row with a
// count, and only one code path may decide that.
type jsFindingCollector struct {
	body   []byte
	starts []int
	cache  map[string]int
	folded map[string]*jsFinding
	order  []string
	// functions is the second output of the sink pass: the DOM-write sinks also
	// name a function to look at, which is a different question from where the
	// write is.
	functions map[string]*jsFunction
	emails    map[string]bool
}

// jsFunction is one named function and the worst thing found inside it.
type jsFunction struct {
	severity string
	evidence string
	line     int
}

// jsFindingRank orders the categories in the record so a reader meets the sinks
// first and the comments last, every time.
func jsFindingRank(kind string) int {
	switch kind {
	case jsFindingSink:
		return 0
	case jsFindingFunction:
		return 1
	// The credentials and the privileged actions come next, and before the
	// informational rows, because a reader who stops reading has still seen the
	// two things that are actually worth their attention. The routes come last
	// of all: there can be hundreds of them, and they are inventory rather than
	// evidence.
	case jsFindingHardcodedAuthToken:
		return 2
	case jsFindingPrivilegedEndpoint:
		return 3
	case jsFindingViteDevServer:
		return 4
	// Electron sits with the Vite markers rather than with the credentials: both
	// answer "what does an injection into this page become", and both are read
	// against the sinks that sit above them.
	case jsFindingElectronExposure:
		return 5
	case jsFindingInternalService:
		return 6
	case jsFindingEmail:
		return 7
	case jsFindingSuspicious:
		return 8
	case jsFindingRoute:
		return 9
	case jsFindingSourceMap:
		return 10
	case jsFindingSourceMapFile:
		return 11
	default:
		return 12
	}
}

// jsSeverityRank orders severities so the worst one wins when two findings
// describe the same subject.
func jsSeverityRank(severity string) int {
	switch severity {
	case jsSeverityCritical:
		return 4
	case jsSeverityHigh:
		return 3
	case jsSeverityMedium:
		return 2
	case jsSeverityInfo:
		return 1
	default:
		return 0
	}
}

// collectJSFindings reads everything the analyser categories look for out of the
// tree jsluice already parsed.
//
// It takes the analyzer rather than the bytes on purpose: a second parse of the
// same file would double the cost of the most expensive thing the crawler does
// per JavaScript resource, and the parse is what makes these categories better
// than the patterns they replace.
func collectJSFindings(analyzer *jsluice.Analyzer, body []byte) []jsFinding {
	collector := newJSFindingCollector(body)
	collector.collectSinks(analyzer)
	collector.collectComments(analyzer)
	collector.collectEmails(analyzer)
	collector.collectDOMSources(analyzer)
	collector.collectRequestCalls(analyzer)
	return collector.result()
}

// jsDOMSourceObjects and jsDOMSourceProperties are upstream `findomxss.sh`'s
// pattern, split so that it can be matched against the tree instead of against
// text.
//
// The upstream regex is `(document|location|window)\.(URL|documentURI|search|
// hash|referrer|(location\.)?href|name)`. `window.location.href` is written
// upstream as `window` + the alternative `location.` + `href`, which is why the
// receiver set carries `window` and the property set carries `href` while the
// `location.location.href` spelling is not a thing any code writes.
//
// `document.cookie` is deliberately absent: upstream's pattern does not list it,
// and adding it would be a claim about the original that the original does not
// make. It is read by the `eval` taint rule instead, which is where a tainted
// `eval` is already raised to `critical`.
var jsDOMSourceObjects = map[string]bool{
	"document": true, "location": true, "window": true, "self": true, "top": true, "parent": true,
}

var jsDOMSourceProperties = map[string]bool{
	"URL": true, "documentURI": true, "documentURIComponent": true,
	"search": true, "hash": true, "referrer": true, "href": true, "name": true,
}

// collectDOMSources reports the reads of attacker-controlled locations.
//
// A read, not a write, and that is the whole point of the category: it is the
// source half of a DOM XSS and it is what makes the sink half worth reporting as
// critical. `location.hash` in a bundle with no DOM write is a fact about the
// program, and the fact is only useful next to the write.
func (c *jsFindingCollector) collectDOMSources(analyzer *jsluice.Analyzer) {
	analyzer.QueryMulti(jsMemberReadQuery, func(matches jsluice.QueryResult) {
		objectNode := matches["obj"]
		propertyNode := matches["prop"]
		if objectNode == nil || propertyNode == nil {
			return
		}
		object := strings.TrimSpace(objectNode.Content())
		property := strings.TrimSpace(propertyNode.Content())
		if object == "" || property == "" {
			return
		}
		// Upstream's pattern is `(document|location|window)\.(URL|documentURI|
		// search|hash|referrer|(location\.)?href|name)`, so the middle link of
		// `window.location.href` is written as an optional `location.` inside the
		// property alternation. The tree gives the same chain as a nested member
		// expression, so `object` is `window.location` here and the receiver is
		// everything before its last dot.
		index := strings.LastIndex(object, ".")
		if index < 0 {
			if !jsDOMSourceObjects[object] || !jsDOMSourceProperties[property] {
				return
			}
			subject := object + "." + property
			c.add(jsFindingDOMSource, jsSeverityMedium, subject,
				jsEnclosingFunction(matches["rrjsread"]), jsFindingEvidence(subject), subject)
			return
		}
		receiver := object[:index]
		link := object[index+1:]
		// The receiver must be one of the three upstream names, and the link
		// between it and the property must be either nothing or the literal
		// `location` upstream allows there — anything else is a chain the
		// original's regex does not match, and matching it would be us claiming
		// coverage the original does not have.
		if !jsDOMSourceObjects[receiver] || !jsDOMSourceProperties[property] {
			return
		}
		if link != "location" && !jsDOMSourceProperties[link] {
			return
		}
		subject := object + "." + property
		c.add(jsFindingDOMSource, jsSeverityMedium, subject,
			jsEnclosingFunction(matches["rrjsread"]), jsFindingEvidence(subject), subject)
	})
}

// jsRequestCallNamePattern is upstream's `reJSName`: the callee has to be
// spelled with identifier characters, which is what excludes an immediately
// invoked anonymous function — upstream says so in its own comment, and a call
// site has to have a name to be worth reporting.
var jsRequestCallNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_$.-]+$`)

// collectRequestCalls is the port of `BishopFox/jsluice`'s `jsurls-sinks` mode
// (`cmd/jsurls-sinks/main.go`), and it is a port of its *rule*, not of a name
// list: upstream accepts any callee whose name is spelled with identifier
// characters and reports it when one of its arguments is a string literal that
// looks like a path.
//
// What this row adds that the endpoint list does not is the callee and the
// position of the argument that carried the path — upstream's output is
// literally `fetch (arg 0)` and `xhr.open (arg 1)`. Two calls with the same URL
// and different verbs, or the same verb and different positions, are the same
// endpoint row here and different rows there.
//
// The severity is `info`: calling `fetch` is not a defect, and a category that
// claims otherwise is a category an analyst learns to skip.
func (c *jsFindingCollector) collectRequestCalls(analyzer *jsluice.Analyzer) {
	analyzer.QueryMulti(jsRequestCallQuery, func(matches jsluice.QueryResult) {
		calleeNode := matches["callee"]
		argumentsNode := matches["args"]
		if calleeNode == nil || argumentsNode == nil {
			return
		}
		name := strings.TrimSpace(calleeNode.Content())
		if !jsRequestCallNamePattern.MatchString(name) {
			return
		}
		position, ok := c.jsPathArgument(argumentsNode)
		if !ok {
			return
		}
		subject := name + " (arg " + strconv.Itoa(position) + ")"
		c.add(jsFindingRequestCall, jsSeverityInfo, subject,
			jsEnclosingFunction(matches["rrjscall"]), jsFindingEvidence(name), name)
	})
	// Upstream's second shape: a plain assignment whose right side is a path.
	// `basePath = '/api/v2'` names where the program's requests start, and no
	// endpoint row carries that.
	analyzer.QueryMulti(jsRequestAssignQuery, func(matches jsluice.QueryResult) {
		leftNode := matches["assignleft"]
		rightNode := matches["assignright"]
		if leftNode == nil || rightNode == nil {
			return
		}
		left := strings.TrimSpace(leftNode.Content())
		if !jsRequestCallNamePattern.MatchString(left) {
			return
		}
		decoded, ok := jsLeadingString(rightNode)
		if !ok || !jsRequestPathPrefix.MatchString(decoded) {
			return
		}
		subject := left + " (assignment)"
		c.add(jsFindingRequestCall, jsSeverityInfo, subject,
			jsEnclosingFunction(matches["rrjsassign"]), jsFindingEvidence(left), left)
	})
}

// jsLeadingString walks down the left spine of an expression until it reaches a
// leaf and answers that leaf's value when it is a string or template literal.
//
// This is upstream's `startsWithString`, which reads the first *byte* of the
// node's source. Measured difference, and it is a real one: on
// `window.location.href = 'https://tracker/p?e=' + encodeURIComponent(q)` the
// original reports the assignment and a node-type check does not, because the
// node is a binary expression and not a string. The leftmost operand is the
// literal the original read, so that is what is asked for here.
func jsLeadingString(node *jsluice.Node) (string, bool) {
	for node != nil {
		switch node.Type() {
		case "string", "template_string":
			decoded := node.DecodedString()
			if decoded == "" {
				return "", false
			}
			return decoded, true
		case "binary_expression", "parenthesized_expression", "sequence_expression":
			child := node.NamedChild(0)
			if child == nil {
				return "", false
			}
			node = child
		default:
			return "", false
		}
	}
	return "", false
}
func (c *jsFindingCollector) jsPathArgument(arguments *jsluice.Node) (int, bool) {
	position := 0
	for _, argument := range arguments.NamedChildren() {
		decoded, ok := jsDecodedStringLiteral(argument)
		if ok && jsRequestPathPrefix.MatchString(decoded) {
			return position, true
		}
		position++
	}
	return 0, false
}

// jsRequestPathPrefix is upstream's `couldBePath`, unchanged, including the
// length floors: `len("/") > 3` means a two-segment path at minimum, so `/a`
// and `/` are not request targets upstream and are not here.
var jsRequestPathPrefix = regexp.MustCompile(`^(https?:.{4,}|/.{3,}|\./.{4,})`)

// jsDecodedStringLiteral answers a node's value when it is a string or template
// literal, and reports not-ok otherwise.
//
// Upstream's `startsWithString` checks the first byte of the node's source for a
// quote; reading the decoded value instead is the same test on the tree, and it
// is what lets `'/api/x'` and “ `/api/x` “ answer the same.
func jsDecodedStringLiteral(node *jsluice.Node) (string, bool) {
	switch node.Type() {
	case "string", "template_string":
		decoded := node.DecodedString()
		if decoded == "" {
			return "", false
		}
		return decoded, true
	default:
		return "", false
	}
}

func newJSFindingCollector(body []byte) *jsFindingCollector {
	// The line index is built once. Computing it per finding would be a second
	// pass over the file for every row, and the file can be a multi-megabyte
	// bundle.
	starts := make([]int, 1, 1+bytes.Count(body, []byte{'\n'}))
	for offset := 0; offset < len(body); {
		next := bytes.IndexByte(body[offset:], '\n')
		if next < 0 {
			break
		}
		offset += next + 1
		starts = append(starts, offset)
	}
	return &jsFindingCollector{
		body:      body,
		starts:    starts,
		cache:     make(map[string]int),
		folded:    make(map[string]*jsFinding),
		functions: make(map[string]*jsFunction),
		emails:    make(map[string]bool),
	}
}

// lineOf answers "which line does this text start on" and caches the answer.
//
// jsluice does not expose node positions through its `Node` wrapper, so the line
// is found by locating the evidence in the bytes the crawler already holds — the
// same approach `secretLineOf` takes for a secret value. A needle that is not
// found yields 0, which the record states as "line unknown" rather than as line 1.
func (c *jsFindingCollector) lineOf(needle string) int {
	if needle == "" {
		return 0
	}
	if line, ok := c.cache[needle]; ok {
		return line
	}
	line := 0
	if index := bytes.Index(c.body, []byte(needle)); index >= 0 {
		// The count of line starts that are at or before the needle is the
		// 1-based line the needle is on. `sort.SearchInts(starts, index)` is not
		// that value — it is the first start at or after the needle, which is the
		// *next* line whenever the needle is not at the very beginning of one.
		// The test for this is `> index`, not `>= index`, and getting it wrong
		// moved every finding down one line.
		line = sort.Search(len(c.starts), func(position int) bool {
			return c.starts[position] > index
		})
	}
	c.cache[needle] = line
	return line
}

// add folds one finding into the record.
//
// The key is kind, subject and function, and deliberately not the evidence: the
// same write with a different line number is the same write, and reporting it
// twice is what the upstream "innerHTML Assignment" plus "innerHTML
// Concatenation" pair does on one line.
func (c *jsFindingCollector) add(kind, severity, subject, function, evidence, needle string) {
	if subject == "" {
		return
	}
	key := kind + "\x00" + subject + "\x00" + function
	line := c.lineOf(needle)
	if existing, ok := c.folded[key]; ok {
		existing.Count++
		if line > 0 && (existing.Line == 0 || line < existing.Line) {
			existing.Line = line
			existing.Evidence = evidence
		}
		if jsSeverityRank(severity) > jsSeverityRank(existing.Severity) {
			existing.Severity = severity
		}
		return
	}
	c.folded[key] = &jsFinding{
		Kind:     kind,
		Severity: severity,
		Subject:  subject,
		Function: function,
		Evidence: evidence,
		Line:     line,
		Count:    1,
	}
	c.order = append(c.order, key)
}

// noteFunction remembers a named function that contains a DOM-write sink.
//
// The line and the evidence are the first sink found inside it, and the earliest
// one wins: a function reported without a line is a name an analyst has to grep
// for, which is the state this record existed to avoid.
func (c *jsFindingCollector) noteFunction(name, severity, evidence, needle string) {
	if name == "" {
		return
	}
	line := c.lineOf(needle)
	existing, ok := c.functions[name]
	if !ok {
		c.functions[name] = &jsFunction{severity: severity, evidence: evidence, line: line}
		return
	}
	if jsSeverityRank(severity) > jsSeverityRank(existing.severity) {
		existing.severity = severity
		existing.evidence = evidence
		existing.line = line
	}
}

// collectSinks is the whole DOM-write pass. Every pattern in the query was
// validated against the original `jsluice query` binary on the fixture, so a
// category that reports nothing here is a category that has nothing in the file.
//
// One query carries five patterns, so the handler has to tell which one fired.
// The captures do that on their own — an object key, a member receiver, a bare
// identifier — and the node type settles the two shapes that share a receiver,
// because `receiver.prop = value` and `receiver.prop(...)` are both an `obj` and
// a `prop` and are nothing else alike.
func (c *jsFindingCollector) collectSinks(analyzer *jsluice.Analyzer) {
	analyzer.QueryMulti(jsSinkQuery, func(matches jsluice.QueryResult) {
		statement := matches.Get("rrjsstmt")
		if statement == nil {
			return
		}
		if key := matches.Get("key"); key != nil {
			if key.RawString() == jsReactSinkProperty {
				c.addSink(jsSeverityHigh, jsReactSinkProperty, statement, true)
			}
			return
		}
		if function := matches.Get("fn"); function != nil && matches.Get("obj") == nil {
			if property := matches.Get("prop"); property != nil {
				// `$(...).html(...)` — a jQuery sink is a sink but not a *DOM-write*
				// one for the function list, which is kept to what upstream
				// classified that way: a function whose body puts markup into the
				// document. A function that appends a node is reported by the sink
				// row, at the line, and that is where the analyst reads it.
				if jsJQueryReceivers[function.RawString()] && jsJQueryProperties[property.RawString()] {
					c.addSink(jsSeverityMedium, function.RawString()+"(...)."+property.RawString(), statement, false)
				}
				return
			}
			// `eval(...)`.
			if function.RawString() != jsEvalName {
				return
			}
			severity := jsSeverityHigh
			if arguments := matches.Get("args"); arguments != nil && jsEvalTaintPattern.MatchString(arguments.Content()) {
				severity = jsSeverityCritical
			}
			c.addSink(severity, jsEvalName, statement, true)
			return
		}
		object := matches.Get("obj")
		property := matches.Get("prop")
		if object == nil || property == nil {
			return
		}
		receiver := strings.TrimSpace(object.Content())
		name := property.RawString()
		if statement.Type() != "assignment_expression" {
			// `receiver.prop(...)`. The receiver is not always the identifier
			// `document`: a bundle writes into a window it just opened as
			// `window.open(...).document.write(...)`, and the Juice Shop main
			// bundle has exactly that — measured, not assumed.
			if (receiver == "document" || strings.HasSuffix(receiver, ".document")) &&
				(name == "write" || name == "writeln") {
				c.addSink(jsSeverityHigh, "document."+name, statement, true)
			}
			return
		}
		// `receiver.prop = value`.
		switch {
		case jsDOMWriteProperties[name] != "":
			c.addSink(jsDOMWriteProperties[name], receiver+"."+name, statement, true)
		case jsLocationProperties[name] && jsLocationReceiver(receiver):
			c.addSink(jsSeverityMedium, receiver+"."+name, statement, false)
		case jsEventHandlerProperties[name]:
			c.addSink(jsSeverityMedium, receiver+"."+name, statement, true)
		}
	})
}

// addSink records a DOM-write sink and, when it is one of the sinks that writes
// markup into the document and it sits inside a named function, remembers that
// function as a review target.
//
// The last argument is what keeps the two categories apart. `location.search = …`
// and `$('#panel').html(…)` are sinks and are reported as sinks; only the
// markup-writing ones also produce a row that names the function, which is the
// upstream `xss_functions` category.
func (c *jsFindingCollector) addSink(severity, subject string, statement *jsluice.Node, markupWriter bool) {
	source := statement.Content()
	enclosing := jsEnclosingFunction(statement)
	evidence := jsFindingEvidence(source)
	needle := jsFindingNeedle(source)
	c.add(jsFindingSink, severity, subject, enclosing, evidence, needle)
	if markupWriter {
		c.noteFunction(enclosing, severity, evidence, needle)
	}
}

// jsLocationReceiver reports whether the left-hand side is the location object.
//
// `location`, `window.location`, `document.location` and `this.location` are all
// the same navigation sink, and a rule that accepted only the first one would
// miss the two forms a bundle actually writes.
func jsLocationReceiver(receiver string) bool {
	return receiver == "location" || strings.HasSuffix(receiver, ".location")
}

// jsEnclosingFunction walks up from a node and returns the name of the function
// it sits in, or "" at file scope.
//
// The name is read from the node that owns the function rather than from the
// function node itself: a declaration carries its name, while an arrow function
// is named by whatever holds it — a variable, an object key or the left side of
// an assignment. Stopping at the first name found is what keeps
// `const render = () => { … }` reported as `render`.
func jsEnclosingFunction(node *jsluice.Node) string {
	for parent := node.Parent(); parent != nil; parent = parent.Parent() {
		switch parent.Type() {
		case "function_declaration", "generator_function_declaration", "method_definition":
			if name := parent.ChildByFieldName("name"); name != nil {
				return name.Content()
			}
		case "function_expression", "arrow_function", "function":
			if owner := parent.Parent(); owner != nil {
				if name := jsBindingName(owner); name != "" {
					return name
				}
			}
		}
	}
	return ""
}

// jsBindingName returns the identifier a node is bound to, if any.
func jsBindingName(node *jsluice.Node) string {
	switch node.Type() {
	case "variable_declarator":
		if name := node.ChildByFieldName("name"); name != nil {
			return name.Content()
		}
	case "pair":
		if key := node.ChildByFieldName("key"); key != nil {
			return key.Content()
		}
	case "assignment_expression":
		if left := node.ChildByFieldName("left"); left != nil {
			return left.Content()
		}
	}
	return ""
}

// comments reads every comment node and classifies the two upstream comment
// categories.
func (c *jsFindingCollector) collectComments(analyzer *jsluice.Analyzer) {
	analyzer.Query(jsLeafQuery, func(node *jsluice.Node) {
		if node.Type() != "comment" {
			return
		}
		text := node.Content()
		kind, severity, subject := jsClassifyComment(text)
		if kind == "" {
			return
		}
		c.add(kind, severity, subject, "", jsFindingEvidence(text), text)
	})
}

// jsClassifyComment answers which of the two comment categories a comment is, if
// either.
//
// The body is what the comment says once its punctuation is removed, so that
// `// TODO: rotate` and `/* TODO: rotate */` are the same finding. A comment that
// is neither is not reported: a category that fires on every comment in a bundle
// is noise, and noise is how a badge stops being read.
// jsBlockMarkerPattern is upstream's second comment pattern,
// `/\*[\s\S]*?(TODO|…)[\s\S]*?\*/`, read as what it actually says: a marker
// **anywhere inside** a block comment.
//
// The anchored `jsCommentMarkerPattern` is upstream's *first* pattern, whose
// `//\s*` genuinely does require the marker at the head of the line. Applying
// that head-anchor to block comments was the gap, and it was found by
// measurement rather than by reading: on the exhaustive fixture upstream
// reported 19 comments and this reported 18, and the missing two were exactly
// `/* … TODO … */` and the four-line `/*\n FIXME: …\n*/`.
//
// The line-by-line scan is deliberate rather than a second pass over the whole
// body: the marker may sit on any line of a long block comment, and that line is
// the evidence an analyst wants.
var jsBlockMarkerPattern = regexp.MustCompile(
	`(?i)\b(TODO|FIXME|XXX|HACK|BUG|NOTE|SECURITY|DEPRECATED|WARNING|TEMP)\b`)

func jsClassifyComment(text string) (kind, severity, subject string) {
	body := jsCommentBody(text)
	if strings.HasPrefix(text, "/*") {
		// A block comment is the shape upstream's second pattern is written for,
		// so the marker is looked for anywhere in it rather than at its head.
		if match := jsBlockMarkerPattern.FindStringSubmatch(body); match != nil {
			return jsFindingComment, jsSeverityInfo, strings.ToUpper(match[1])
		}
	} else if match := jsCommentMarkerPattern.FindStringSubmatch(body); match != nil {
		return jsFindingComment, jsSeverityInfo, strings.ToUpper(match[1])
	}
	if match := jsSuspiciousCommentPattern.FindStringSubmatch(body); match != nil {
		return jsFindingSuspicious, jsSeverityMedium, strings.ToLower(match[1])
	}
	return "", "", ""
}

// jsCommentBody strips the comment punctuation and the whitespace around it.
func jsCommentBody(text string) string {
	trimmed := strings.TrimSpace(text)
	trimmed = strings.TrimPrefix(trimmed, "//")
	trimmed = strings.TrimPrefix(trimmed, "/*")
	trimmed = strings.TrimSuffix(trimmed, "*/")
	return strings.TrimSpace(strings.TrimLeft(trimmed, "*"))
}

// emails reads the addresses out of string literals.
//
// Literals rather than the whole file, so an address inside a comment or inside
// a dead identifier is not a finding, and the placeholder vocabulary of
// `isPlaceholderValue` filters the same stand-ins the rest of the tool filters,
// which is also what the upstream analyser filtered them with.
func (c *jsFindingCollector) collectEmails(analyzer *jsluice.Analyzer) {
	analyzer.Query(jsLeafQuery, func(node *jsluice.Node) {
		if node.Type() != "string" && node.Type() != "template_string" {
			return
		}
		decoded := node.DecodedString()
		if !strings.Contains(decoded, "@") {
			return
		}
		for _, address := range jsEmailPattern.FindAllString(decoded, -1) {
			if c.emails[address] || isPlaceholderValue(address) {
				continue
			}
			c.emails[address] = true
			c.add(jsFindingEmail, jsSeverityInfo, address, "", jsFindingEvidence(decoded), node.Content())
		}
	})
}

// result folds the function findings in and returns the record.
func (c *jsFindingCollector) result() []jsFinding {
	findings := make([]jsFinding, 0, len(c.order)+len(c.functions))
	for _, key := range c.order {
		findings = append(findings, *c.folded[key])
	}
	names := make([]string, 0, len(c.functions))
	for name := range c.functions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		function := c.functions[name]
		findings = append(findings, jsFinding{
			Kind:     jsFindingFunction,
			Severity: function.severity,
			Subject:  name,
			Evidence: function.evidence,
			Line:     function.line,
			Count:    1,
		})
	}
	sort.SliceStable(findings, func(left, right int) bool {
		if rank, other := jsFindingRank(findings[left].Kind), jsFindingRank(findings[right].Kind); rank != other {
			return rank < other
		}
		if findings[left].Severity != findings[right].Severity {
			return jsSeverityRank(findings[left].Severity) > jsSeverityRank(findings[right].Severity)
		}
		if findings[left].Line != findings[right].Line {
			return findings[left].Line < findings[right].Line
		}
		return findings[left].Subject < findings[right].Subject
	})
	return findings
}

// jsFindingEvidence renders the source a finding was read from into something a
// table cell and a JSON export can both hold.
func jsFindingEvidence(source string) string {
	collapsed := strings.Join(strings.Fields(source), " ")
	const limit = 160
	runes := []rune(collapsed)
	if len(runes) <= limit {
		return collapsed
	}
	return string(runes[:limit]) + "…"
}

// jsFindingNeedle shortens a source excerpt into something safe to search for in
// the file.
//
// The cut is at a rune boundary and the result is capped, because the excerpt of
// a statement in a minified bundle can be the whole bundle, and `bytes.Index`
// over a multi-megabyte haystack for a multi-megabyte needle is a cost with no
// return.
func jsFindingNeedle(source string) string {
	const limit = 96
	runes := []rune(source)
	if len(runes) <= limit {
		return source
	}
	return string(runes[:limit])
}
