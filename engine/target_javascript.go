package main

// JavaScript analysis for the Target crawler.
//
// # What this replaces, and why
//
// Until now the crawler read a JavaScript resource and pulled references out of
// it with a regular expression, `mapURLPattern`:
//
//	`(?i)(?:["'(\s]|^)((?:https?://|/)[^"'()\s<>]+)`
//
// That sees the text, not the program. It cannot tell `fetch("/api/v1/users/"+id)`
// from the string `"/api/v1/users/"` that happens to sit next to it, it has no
// method, no parameter names and no idea whether the reference was ever used as
// a request at all. jsluice parses the file with tree-sitter and reports the
// call site: which function, which method, which query and body parameters, and
// what object the value came from. On a hand-written sample the same file
// yields this instead of a flat list of strings:
//
//	/api/v1/users/EXPR   type=fetch   method=POST
//	/login?redirect=EXPR&method=oauth  type=locationAssignment  queryParams=[redirect method]
//	/api/legacy/report   type=$.ajax  method=POST
//
// jsluice is a Go package (MIT, Bishop Fox) and is linked into the engine
// rather than shipped as a binary. That is the whole point of the choice: the
// bytes the crawler already read are the input, so no second process, no second
// fetch of the same asset, and no request that bypasses the passive proxy the
// rest of the traffic goes through.
//
// # The cost, measured rather than assumed
//
// jsluice parses with `smacker/go-tree-sitter`, which is cgo. Two consequences
// are paid for explicitly instead of being discovered later:
//
//   - `engine/Dockerfile` now installs `build-base` in the build stage, because
//     `golang:1.26-alpine` has no C compiler and a tree that does not compile is
//     a build that does not run.
//   - There is no byte cap on the analysis. The project forbids hidden limits,
//     and a cap on what may be analysed is a cap on what may be found. What is
//     published instead is the cost: every page carries `js.ms` and `js.bytes`.
//
// Measured on this machine before the code was written, wall clock and heap for
// `NewAnalyzer` + `GetURLs` + `GetSecrets`:
//
//	jquery.min.js          87 KB     346 ms     6 MB    0 URLs
//	select2.full.js       174 KB     472 ms     8 MB    0 URLs
//	100k nested arrays    200 KB     985 ms     -      0 URLs
//	200k nested parens    400 KB   1 367 ms     -      0 URLs
//	20k copies of a fetch 1.3 MB   1 647 ms    35 MB  20 000 URLs
//	1M nested parens      2.0 MB   7 899 ms     -      0 URLs
//
// That is roughly 3 ms per kilobyte, and the pathological nesting depth that
// costs eight seconds is not a thing a web server emits. The two rows that
// matter are the last two: the repeated-file row produced 20 000 matches for one
// endpoint, which is why `mergeJSEndpoints` exists, and the 1M-nesting row is
// why the recover below exists.
//
// # Why a recover
//
// A panic on any goroutine terminates the process, and this goroutine is the
// crawl. The input is a file served by a host the analyst does not control, so
// "the parser will not panic" is an assumption about someone else's server. A
// recovered panic becomes an `error` string on that one page; the crawl
// continues and the analyst sees that the file was not read rather than losing
// the engine, the passive proxy, the SSE stream and every running job.

import (
	"bytes"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/BishopFox/jsluice"
)

// jsExpressionMarker is the literal jsluice substitutes for a value it cannot
// know. `"/api/users/" + uid` becomes `/api/users/EXPR`: a real path with an
// unknown segment, which is the most useful thing a static analyser can say
// about it and is not a URL anybody should send a request to.
const jsExpressionMarker = "EXPR"

// jsAnalysis is what one JavaScript resource contributed to the crawl. It is
// attached to the page record as `page["js"]`, so it is part of the map, the
// project bundle and the export rather than a log line nobody reads.
//
// The unexported `links` field is the crawl frontier this file produced. It is
// not serialised: which references were enqueued is visible in the `pages` list
// itself, and carrying a second copy of every path in every page record would
// double the size of the export to say something the table already says.
type jsAnalysis struct {
	// Bytes is what was read and handed to the parser, so a page that reports
	// zero endpoints can be read as "this file had nothing" rather than "this
	// file was not analysed".
	Bytes int `json:"bytes"`
	// Millis is the measured wall clock of the analysis. It is the visible form
	// of the missing byte cap: a slow file says so instead of stalling silently.
	Millis int64 `json:"ms"`
	// Endpoints are the request sites the program actually names.
	Endpoints []jsEndpoint `json:"endpoints"`
	// Secrets are reported with the full value. The owner decided this on
	// 2026-09-30: a finding an analyst cannot act on is not a finding, and the
	// tool exists so the analyst can use the key it found. The fingerprint stays
	// beside the value because it is what recognises the same key in a second
	// file without reading the first one again.
	//
	// The consequence is stated rather than hidden: this record is stored in
	// PostgreSQL and reaches every export. `osint_secrets.go` deliberately keeps
	// values out of the OSINT graph for exactly that reason, so the two paths now
	// differ, and the difference is a decision, not an oversight.
	Secrets []jsSecret `json:"secrets"`
	// Findings are the four categories that are not credentials: the DOM-write
	// sinks and the functions that contain them, the comments worth reading and
	// the addresses the file carries. They are read off the same parse tree as
	// the endpoints and the secrets, in `collectJSFindings`, which is the port
	// of zack0x01/JS-Analyser — see that file's header for what was ported, what
	// was deliberately not, and what was measured against both originals.
	Findings []jsFinding `json:"findings"`
	// VulnerableLibraries are the known libraries the file carries, with the
	// version that was read out of it and the problems known for that version.
	//
	// The port is `RetireJS/retire.js`; the database is vendored, so the answer
	// does not depend on the network. A version that the extractor named but the
	// range could not be checked against is reported with an empty `below` and a
	// `Version` that is either the string read or empty — never a guess, because
	// a guessed version produces a confident report about a release nobody read.
	VulnerableLibraries []retirejsVulnerableLibrary `json:"vulnerable_libraries"`
	// LinksWithExpression counts endpoints that were not enqueued because their
	// path contains an unknown expression. Reporting the number is the
	// difference between "the crawler skipped this" and "the crawler missed it".
	LinksWithExpression int `json:"links_with_expression"`
	// Variables are the names the program binds its own values to, deduplicated
	// and sorted. This is the port of `KathanP19/JSFScan.sh`'s seventh step
	// (`tools/jsvar.sh`), whose whole output is a wordlist of `var` names for
	// a wordlist to be built from.
	//
	// It is a list of its own and not a finding kind, and the reason is
	// measured: the step is the only one of the nine that returns every match.
	// JS-Analyser's 11 sink rows on the capability fixture are 11 lines a reader
	// acts on, while that file's 30 variable names are a wordlist — on a shipped
	// bundle the same rule returns five figures. Put in `findings`, they would
	// not add thirty rows of evidence, they would bury the thirty rows that are
	// evidence, and the table a reader scans would become a table nobody scans.
	// A separate list loses nothing: every name is still here, still in the
	// record, still in the export, and still one click from the report.
	Variables []jsVariable `json:"variables"`
	// Routes are the paths the application serves, read out of a build manifest:
	// Next.js `sortedPages`, and the webpack route keys of a pages-router build.
	// This is the port of the "open DevTools and print
	// `__BUILD_MANIFEST.sortedPages`" trick, and the difference is that the
	// routes are not merely printed — they join the crawl frontier, so a page the
	// site does not link to is requested and lands on the map like any other.
	//
	// A route the manifest builds (`/blog/[slug]`) stays here and does not join
	// the frontier: there is nothing to request until the program has run, and
	// the browser-driven crawl is the one that runs it.
	Routes []jsRoute `json:"routes"`
	// Params is the fuzzing wordlist: every parameter name the call sites use and
	// every name the program binds. This is GAP's "get all parameters" and the
	// one-liner that turns `var` names into `?name=` probes, kept as a list for
	// the reason `variables` is: a wordlist is not evidence, and burying it in
	// `findings` would bury the rows that are.
	Params []jsParamCandidate `json:"params"`
	// ProbeWords is the target-specific fuzzing wordlist: each request site this
	// program names, carrying a parameter name this same program names. It is the
	// pairing that carries the sentence — "path here, that name there" — which
	// neither `endpoints` nor `params` says on its own.
	//
	// These are words to send, not findings. Nothing here has been proved against
	// the target, and a reader who treats a word as a result will fuzz the wrong
	// thing with the wrong expectation.
	ProbeWords []string `json:"probe_words,omitempty"`
	// ProbeWordsTruncated is how many combinations the per-endpoint bound
	// dropped. It is reported rather than inferred, because a wordlist that looks
	// complete and is not is worse than one that says where it stops.
	ProbeWordsTruncated int `json:"probe_words_truncated,omitempty"`
	// Error is why a file produced nothing. It is set instead of returning
	// nothing, because a silent zero reads as an empty file.
	Error string `json:"error,omitempty"`

	links []string `json:"-"`
}

// jsVariable is one name the program binds a value to.
//
// Three fields, because the two questions an analyst asks about a name are "what
// did it end up holding" and "where does it live": `Kind` separates the three
// places a name can come from, since a `const` at the top of the file is not the
// same evidence as a property of one request's options, and `Line` is what makes
// the name findable in a multi-megabyte bundle.
type jsVariable struct {
	Name string `json:"name"`
	// Kind is `declaration` for `var`/`let`/`const`, `property` for an object
	// key, and `assignment` for `window.x = …`.
	Kind string `json:"kind"`
	Line int    `json:"line"`
}

// jsEndpoint is one request site found in the source.
type jsEndpoint struct {
	// URL is the reference as written, not as resolved. The unresolved form is
	// the evidence: `/api/v1/users/EXPR` says the program builds the path, which
	// a resolved absolute URL would have hidden.
	URL    string   `json:"url"`
	Method string   `json:"method"`
	Types  []string `json:"types"`
	Query  []string `json:"query_params"`
	Body   []string `json:"body_params"`
	// Resolved is the same reference as a browser would request it, and it is
	// absent when that would say nothing new. It exists because the unresolved
	// form alone makes two reports incomparable: measured on 11 real bundles of
	// yandex.ru, 153 of our 176 references read `//advertising.yandex.ru/…`
	// where the original reads `https://advertising.yandex.ru/…`, so a reader
	// comparing the two reports saw 23 agreements out of 176 on what is one
	// and the same set. URL stays as written because it is the evidence —
	// `/api/v1/users/EXPR` says the program builds the path — and Resolved says
	// what to open.
	Resolved string `json:"resolved,omitempty"`
	// Headers and ContentType are only present for call sites that declare them,
	// which today means fetch with an explicit init object.
	Headers     map[string]string `json:"headers,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
}

// jsSecret is a secret finding, with the secret in it.
type jsSecret struct {
	// Rule is the provider name from `secretRules`, so the same leaked key is
	// called the same thing whether the crawler or the OSINT transform found it.
	Rule string `json:"rule"`
	// Severity is the operator-facing hint that goes with that rule.
	Severity string `json:"severity"`
	// Value is the credential as it was found, unredacted, because the analyst
	// has to be able to use it. It is not `omitempty`: an export that carries
	// the rule and hides the key would be a report about a finding the reader
	// cannot act on, which is the state this feature was in before the owner
	// decided against it on 2026-09-30.
	Value string `json:"value"`
	// Fingerprint is the truncated prefix plus a hash of the whole value, from
	// `secretFingerprint`. It is what recognises the same key in a second file
	// without reading this one again, and what makes two reports of one leak
	// fold into one.
	Fingerprint string `json:"fingerprint"`
	// Line points into the file so the finding can be opened rather than
	// believed.
	Line int `json:"line"`
	// Kind is jsluice's own matcher name, kept so a finding can be traced back
	// to the rule that produced it instead of appearing from nowhere.
	Kind string `json:"kind"`
}

// jsSecretKinds maps the matchers jsluice ships to this project's rule names.
//
// jsluice's built-ins cover AWS keys, Google API keys, GitHub tokens and a
// Firebase config object. `secretRules` already names the first three, so
// inventing a second vocabulary for the same finding would make the operator
// compare two names for one problem. The ids below are the ones already in use;
// `firebase_config` is new because the object shape is something only the
// analyser can see — a regex over the same text finds the same `AIza` key and
// nothing about the project it belongs to.
var jsSecretKinds = map[string]struct{ rule, severity string }{
	"AWSAccessKey": {"aws_access_key_id", "AWS access key id"},
	"gcpKey":       {"google_api_key", "Google API key"},
	"githubKey":    {"github_token", "GitHub personal access token"},
	"firebase":     {"firebase_config", "Firebase web config"},
}

// jsAwsSecretRule is reported when an AWS access key id was found together with
// a secret in the same object, which jsluice resolves structurally: the pair
// that holds the secret is the one whose sibling is the key id.
const jsAwsSecretRule = "aws_secret_access_key"

// jsExpressionFields splits a reference into the runs of letters, digits and
// underscores, which is what a substituted expression looks like once the
// separators around it are removed.
func jsExpressionFields(reference string) []string {
	return strings.FieldsFunc(reference, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_'
	})
}

// containsJSExpression reports whether jsluice stood a value in for an
// expression it could not evaluate.
//
// It compares whole fields rather than searching for the substring, because a
// real path may legitimately contain the letters. `/api/EXPR-test` in the source
// is read as an expression and is therefore not enqueued, which costs one
// unreached reference; `/api/EXPRESSION` in the source is not, because
// `EXPRESSION` is a different field. Both cases stay in `endpoints`, so nothing
// is lost — only the crawl skips them.
func containsJSExpression(reference string) bool {
	if reference == jsExpressionMarker {
		return true
	}
	for _, field := range jsExpressionFields(reference) {
		if field == jsExpressionMarker {
			return true
		}
	}
	return false
}

// mergeJSEndpoints folds the matchers' output into one row per reference.
//
// Two things make a fold necessary rather than an optimisation. jsluice reports
// the same literal more than once — `/api/v2/orders` arrives as `axios.post`
// and again as `stringLiteral` — and a file that repeats a function reports it
// once per copy, which on a measured 1.3 MB file meant 20 000 rows for a single
// endpoint. When two rows disagree, the row that knows the method wins: the
// bare string literal is the same text with nothing added, so it can never be
// the better answer.
//
// The second returned value is the crawl frontier, absolute and deduplicated.
// The third counts references held back because their path contains an
// expression.
func mergeJSEndpoints(matches []*jsluice.URL, base *url.URL) ([]jsEndpoint, []string, int) {
	type folded struct {
		endpoint jsEndpoint
		types    map[string]bool
		query    map[string]bool
		body     map[string]bool
	}
	order := make([]string, 0, len(matches))
	byURL := make(map[string]*folded, len(matches))
	for _, match := range matches {
		if match == nil {
			continue
		}
		raw := strings.TrimSpace(match.URL)
		if raw == "" {
			continue
		}
		entry, seen := byURL[raw]
		if !seen {
			// The resolved form is written beside the reference as it was read,
			// and only when it differs: `//host/p` and `/api/p` both say where
			// to go once the file they were written in is known, and the analyst
			// comparing this report with another tool's needs that form, while the
			// written one is the evidence of what the program actually built.
			endpoint := jsEndpoint{URL: raw, Method: match.Method}
			if base != nil {
				if resolved := mustResolveURL(base, raw).String(); resolved != raw {
					endpoint.Resolved = resolved
				}
			}
			entry = &folded{
				endpoint: endpoint,
				types:    map[string]bool{},
				query:    map[string]bool{},
				body:     map[string]bool{},
			}
			byURL[raw] = entry
			order = append(order, raw)
		}
		if entry.endpoint.Method == "" && match.Method != "" {
			entry.endpoint.Method = match.Method
		}
		if entry.endpoint.ContentType == "" && match.ContentType != "" {
			entry.endpoint.ContentType = match.ContentType
		}
		if entry.endpoint.Headers == nil && len(match.Headers) > 0 {
			entry.endpoint.Headers = match.Headers
		}
		if match.Type != "" {
			entry.types[match.Type] = true
		}
		for _, name := range match.QueryParams {
			entry.query[name] = true
		}
		for _, name := range match.BodyParams {
			entry.body[name] = true
		}
	}
	sort.Strings(order)
	endpoints := make([]jsEndpoint, 0, len(order))
	links := make([]string, 0, len(order))
	seenLinks := make(map[string]bool, len(order))
	// The built-up references are collected first, because whether a bare string
	// literal is half a concatenation can only be answered once every completed
	// reference is known. Deciding it in one pass over `order` would depend on
	// the sort order, and a path that was enqueued or skipped would change
	// depending on which letter sorts first.
	var built []string
	deferred := 0
	for _, raw := range order {
		if containsJSExpression(raw) {
			built = append(built, raw)
		}
	}
	for _, raw := range order {
		entry := byURL[raw]
		endpoint := entry.endpoint
		endpoint.Types = sortedJSSet(entry.types)
		endpoint.Query = sortedJSSet(entry.query)
		endpoint.Body = sortedJSSet(entry.body)
		endpoints = append(endpoints, endpoint)
		// The count is taken before the gate, because "held back because the
		// program builds this path" and "not a reference at all" are different
		// answers and only the first one is a discovery the analyst is missing.
		// Counted after the gate it would always be zero, which is what the first
		// version of this did.
		if containsJSExpression(raw) {
			deferred++
			continue
		}
		// The gate is not `validMapReference`, and the difference is measured
		// rather than stylistic. That function was written for the regular
		// expression and only accepts a reference that starts with `/` or a
		// scheme, because text scraped out of a file has no base to resolve
		// against. A string literal found by a parser does have a base — the file
		// it was read from — so `api/v1/users.json` in `/assets/app.js` is a real
		// reference and the old gate silently dropped it. Measured: with the old
		// gate, a bundle referencing `api/v1/users.json` produced zero crawl
		// links.
		if !jsCrawlableReference(raw) {
			continue
		}
		// Half of a path the program assembles is not a path. Both rows stay in
		// `endpoints`; only the crawl skips the fragment.
		if jsConcatenatedFragment(raw, built) {
			continue
		}
		resolved := mustResolveURL(base, raw).String()
		if seenLinks[resolved] {
			continue
		}
		seenLinks[resolved] = true
		links = append(links, resolved)
	}
	sort.Strings(links)
	return endpoints, links, deferred
}

// jsConcatenatedFragment reports whether a reference is the left-hand piece of a
// concatenation the program assembles at runtime.
//
// jsluice reports both halves of `"/api/v1/users/" + uid`: the completed
// `/api/v1/users/EXPR`, which carries the method and the call site, and the
// bare string literal `/api/v1/users/`, which is what a query saw before the
// parser looked at the `+`. The second is not an endpoint — it is half of one.
// Requesting it sends traffic to a path that does not exist, and on the live
// fixture it produced three such requests: `/api/never-built/`, `/api/search?q=`
// and `/api/v1/users/`, all answered 200 by a fixture that answers everything.
//
// The half is recognised by being a proper prefix of a reference that carries
// the substitution marker, which is the same rule that already defers
// `/api/users/EXPR` from the frontier. Both rows stay in `endpoints`; only the
// crawl frontier loses them.
//
// The prefix alone is not enough, and getting that wrong loses a real endpoint
// silently. `/api/v1/users` is a proper prefix of `/api/v1/users/EXPR`, so a
// plain prefix test called it half a concatenation — and a listing endpoint the
// site genuinely links to was then never requested, with nothing on the screen
// to say so. The discriminator is where the cut falls: a fragment is a value the
// program was still writing when it stopped, so the reference ends on a
// separator (`/`, `?`, `&`, `=`) and the built string continues the same token. A
// reference ending in anything else names a complete resource and stays on the
// frontier, which is why `/api/v1/users` and `/api/search` are enqueued while
// `/api/v1/users/` and `/api/search?q=` are not.
func jsConcatenatedFragment(reference string, deferred []string) bool {
	if !endsOnSeparator(reference) {
		return false
	}
	for _, built := range deferred {
		if len(reference) < len(built) && strings.HasPrefix(built, reference) {
			return true
		}
	}
	return false
}

// endsOnSeparator reports whether a reference stops at a separator, which is
// where a concatenated value is still unfinished.
func endsOnSeparator(reference string) bool {
	if reference == "" {
		return false
	}
	switch reference[len(reference)-1] {
	case '/', '?', '&', '=':
		return true
	default:
		return false
	}
}

// jsCrawlableReference decides whether a reference found by the parser can be
// enqueued.
//
// It rejects a non-HTTP scheme outright, so `mailto:`, `data:`, `javascript:` and
// `blob:` are never requested, and it rejects a template string, which is
// jsluice's own marker for a reference the program builds. Everything else — a
// root-relative path, a document-relative path, a protocol-relative host, an
// absolute URL — is allowed, because the crawler resolves all four against the
// file the reference was read from and then applies its own same-origin and
// page-budget rules. Those rules are not restated here: this function answers
// "is this a reference a browser would follow", and the crawl answers "should
// this crawl follow it".
func jsCrawlableReference(reference string) bool {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return false
	}
	// A reference carrying the substitution marker is a path shape, not a path.
	if containsJSExpression(reference) {
		return false
	}
	// Braces and brackets are what a template literal and a minifier leave behind
	// where a value was interpolated. There is no URL to request until the
	// program has run, and the browser-driven crawler is the one that runs it.
	if strings.ContainsAny(reference, "{}[]|*") {
		return false
	}
	lowered := strings.ToLower(reference)
	if scheme, _, found := strings.Cut(reference, ":"); found && !strings.HasPrefix(reference, "/") {
		// A colon before the first slash is a scheme, except in the shapes that
		// are not: a port in a protocol-relative host, or a colon inside a path
		// segment such as `/a:b`.
		if slash := strings.Index(reference, "/"); slash < 0 || schemeIndex(reference) < slash {
			switch strings.ToLower(scheme) {
			case "http", "https":
			default:
				return false
			}
		}
	}
	if !strings.HasPrefix(reference, "/") &&
		!strings.HasPrefix(reference, ".") &&
		!strings.HasPrefix(reference, "#") &&
		!strings.Contains(lowered, "//") {
		// A bare word is a string, not a reference. jsluice's own filter already
		// requires a `/`, `?` or `.`, so reaching here means the reference has one
		// of those and is not a scheme; the remaining shape check is what keeps
		// "1.5" and "v1.2.3" out of the frontier.
		if !strings.ContainsAny(reference, "/?") {
			return false
		}
	}
	// A fragment is a location inside a document the crawler has already
	// requested or has not; it is not a separate resource.
	return !strings.HasPrefix(reference, "#")
}

// schemeIndex reports where a URL scheme ends, or -1 when the text has none. A
// scheme is a letter followed by letters, digits, `+`, `-` or `.` up to the first
// colon, which is the rule in RFC 3986 and the reason "a:b" is a path and
// "http:" is a scheme.
func schemeIndex(reference string) int {
	for index := 0; index < len(reference); index++ {
		switch character := reference[index]; {
		case character == ':':
			return index
		case index == 0 && !isASCIILetter(character):
			return -1
		case isASCIILetter(character) || isASCIIDigit(character) ||
			character == '+' || character == '-' || character == '.':
		default:
			return -1
		}
	}
	return -1
}

func isASCIILetter(character byte) bool {
	return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z')
}

func isASCIIDigit(character byte) bool {
	return character >= '0' && character <= '9'
}

// sortedJSSet turns a matcher-collected set into the stable, empty-never list
// the record carries. A JSON `null` array would read as "not analysed" on a page
// that was analysed and simply had no parameters.
func sortedJSSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// collectJSSecrets turns jsluice's matches and this project's own rules into
// findings that name a provider and carry a fingerprint.
//
// Two sources feed it and they do not overlap. jsluice's built-in matchers cover
// the vendor formats that are recognisable by shape; `jsRuleMatchers` covers the
// rules in `secretRules` that jsluice does not implement, run against the parse
// tree rather than against the whole file. A secret in a comment, in a string
// that is never executed, or inside a minified identifier no longer matches,
// which is the point of running the rules here rather than over the text.
// jsVariableQuery is the three shapes a name can be bound in, in one query.
//
// `jsvar.sh` upstream greps `var <name>` out of the text, which misses `let`,
// `const`, object properties and plain assignments — and a bundle written as
// ES6 has almost no `var`. So the port asks the tree for all four and says which
// shape each name came from.

// collectJSVariables returns the names the program binds values to.
//
// This is the port of `KathanP19/JSFScan.sh` step 7 (`tools/jsvar.sh`), whose
// entire output is `curl | grep -Eo "var [a-zA-Z0-9_]+" | sort -u | awk
// 'length >= 3'`. The length floor is kept because it is upstream's and it is
// right for a wordlist: `a`, `b`, `i` are loop counters, and a wordlist built
// from them is a wordlist of noise.
//
// The return is sorted and deduplicated, which is what makes it a list a reader
// can compare between two bundles rather than a transcript of tree-sitter's
// traversal order.
func collectJSVariables(analyzer *jsluice.Analyzer, body []byte) []jsVariable {
	starts := make([]int, 1, 1+bytes.Count(body, []byte{'\n'}))
	for offset := 0; offset < len(body); {
		next := bytes.IndexByte(body[offset:], '\n')
		if next < 0 {
			break
		}
		offset += next + 1
		starts = append(starts, offset)
	}
	found := make(map[string]jsVariable)
	line := func(needle string) int {
		if needle == "" {
			return 0
		}
		index := bytes.Index(body, []byte(needle))
		if index < 0 {
			return 0
		}
		return sort.Search(len(starts), func(position int) bool {
			return starts[position] > index
		})
	}
	// jsVariableShapes are the three places a name can be bound, each with the
	// capture that holds the name itself rather than the statement around it. The
	// three are separate queries rather than one alternation because a shared
	// capture name would make the kind undecidable, and the kind is one of the three
	// fields the record carries.
	var jsVariableShapes = []struct {
		kind        string
		nameCapture string
		query       string
	}{
		{
			kind:        "declaration",
			nameCapture: "declname",
			query: `(variable_declarator
  name: (identifier) @declname) @declstmt`,
		},
		{
			kind:        "property",
			nameCapture: "pairname",
			query: `(pair
  key: (property_identifier) @pairname) @pairstmt`,
		},
		{
			kind:        "assignment",
			nameCapture: "assignname",
			query: `(assignment_expression
  left: (member_expression property: (property_identifier) @assignname)) @assignstmt`,
		},
	}
	// Three shapes, three queries, one map. The name is captured under its own
	// name in each query because a single capture name across an alternation
	// would make the kind undecidable — and the kind is one of the three fields
	// the record carries.
	for _, shape := range jsVariableShapes {
		shape := shape
		analyzer.QueryMulti(shape.query, func(matches jsluice.QueryResult) {
			nameNode := matches[shape.nameCapture]
			if nameNode == nil {
				return
			}
			name := strings.TrimSpace(nameNode.Content())
			// Upstream's own floor: `awk 'length($1) >= 3'`.
			if len(name) < 3 {
				return
			}
			if _, seen := found[name]; seen {
				return
			}
			found[name] = jsVariable{Name: name, Kind: shape.kind, Line: line(name)}
		})
	}
	names := make([]string, 0, len(found))
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)
	variables := make([]jsVariable, 0, len(names))
	for _, name := range names {
		variables = append(variables, found[name])
	}
	return variables
}

// secretRulesInPriorityOrder returns the registry in the order findings are
// claimed: this project's own rules first, the ported vendor rules after.
//
// The order matters only because one credential is now folded into one row. A
// value recognised by two rules is one exposure with two names, and the row has
// to carry the project's own name for it: `stripe_secret_key` is what the
// report and the UI already speak, and a vendor rule shadowing it would rename
// a finding that predates the port and break lookups written against it.
//
// Sorting by id prefix is mechanical and needs no maintained list: every ported
// rule in this project is generated with a `pinkerton_` prefix, and the day a
// second vendor arrives the same rule covers it by adding its prefix there.
//
// A rule that declares `declinesSpecificShape` goes last of all, whatever prefix
// it carries. That rule is a catch-all: it claims anything its name and value
// shape allow, so if it goes first it swallows every finding a shape-based rule
// could have named. Measured twice, and both times it was a real loss of meaning
// rather than a duplicate row: `generic_api_key_assignment` took a three-segment
// JWT and the operator read "generic secret assignment" instead of "JWT", then took
// an `xoxb-` token and the Slack rule stopped firing. Both were found by asking
// which rule wins a value both of them recognise, not by reading the code.
//
// The flag rather than a list of shapes is the point. A JWT-shaped value was the
// first case measured and Slack the second; a third would have arrived later and a
// list of shapes would have been a shorter name for the same miss. The rule says
// what kind of rule it is, and the order follows from that.
func secretRulesInPriorityOrder() []secretRule {
	ordered := make([]secretRule, 0, len(secretRules))
	for _, rule := range secretRules {
		if !strings.HasPrefix(rule.id, "pinkerton_") && !rule.declinesSpecificShape {
			ordered = append(ordered, rule)
		}
	}
	for _, rule := range secretRules {
		if strings.HasPrefix(rule.id, "pinkerton_") && !rule.declinesSpecificShape {
			ordered = append(ordered, rule)
		}
	}
	for _, rule := range secretRules {
		if rule.declinesSpecificShape {
			ordered = append(ordered, rule)
		}
	}
	return ordered
}

func collectJSSecrets(matches []*jsluice.Secret, body []byte) []jsSecret {
	lines := strings.Split(string(body), "\n")
	findings := make([]jsSecret, 0, len(matches))
	// The fold is keyed on the rule, not on the fingerprint, and the matcher
	// name is carried alongside. A key that two matchers both recognise is one
	// finding with two reasons it was found, and which of the two reasons is
	// kept must not depend on the order tree-sitter happened to visit the tree.
	seen := make(map[string]bool, len(matches))
	appendFinding := func(kind, rule, severity, value string) {
		if value == "" || isPlaceholderValue(value) {
			return
		}
		// The same shape requirement the text scan applies, read from the same
		// registry: a rule that answers "is this a credential" in two places
		// answers it differently the first time one of them is edited.
		if named, own := jsRuleByID(kind); own && !secretValueIsUsable(named, value) {
			return
		}
		if seen[rule+"\x00"+value] {
			return
		}
		// Згортання за самим значенням **не** робиться тут: матчери приходять
		// двома родинами, і пріоритет між ними не гарантований, тому перехоплення
		// усередині знецінювало правило, яке мало виграти — саме це показав тест
		// на `stripe_secret_key`, якого перехопило правило вендора на тому самому
		// значенні. Згортання виконується після збору, де пріоритет заданий явно.
		seen[rule+"\x00"+value] = true
		prefix, digest := secretFingerprint(value)
		findings = append(findings, jsSecret{
			Rule:        rule,
			Severity:    severity,
			Value:       value,
			Fingerprint: prefix + "…" + digest[:12],
			Line:        secretLineOf(lines, value),
			Kind:        kind,
		})
	}
	for _, match := range matches {
		if match == nil {
			continue
		}
		// A match this project produced carries its own rule id as the kind; a
		// match jsluice produced carries a matcher name that has to be mapped
		// onto a rule id so the same key is called the same thing by the crawler
		// and by the OSINT transform.
		if rule, own := jsRuleByID(match.Kind); own {
			appendFinding(match.Kind, rule.id, rule.severity, jsSecretValue(match.Data, "key"))
			continue
		}
		named, known := jsSecretKinds[match.Kind]
		if !known {
			continue
		}
		switch match.Kind {
		case "AWSAccessKey":
			// The severity of an AWS finding depends on whether the secret half
			// is next to the id, which is what makes it usable rather than a
			// public identifier. jsluice resolves that from the surrounding
			// object, so the answer is read from the matcher rather than
			// invented here.
			severity := "AWS access key id"
			if jsSecretValue(match.Data, "secret") != "" {
				severity = named.severity
			}
			appendFinding(match.Kind, named.rule, severity, jsSecretValue(match.Data, "key"))
			appendFinding(match.Kind, jsAwsSecretRule, "AWS secret access key", jsSecretValue(match.Data, "secret"))
		case "firebase":
			// The config object is the finding; the key inside it is only the
			// fingerprint. Which project and which bucket the key belongs to is
			// the part a regular expression over the same text cannot reach.
			appendFinding(match.Kind, named.rule, named.severity, jsSecretValue(match.Data, "apiKey"))
		default:
			appendFinding(match.Kind, named.rule, named.severity, jsSecretValue(match.Data, "key"))
		}
	}
	// Контекстні правила читаються по всьому тілу файлу, а не по літералу.
	//
	// Причина виміряна: 14 правил Pinkerton мають вигляд `(?i)twitter.*['\"][…]['\"]`
	// або `(?i)asana[…]{0,20}=[…]`, тобто їм потрібні **сусідні** символи —
	// слово-контекст, лапки або знак присвоєння поруч із токеном. Літерал
	// містить усе це лише тоді, коли значення стоїть усередині нього; у файлі
	// токен часто лежить окремо від контексту, і тоді літерал не збігається
	// ніколи. Збіг міряється на тих самих байтах: патерн збігається з файлом
	// (`ok=true`), а `jsRuleValue` на літералі повертає порожньо.
	//
	// Чому це окремий прохід, а не розширення літерального матчера: jsluice не
	// віддає позиції вузлів через свій `Node`, тож вікно навколо літерала з
	// нього взяти неможливо. Тіло файлу тут доступне — `collectJSSecrets` його
	// отримує.
	//
	// Дешево: прохід один, регулярки лише ті, чий текст містить « будь-які символи
	// між » (`.*` або `.{`), і кожен збіг одразу йде через `appendFinding`,
	// тож фільтр плейсхолдерів і згортання діють так само, як для літералів.
	// Правила, які вже дали знахідку через літерал. Тіло для них повторно не
	// читається: інакше те саме значення приходило б двічі — з рядка літерала і
	// з рядка тіла, — а згортання за ключем ховало б різницю.
	for _, rule := range secretRulesInPriorityOrder() {
		for _, match := range rule.pattern.FindAllStringSubmatch(string(body), -1) {
			value := ""
			if len(match) > secretValueGroup(rule) {
				value = match[secretValueGroup(rule)]
			}
			appendFinding(rule.id, rule.id, rule.severity, value)
		}
	}

	// Один секрет — один рядок, і рядок несе ім'я, яким його назвав сам проєкт.
	//
	// Згортання виконується після збору, а не під час: матчери приходять двома
	// родинами (літеральні та присвоювальні), і пріоритет між ними не
	// гарантований. Перехоплення всередині `appendFinding` знецінювало правило,
	// яке мало виграти — саме це показав тест на `stripe_secret_key`, якого
	// перехопило правило вендора на тому самому значенні.
	//
	// Порядок задається явно: наші правила перед правилами вендора, далі за
	// іменем, тож результат не залежить від того, у якому порядку дерево
	// обійшов вузли.
	//
	// Згортання торкається **лише** пари «правило вендора ↔ наше правило» на
	// однаковому значенні. Згортання за будь-яким значенням було б ширшим за
	// завдання порту й ламало власні правила проєкту: `google_api_key` і
	// `generic_api_key_assignment` впізнають той самий рядок, і прибрати один
	// із них означало б змінити контракт, який існував до перенесення.
	vendorDuplicate := make(map[string]bool, len(findings))
	for _, finding := range findings {
		if strings.HasPrefix(finding.Rule, "pinkerton_") {
			continue
		}
		vendorDuplicate[finding.Value] = true
	}
	if len(vendorDuplicate) > 0 {
		kept := findings[:0]
		for _, finding := range findings {
			if strings.HasPrefix(finding.Rule, "pinkerton_") && vendorDuplicate[finding.Value] {
				continue
			}
			kept = append(kept, finding)
		}
		findings = kept
	}

	sort.Slice(findings, func(left, right int) bool {
		if findings[left].Rule != findings[right].Rule {
			return findings[left].Rule < findings[right].Rule
		}
		if findings[left].Fingerprint != findings[right].Fingerprint {
			return findings[left].Fingerprint < findings[right].Fingerprint
		}
		return findings[left].Kind < findings[right].Kind
	})
	return findings
}

// jsRuleByID finds this project's own rule by the id a matcher reported, so a
// match made by `jsRuleMatchers` is named like the text scan names it.
func jsRuleByID(id string) (secretRule, bool) {
	for _, rule := range secretRules {
		if rule.id == id {
			return rule, true
		}
	}
	return secretRule{}, false
}

// jsSecretValue reads one key out of a matcher's data.
//
// jsluice types `Data` as `any` and the built-in matchers put a
// `map[string]string` there, but a matcher that finds nothing to report can put
// a different shape in it. Reading through this one function means a shape
// change is a skip of one match rather than a panic that takes the crawl with
// it, which is the same reason the caller recovers.
func jsSecretValue(data any, key string) string {
	switch typed := data.(type) {
	case map[string]string:
		return typed[key]
	case map[string]any:
		if value, ok := typed[key].(string); ok {
			return value
		}
	}
	return ""
}

// jsAssignmentShape is one way a JavaScript program writes `name = "value"`.
//
// The node names differ, the answer does not, and keeping the three apart as
// data rather than as three copies of the matcher is what makes it obvious that
// a fourth shape is missing when one is.
type jsAssignmentShape struct {
	query  string
	fields func(*jsluice.Node) (name, value *jsluice.Node)
}

// jsAssignmentShapes are the three shapes the tree can answer for a hardcoded
// credential: an object property, a variable declarator and a plain assignment.
var jsAssignmentShapes = []jsAssignmentShape{
	{
		query: "(pair) @rrjsruleassign",
		fields: func(node *jsluice.Node) (*jsluice.Node, *jsluice.Node) {
			return node.ChildByFieldName("key"), node.ChildByFieldName("value")
		},
	},
	{
		query: "(variable_declarator) @rrjsruleassign",
		fields: func(node *jsluice.Node) (*jsluice.Node, *jsluice.Node) {
			return node.ChildByFieldName("name"), node.ChildByFieldName("value")
		},
	},
	{
		query: "(assignment_expression) @rrjsruleassign",
		fields: func(node *jsluice.Node) (*jsluice.Node, *jsluice.Node) {
			return node.ChildByFieldName("left"), node.ChildByFieldName("right")
		},
	},
}

// jsRuleMatchers runs this project's `secretRules` against the parse tree.
//
// Only the rules jsluice does not already implement are listed here. AWS access
// key ids, Google API keys and GitHub tokens are in `jsSecretKinds` because
// jsluice recognises them structurally, and listing them again would report one
// leaked key twice under two matcher names.
//
// The vendor formats match string literals, because a key is a value. An
// assignment cannot: it needs the variable's *name*, which lives on the pair
// node, so it gets its own query. That split is the structural gain over the
// text scan — `apiKey: "..."` is found by reading the object, not by hoping the
// name and the value are adjacent on one line of minified source.
//
// Which rules are assignment-shaped is read from `secretValueGroup` rather than
// from a rule id. Naming the id here left a second place to forget to update
// when a rule was added: the new rule would have matched nothing in the tree and
// nothing would have said so.
func jsRuleMatchers() []jsluice.SecretMatcher {
	literalRules := make([]secretRule, 0, len(secretRules))
	var pairRules []secretRule
	for _, rule := range secretRulesInPriorityOrder() {
		if jsBuiltInSecretRule(rule.id) {
			continue
		}
		if secretValueGroup(rule) == secretAssignmentValueGroup {
			pairRules = append(pairRules, rule)
			continue
		}
		literalRules = append(literalRules, rule)
	}
	matchers := make([]jsluice.SecretMatcher, 0, len(secretRules))
	// One query string for every literal rule: `GetSecrets` caches by query, so
	// the tree is walked once no matter how many rules read it.
	for _, rule := range literalRules {
		rule := rule
		matchers = append(matchers, jsluice.SecretMatcher{
			Query: "(string) @rrjsrule",
			Fn: func(node *jsluice.Node) *jsluice.Secret {
				value, ok := jsRuleValue(rule, node.RawString())
				if !ok {
					return nil
				}
				return &jsluice.Secret{
					Kind:     rule.id,
					Severity: jsluice.SeverityMedium,
					Data:     map[string]string{"key": value},
				}
			},
		})
	}
	for _, rule := range pairRules {
		rule := rule
		// Three shapes, one rule. An object property is one way a JavaScript
		// program hardcodes a credential, but it is not the way programs
		// usually write one: `const password = "…"` is a variable declarator and
		// `window.pwd = "…"` is an assignment, and a pair-only query saw neither.
		// That was measured, not assumed — the first version of this port matched
		// `{password: "…"}` and reported nothing for the form every bundle
		// actually uses.
		for _, shape := range jsAssignmentShapes {
			shape := shape
			matchers = append(matchers, jsluice.SecretMatcher{
				Query: shape.query,
				Fn: func(node *jsluice.Node) *jsluice.Secret {
					name, assigned := shape.fields(node)
					if name == nil || assigned == nil || !assigned.IsStringy() {
						return nil
					}
					// The rule matches "name = value" itself, so the value is read
					// off the assignment rather than off the bare literal, where a
					// 24-character string of any kind would match.
					//
					// The value arrives as `Content()` and not as `RawString()`,
					// so its quotes are still there. A rule may demand a quoted
					// value — `hardcoded_password` does, because that is what keeps
					// `password: isDisabled` out of the findings — and `RawString`
					// strips exactly the characters such a rule is written
					// against, which would make the tree path and the text path
					// answer differently for one rule on one file.
					value, ok := jsRuleValue(rule, name.RawString()+": "+assigned.Content())
					if !ok {
						return nil
					}
					return &jsluice.Secret{
						Kind:     rule.id,
						Severity: jsluice.SeverityMedium,
						Data:     map[string]string{"key": value},
					}
				},
			})
		}
	}
	return matchers
}

// jsBuiltInSecretRule reports whether jsluice's own matchers already cover a
// rule id, so the same key is not reported by two matchers.
func jsBuiltInSecretRule(id string) bool {
	switch id {
	case "aws_access_key_id", "google_api_key", "github_token":
		return true
	default:
		return false
	}
}

// jsRuleValue applies one rule to one piece of text and returns the captured
// value, or reports that the rule did not match. The group comes from
// `secretValueGroup`, which is the one place that knows which capture holds the
// value for each rule shape.
func jsRuleValue(rule secretRule, text string) (string, bool) {
	group := secretValueGroup(rule)
	// The rule must match the whole name, not the tail of it.
	//
	// Measured on a live target: the vk.com loader carries a code-splitting map
	// whose key is `entry\/web\/login` and whose value is a sixteen-character
	// hex module id. The pattern is unanchored, so it matched the `login:` at the
	// end of that key and reported `9ab740b017dee983` as a hardcoded username —
	// an accusation about a third party's account, made out of a build artefact.
	//
	// The text scan cannot anchor: there the pattern has to find the assignment
	// somewhere in a whole file, and `const apiKey = "…"` puts it after code.
	// Here the text is synthesised from exactly one pair, so requiring the match
	// to start at the first byte is not a restriction but the definition of the
	// name.
	if rule.valueGroup == secretAssignmentValueGroup {
		located := rule.pattern.FindStringSubmatchIndex(text)
		if len(located) < 2 || located[0] != 0 {
			return "", false
		}
	}
	match := rule.pattern.FindStringSubmatch(text)
	if len(match) <= group {
		return "", false
	}
	value := match[group]
	if value == "" {
		return "", false
	}
	return value, true
}

// analyzeJavaScriptPanicking is a seam that exists so the recover in
// `analyzeJavaScript` can be tested.
//
// A guard that can only be exercised by finding an input which makes tree-sitter
// panic is a guard that is never exercised: the test would need a fuzzer and a
// corpus, and the failure would arrive in production instead. The seam is an
// empty function that the crawl never replaces, and the test replaces it to drive
// the real function into its own recover. It is declared here rather than in the
// test file because the shipped code calls it, and a test file is not part of
// `go build`.
var analyzeJavaScriptPanicking = func() {}

// analyzeJavaScript reads one JavaScript resource and reports what it names.
//
// pageURL is the URL the bytes came from, and it is the base the references are
// resolved against. The crawl resolves everything against the URL it started
// from, which is wrong for a reference written relative to the file that
// contains it: `api/v1/users.json` in `/assets/app.js` is `/assets/api/v1/users.json`,
// not `/api/v1/users.json`. For JavaScript the correct base is known, so it is
// used.
func analyzeJavaScript(pageURL string, body []byte) (analysis jsAnalysis) {
	analysis.Bytes = len(body)
	// The three lists are initialised rather than left nil: a file that was
	// analysed and found nothing must serialise as three empty lists, because a
	// missing key and an empty result are different claims.
	analysis.Endpoints = []jsEndpoint{}
	analysis.Secrets = []jsSecret{}
	analysis.Findings = []jsFinding{}
	analysis.Variables = []jsVariable{}
	analysis.Routes = []jsRoute{}
	analysis.Params = []jsParamCandidate{}
	analysis.links = []string{}
	started := time.Now()
	defer func() {
		analysis.Millis = time.Since(started).Milliseconds()
		if recovered := recover(); recovered != nil {
			analysis.Error = fmt.Sprintf("javascript parser failed: %v", recovered)
			analysis.Endpoints = []jsEndpoint{}
			analysis.Secrets = []jsSecret{}
			analysis.Findings = []jsFinding{}
			analysis.Variables = []jsVariable{}
			analysis.Routes = []jsRoute{}
			analysis.Params = []jsParamCandidate{}
			analysis.links = []string{}
		}
	}()
	if len(body) == 0 {
		return analysis
	}
	// The seam exists so the recover below can be tested. It costs one call and
	// nothing else: the test replaces it, and nothing in the crawl does.
	analyzeJavaScriptPanicking()
	base, err := url.Parse(pageURL)
	if err != nil {
		// An unparsable base means relative references cannot be resolved, and
		// the absolute ones still can. Saying so on the page keeps the missing
		// links from being read as a file with nothing in it.
		base = &url.URL{Scheme: "https", Host: "invalid"}
		analysis.Error = fmt.Sprintf("page url %q is not parsable: %v", pageURL, err)
	}
	analyzer := jsluice.NewAnalyzer(body)
	analyzer.AddSecretMatchers(jsRuleMatchers())
	endpoints, links, deferred := mergeJSEndpoints(analyzer.GetURLs(), base)
	analysis.Endpoints = endpoints
	analysis.links = links
	analysis.LinksWithExpression = deferred
	analysis.Secrets = collectJSSecrets(analyzer.GetSecrets(), body)
	analysis.Variables = collectJSVariables(analyzer, body)
	// The same analyzer, the same parse: the DOM-write sinks, the comments and
	// the addresses are read off the tree that was already built, because a
	// second parse of a multi-megabyte bundle is the most expensive thing this
	// file could do twice.
	analysis.Findings = collectJSFindings(analyzer, body)
	// The capabilities pass reads the same parse tree: the routes a build
	// manifest names, the services that answer only from inside, the privileged
	// endpoints, the credentials bound to authentication-shaped names, the Vite
	// markers, and the parameter wordlist. `secrets` goes in so a credential the
	// pass above already reported is not reported again under a second name.
	capabilities := collectJSCapabilities(analyzer, body, base, endpoints, analysis.Variables, analysis.Secrets)
	analysis.Routes = capabilities.Routes
	analysis.Params = capabilities.Params
	analysis.ProbeWords, analysis.ProbeWordsTruncated = collectTargetSpecificWordlist(endpoints, capabilities.Params)
	analysis.Findings = mergeJSFindings(analysis.Findings, capabilities.Findings)
	// The manifest routes join the frontier. They are appended rather than
	// replacing it, because a build manifest and a call site are two independent
	// sources of references and either may name something the other missed.
	analysis.links = mergeJSLinkLists(analysis.links, capabilities.Links)
	// The library database is read once per file, on the bytes already in
	// memory: there is no second fetch, and no name is invented for the file.
	analysis.VulnerableLibraries = retirejsDetect(pageURL, retirejsFileName(pageURL), body)
	return analysis
}

// mergeJSLinkLists folds a second frontier into the first, sorted and without
// duplicates.
func mergeJSLinkLists(existing, extra []string) []string {
	if len(extra) == 0 {
		return existing
	}
	seen := make(map[string]bool, len(existing)+len(extra))
	merged := make([]string, 0, len(existing)+len(extra))
	for _, list := range [][]string{existing, extra} {
		for _, link := range list {
			if seen[link] {
				continue
			}
			seen[link] = true
			merged = append(merged, link)
		}
	}
	sort.Strings(merged)
	return merged
}
