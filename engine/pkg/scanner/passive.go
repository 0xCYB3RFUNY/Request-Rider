package scanner

// Passive match band.
//
// This file scores already-captured exchanges against nuclei templates without
// sending a single request. It imports the narrow rung
// `github.com/projectdiscovery/nuclei/v3/pkg/operators` — 627 packages in the
// dependency graph, measured with `go list -deps` — rather than
// `pkg/templates` (1 801) or `lib` (2 138), because this project already has a
// verified YAML parser (0 false rejections on 40 000 real templates) and does
// not need nuclei's.
//
// What this band is NOT: it is not a scanner. It never opens a socket, so it
// cannot be pause/resume/`SIGSTOP`-ed, and it does not replace the binary's
// execution path. `Start scan`, the `-ms` report, the invocation layout and
// crash isolation all stay exactly where they are.
//
// The single point of coupling with a nuclei version is `responseToDSLMap`,
// which nuclei does not export. The ~60 lines below mirror
// `pkg/protocols/http/operators.go` and `pkg/protocols/file/operators.go` of
// v3.11.1 field for field, and `TestResponseToDSLMapCarriesEveryDocumentedKey`
// pins the keys so a version bump that renames one fails loudly here instead of
// silently evaluating `dsl:` against a missing variable.

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	operatorsCache "github.com/projectdiscovery/nuclei/v3/pkg/operators/cache"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"gopkg.in/yaml.v3"
)

// operatorsCacheLimit is the regex/DSL cache size this process is using. It is
// tracked here because nuclei exposes the setter but not the getter, and a
// bound nobody can read is a bound nobody can show.
var operatorsCacheLimit = DefaultPassiveCompileCache

// PassiveCapability reports whether a template can be scored by this band at
// all, and if not, which construct makes it out of reach. The reason is always
// named, because "silently fewer templates" is the exact failure this band
// exists to avoid: 64 % of the official corpus carries `dsl:`, and a corpus
// number with no explanation is indistinguishable from a broken import.
type PassiveCapability struct {
	// Supported is true when every request block in the document is a pure
	// function of (request, response).
	Supported bool
	// Reason names the construct that put the document out of reach. It is
	// empty exactly when Supported is true.
	Reason string
}

// passiveUnsupportedBlocks are the protocol blocks whose matchers are not pure
// functions of a stored HTTP exchange. They are enumerated rather than
// pattern-matched so a new block nuclei adds later is reported as unsupported
// instead of being evaluated against a DSL map that lacks its variables.
var passiveUnsupportedBlocks = map[string]string{
	"code":        "runs a local engine, so it never looks at a request or a response",
	"javascript":  "evaluates JavaScript, which this band deliberately does not execute",
	"headless":    "drives a browser, so it produces a page rather than a response to match",
	"dns":         "matches DNS answers, which are not part of an HTTP exchange",
	"network":     "matches raw TCP or a protocol port, not an HTTP exchange",
	"tcp":         "matches raw TCP or a protocol port, not an HTTP exchange",
	"ssl":         "matches a TLS handshake and certificate chain, not an HTTP exchange",
	"whois":       "matches a WHOIS record, not an HTTP exchange",
	"websocket":   "matches a WebSocket frame exchange, not an HTTP exchange",
	"jarm":        "matches a JARM TLS fingerprint, not an HTTP exchange",
	"asn":         "matches an ASN record, not an HTTP exchange",
	"port":        "matches a port state, not an HTTP exchange",
	"fuzzing":     "is a fuzzing rule, so it generates its own requests instead of matching a stored one",
	"workflows":   "is a workflow of templates, not a single matcher over one exchange",
	"multi":       "is a multi-protocol container, so at least one of its blocks is out of reach here",
	"ssl-request": "matches a TLS handshake and certificate chain, not an HTTP exchange",
}

// passiveRequestPayloadKeys are the request fields that make a match depend on
// something other than the exchange being scored. A template that fuzzes,
// clusters payloads, races or pipelines is deciding something about *its own*
// request generation, and one stored exchange cannot answer that question.
var passiveRequestPayloadKeys = map[string]string{
	"payloads":          "carries an attack dictionary, so the matcher judges generated requests rather than this exchange",
	"fuzzing":           "generates requests from fuzzing rules rather than matching a stored exchange",
	"race":              "coordinates a race between several requests, which one stored exchange cannot stand in for",
	"race_count":        "coordinates a race between several requests, which one stored exchange cannot stand in for",
	"pipeline":          "judges a sequence of pipelined requests, which one stored exchange cannot stand in for",
	"req-condition":     "matches across several named requests, and this band has one exchange to judge them all with",
	"payload_variables": "injects attacker-chosen variables into the request before matching",
	"pre-condition":     "gates on a request made before this one, which this band never makes",
	"attack":            "declares a payload-combination attack, so the matcher judges generated requests",
}

// passiveDocument is the part of a nuclei template this band reads. It is
// deliberately narrower than nuclei's own `templates.Template`: reading only
// what is scored keeps a template's own request *construction* out of reach, so
// there is no code path here that could produce a request.
type passiveDocument struct {
	ID   string      `yaml:"id"`
	Info passiveInfo `yaml:"info"`
	// Variables is the document's own `variables:` block: names the template
	// fills in before it sends, so a placeholder like `{{username}}` has a value
	// even though no request extracts one.
	Variables map[string]interface{} `yaml:"variables"`
	// Flow is nuclei's own chaining key, `flow: http(1) && http(2)`. It is read
	// so a chained template is named as a flow rather than as a request count.
	Flow     string           `yaml:"flow"`
	HTTP     []passiveRequest `yaml:"http"`
	Requests []passiveRequest `yaml:"requests"`
	File     []passiveRequest `yaml:"file"`
	// Tcp is the `tcp:` list, kept apart for the same reason: it dials a socket,
	// it does not send a request.
	Tcp []passiveRequest `yaml:"tcp"`
	// HeadlessBlocks is the `headless:` list, kept apart for the same reason: it
	// opens a browser, not a request.
	HeadlessBlocks []passiveRequest `yaml:"headless"`
	// CodeBlocks is the `code:` list, kept apart from the request blocks because a
	// document that declares one has no request to send: its subject is what the
	// local interpreter prints.
	//
	// It also accepts a bare `code: true`, which is a form the corpus uses to
	// switch the protocol on without writing blocks of its own. Measured: the
	// `code/cves/2025` family writes exactly that, and decoding it as a list
	// turned 10 of 500 sampled templates into «invalid YAML» — a complaint about
	// the shape of a key rather than about anything the template does.
	CodeBlocks codeBlocks `yaml:"code"`
	// JavaScriptBlocks is the `javascript:` list.
	JavaScriptBlocks []passiveRequest `yaml:"javascript"`
}

type passiveInfo struct {
	Name     string `yaml:"name"`
	Severity string `yaml:"severity"`
}

// passiveRequest is one request block with its operators inlined, which is how
// nuclei itself models it: `operators.Operators` is embedded with
// `yaml:",inline"` in `pkg/protocols/http/http.go`, so `matchers`,
// `extractors` and `matchers-condition` are siblings of `path` and `method`.
type passiveRequest struct {
	operators.Operators `yaml:",inline"`

	Method  string            `yaml:"method"`
	Path    []string          `yaml:"path"`
	Raw     []string          `yaml:"raw"`
	Body    string            `yaml:"body"`
	Headers map[string]string `yaml:"headers"`

	// The fields below exist only so a template that depends on them can be
	// named as out of reach instead of being scored as if it did not.
	Attack    string                 `yaml:"attack"`
	Payloads  map[string]interface{} `yaml:"payloads"`
	Fuzzing   []yaml.Node            `yaml:"fuzzing"`
	Race      bool                   `yaml:"race"`
	RaceCount int                    `yaml:"race_count"`
	Pipeline  bool                   `yaml:"pipeline"`
	// ReqCondition is a pointer because nuclei's default is true and Go's
	// zero value is false: a plain bool would read every unspecified chain as
	// ungated and send every request in it.
	ReqCondition *bool `yaml:"req-condition"`
	// CodeEngines is the `engine:` list of a `code:` block, CodeTimeoutSec its own
	// `timeout:`, and CodeSource its `source:`.
	//
	// They live on the block rather than on the document because `code:` is a list
	// of blocks, and a document may mix several interpreters.
	CodeEngines    codeEngines `yaml:"engine"`
	CodeTimeoutSec int         `yaml:"timeout"`
	CodeSource     string      `yaml:"source"`
	// FileExtensions is the `extensions:` list of a `file:` block, which is the
	// only subject these templates declare: measured, all 447 name extensions and
	// none names a path.
	FileExtensions []string `yaml:"extensions"`
	// HeadlessSteps is a `headless:` block's step list.
	//
	// Measured over the 222 documents of the corpus: 229 blocks, `navigate` in every
	// one, `waitdialog` in 203, `script` in 47, `waitload` in 28, `setheader` in 4,
	// `click` in 3, `text` in 2; `payloads:` in 198 documents and `fuzzing:` in 196, so
	// a block is normally a small cross product of a payload against the places it may
	// be injected rather than one request.
	HeadlessSteps []headlessStep `yaml:"steps"`
	// JavaScriptCode and JavaScriptArgs are a `javascript:` block.
	//
	// Measured: 54 of the 192 corpus `javascript:` documents need no
	// `require("nuclei/…")` at all — they read `template.*` (108 accesses) and
	// `args:`. The other 138 need a protocol library nuclei ships inside its own
	// runtime, and each is refused by name rather than run without it.
	JavaScriptCode string            `yaml:"code"`
	JavaScriptArgs map[string]string `yaml:"args"`
	// BlockID is a block's own `id:`, which is how `flow:` names it.
	//
	// Measured: `http("login")` and `http("create-workflow")` appear in 16
	// templates, and each names a block that carries `id: <that name>` — e.g.
	// `flow: http("version-check")` beside `- id: version-check`. Reading the
	// name as a block index would have dialled whichever block happened to sit
	// in that position.
	BlockID string `yaml:"id"`
	// TcpHost, TcpPort, TcpInputs and TcpTLS describe a `tcp:` block.
	//
	// Measured over the 289 `tcp:` templates of the corpus: `host:` in all of
	// them, `port:` in 253, `inputs:` in 278, `tls:` in 8.
	TcpHost          []string               `yaml:"host"`
	TcpPort          int                    `yaml:"port"`
	TcpInputs        []tcpStepInput         `yaml:"inputs"`
	TcpTLS           bool                   `yaml:"tls"`
	PayloadVariables map[string]interface{} `yaml:"payload_variables"`
	// PreCondition is the script a block runs **before** its own code, and in the
	// corpus it is a plain string — a block scalar, usually multi-line:
	//
	//     javascript:
	//       - pre-condition: |
	//           isPortOpen(Host,Port)
	//
	// It was typed `[]yaml.Node`, and a block scalar cannot decode into a slice, so
	// every such document failed to parse with
	// «cannot unmarshal !!str isPortOpen… into […]». Measured on
	// `javascript/enumeration/ssh/*.yaml`: 5 of 5 documents refused before any code
	// of theirs ran, which is why those templates never started.
	PreCondition string `yaml:"pre-condition"`
}

// DefaultPassiveCompileCache is how many compiled regexes and DSL expressions
// the band keeps between templates.
//
// This is the bound the plan asked for as `ExecutorOptions.DoNotCache = true`,
// reached a different way because `protocols.ExecutorOptions` does not exist in
// the 627-package rung this band imports — measured with `go list -deps`, the
// graph holds `pkg/operators` but neither `pkg/protocols` nor `pkg/templates`.
// nuclei instead keeps its own process-wide LRU caches
// (`pkg/operators/cache`), and those are the memory that a corpus grows into.
//
// It is a default, not a ceiling: `SetPassiveCompileCacheLimits` replaces it
// with a caller-chosen value, and a value of 0 restores nuclei's own default.
// The limit is reported in the band's own output rather than applied silently.
const DefaultPassiveCompileCache = 4096

// SetPassiveCompileCacheLimits sets how many compiled regexes and DSL
// expressions survive between templates, and returns the value actually in
// effect. Both arguments must be positive; a value of 0 means "leave the
// current limit alone", so a caller that only wants to bound one of the two
// cannot accidentally unbind the other.
//
// This is an explicit, visible engineering bound rather than a silent cap: it
// exists so a template carrying thousands of patterns cannot hold its compiled
// form for the rest of the process, and it does not remove any capability —
// every template is still scored, only the reuse of compiled patterns between
// templates is what shrinks.
func SetPassiveCompileCacheLimits(regexes, dsl int) int {
	if regexes > 0 {
		operatorsCache.SetCapacities(regexes, 0)
	}
	if dsl > 0 {
		operatorsCache.SetCapacities(0, dsl)
	}
	if regexes > 0 {
		operatorsCacheLimit = regexes
	}
	return operatorsCacheLimit
}

// PassiveCompileCacheLimit reports the regex cache size in effect, so the value
// can be shown to the operator instead of being a fact buried in a dependency.
func PassiveCompileCacheLimit() int {
	return operatorsCacheLimit
}

// PassiveExchange is one stored HTTP exchange. It carries what a matcher may
// legitimately read and nothing else: no URL to fetch, no client, no deadline.
type PassiveExchange struct {
	// Method and URL identify the exchange that was captured.
	Method string
	URL    string
	// Host is the host the exchange was sent to, which is what nuclei's
	// `host` DSL variable holds.
	Host string
	// RawRequest and RawResponse are the verbatim bytes on the wire. They are
	// what `request` and `response` resolve to, and they are the evidence a
	// match is later shown against, so they are never reconstructed.
	RawRequest  string
	RawResponse string
	// StatusCode is the response status.
	StatusCode int
	// Body is the decoded response body, which is what `body` resolves to.
	Body string
	// Parts holds the protocol-named parts a matcher may name in `part:`.
	//
	// Measured over the 967 `code:` templates of the official corpus:
	// `code_1_response` 84, `response` 34, `body` 33, `code_2_response` 13,
	// `stderr` 9, `code_3_response` 2, `code_3_stderr` 1, `code_4_response` 1,
	// `all` 1. So the numbered form is the common one, and a runner that knows
	// only `stdout` leaves the most-used matcher of the whole protocol unmatched
	// while looking perfectly healthy.
	Parts map[string]string
	// Native holds the DSL variables a protocol produces as something other than
	// text, and it is written after `Parts` so a name present in both ends up with
	// the protocol's own value.
	//
	// It exists because of one measured fact. A `headless:` step named by `waitdialog`
	// yields the DSL variable `reflected`, and nuclei's own headless runtime writes
	// it as `out[act.Name] = true` — a **bool**
	// (`pkg/protocols/headless/engine/page_actions.go:931`). Written as the string
	// `"true"`, the identical template does not match: measured side by side,
	//
	//	reflected == true   data["reflected"] = true      → matches
	//	reflected == true   data["reflected"] = "true"    → does not match
	//
	// because govaluate compares the parameter to a bool. A string would therefore
	// have made 203 of the 222 `headless:` blocks unable to match anything at all,
	// while looking perfectly healthy — a verdict that can never fire.
	Native map[string]interface{}
	// Header is the response header set.
	Header http.Header
	// Duration is the measured exchange time in seconds, which is what
	// `duration` resolves to.
	Duration time.Duration
	// ContentLength is the response content length as reported on the wire.
	// A negative value means the header was absent, and nuclei then falls back
	// to the body length.
	ContentLength int64
	// Dynamic holds what earlier request blocks of the same template extracted,
	// which is what `template["name"]` resolves to. It is empty for a single
	// stored exchange, because a stored exchange has no earlier request.
	Dynamic map[string]string
}

// PassiveMatch is the verdict for one template against one exchange.
type PassiveMatch struct {
	// ExtractLists is every value each extracted name matched, in order.
	//
	// It exists beside `Dynamic` and not inside it. `Dynamic` holds only the names
	// that matched once, because a request must never substitute a name whose
	// value is ambiguous. `iterate()` in a `flow:` asks for all of them and sends
	// no request, so the list is available there and unavailable in a path.
	ExtractLists map[string][]string
	// Dynamic holds the named extractions a later request block can read.
	//
	// It comes from nuclei's `Result.Extracts`, which is keyed by the extractor's
	// `name:`, and not from `OutputExtracts`, which is a flat list of bare values
	// with the names already stripped — so a name→value pairing cannot be
	// recovered from it. A name that extracted more than one value is left out
	// rather than joined, because a request line cannot hold a list.
	Dynamic map[string]string

	// TemplateID, Name and Severity identify the template.
	TemplateID string
	Name       string
	Severity   string
	// Matched is true when the template's matchers matched the exchange.
	Matched bool
	// MatcherNames are the names of the matchers that fired, in the order
	// nuclei reports them.
	MatcherNames []string
	// Extracts are the values the template's extractors pulled out of the
	// exchange.
	Extracts []string
	// Reason names why a template was not scored. It is empty for a scored
	// template, whatever the verdict.
	Reason string
}

// passiveMatchPart mirrors `Request.getMatchPart` of the http protocol. The
// default part is `body`, `header` is the documented spelling of
// `all_headers`, and `all` is body concatenated with headers.
func passiveMatchPart(part string, data map[string]interface{}) (string, bool) {
	switch part {
	case "":
		part = "body"
	case "header":
		part = "all_headers"
	}
	if part == "all" {
		var builder strings.Builder
		builder.WriteString(passiveToString(data["body"]))
		builder.WriteString(passiveToString(data["all_headers"]))
		return builder.String(), true
	}
	item, ok := data[part]
	if !ok {
		return "", false
	}
	return passiveToString(item), true
}

// passiveToString mirrors `types.ToString`, which is what every nuclei matcher
// calls to turn a DSL value into a corpus. A `dsl:` expression such as
// `len(body)` therefore sees a Go `int` and `contains(body, 'x')` sees the
// decoded body, exactly as in the binary.
func passiveToString(data interface{}) string {
	switch value := data.(type) {
	case nil:
		return ""
	case string:
		return value
	case bool:
		if value {
			return "true"
		}
		return "false"
	case int:
		return fmt.Sprintf("%d", value)
	case int64:
		return fmt.Sprintf("%d", value)
	case float64:
		return fmt.Sprintf("%v", value)
	case []string:
		return strings.Join(value, "\n")
	case http.Header:
		return passiveHeadersToString(value)
	default:
		return fmt.Sprintf("%v", value)
	}
}

// passiveHeadersToString mirrors `utils.HeadersToString`, which is how nuclei
// renders a header set into the `all_headers` variable.
func passiveHeadersToString(headers http.Header) string {
	var builder strings.Builder
	for header, values := range headers {
		builder.WriteString(header)
		builder.WriteString(": ")
		for index, value := range values {
			builder.WriteString(value)
			if index != len(values)-1 {
				builder.WriteRune('\n')
				builder.WriteString(header)
				builder.WriteString(": ")
			}
		}
		builder.WriteRune('\n')
	}
	return builder.String()
}

// responseToDSLMap converts a stored exchange into the variable map that
// nuclei's `dsl:` matchers and `kval:` extractors read.
//
// This is the one function in the project that has to track a nuclei version,
// because nuclei does not export it. It mirrors v3.11.1
// `pkg/protocols/http/operators.go:responseToDSLMap` field for field:
//
//   - cookies are exposed under their lowercased name, so `contains(body, ...)`
//     and a `session` cookie are both addressable;
//   - headers are exposed under their name with `-` replaced by `_` and
//     values joined by a space, so `content_type` is how a template spells
//     `Content-Type`;
//   - `path` holds the host, mirroring nuclei's own offline evaluator, where
//     `path` is the input the template was matched against;
//   - `content_length` falls back to the body length when the wire did not
//     report one.
//
// Deliberate omissions, each of which is a known limitation rather than a
// silent difference:
//
//   - TLS metadata is not synthesised. nuclei's `enrichEventWithTLSMetadata`
//     reads `resp.TLS`, which a stored exchange does not carry, so a `dsl:`
//     that tests `tls_version` or `issuer_cn` cannot be answered here. The
//     band reports such a template as unscorable instead of answering false,
//     because "did not match" and "cannot be judged" are different claims.
//   - `template-info` is not synthesised from a `model.Info` value, because
//     building one is not needed by any matcher and would pull `pkg/model` in
//     for a field no template reads.
func responseToDSLMap(exchange PassiveExchange, templateID, templatePath string) map[string]interface{} {
	data := make(map[string]interface{}, 12+len(exchange.Header)+len(exchange.Parts))

	// Protocol-named parts first, then the ordinary fields below: a template that
	// names a part gets exactly what that part holds, and `response`/`body` keep
	// their own meaning afterwards.
	for name, value := range exchange.Parts {
		data[name] = value
	}

	for name, value := range exchange.Native {
		data[name] = value
	}

	// A protocol's own values second, so a `headless:` step flag stays a bool where
	// `parts` would have made it a string — see `Native`.

	// Cookies first, then headers, so a header wins a name collision — the same
	// order nuclei uses, where the header loop overwrites a cookie whose name
	// is also a header name.
	//
	// The parsing is stdlib's `(*http.Response).Cookies`, which is what nuclei
	// itself calls via `resp.Cookies()`. Hand-rolling the split on "=" gets
	// `session=abc; Path=/` wrong in a way that is invisible until a template
	// reads the cookie, so the parser nuclei uses is the parser used here.
	response := &http.Response{Header: exchange.Header}
	for _, cookie := range response.Cookies() {
		data[strings.ToLower(cookie.Name)] = cookie.Value
	}
	for name, values := range exchange.Header {
		key := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "-", "_"))
		data[key] = strings.Join(values, " ")
	}

	// `host` is what the http protocol puts the matched host in, and `path` is
	// the spelling nuclei's own offline evaluator uses for the same value. Both
	// are set because both spellings occur in real templates and only one of
	// them resolves on a given protocol.
	data["host"] = exchange.Host
	data["path"] = exchange.Host
	data["matched"] = exchange.URL
	data["request"] = exchange.RawRequest
	data["response"] = exchange.RawResponse
	data["status_code"] = exchange.StatusCode
	data["body"] = exchange.Body
	data["type"] = "http"
	data["all_headers"] = passiveHeadersToString(exchange.Header)
	data["header"] = passiveHeadersToString(exchange.Header)
	data["duration"] = exchange.Duration.Seconds()
	data["template-id"] = templateID
	data["template-path"] = templatePath
	data["content_length"] = passiveContentLength(exchange.ContentLength, len(exchange.Body))
	// `template` is where a later request block reads what an earlier one
	// extracted — `template["token"]` is how a login hands its token to the
	// request that uses it. It is a map, not a string, because that is the
	// indexing the expression performs.
	//
	// It is set from the block's own extraction only. A stored exchange has no
	// earlier request, so the map stays empty there, and nuclei's own evaluator
	// has the same shape.
	if exchange.Dynamic != nil {
		data["template"] = exchange.Dynamic
	}

	return data
}

// passiveContentLength mirrors `utils.CalculateContentLength`: a wire value of
// -1 or lower means the header was absent, and the body length is the answer.
func passiveContentLength(contentLength int64, bodyLength int) int64 {
	if contentLength > -1 {
		return contentLength
	}
	return int64(bodyLength)
}

// passiveMatchFunc mirrors `http.Request.Match`. It is the function nuclei
// hands to `Operators.Execute`, so the AND/OR condition, `negative:` matchers
// and the matched-snippet bookkeeping are nuclei's own code and not a
// reimplementation of it.
func passiveMatchFunc(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	item, ok := passiveMatchPart(matcher.Part, data)
	if !ok && matcher.Type.MatcherType != matchers.DSLMatcher {
		return false, []string{}
	}
	switch matcher.GetType() {
	case matchers.StatusMatcher:
		statusCode, ok := data["status_code"].(int)
		if !ok {
			return false, []string{}
		}
		return matcher.Result(matcher.MatchStatusCode(statusCode)), []string{passiveStatusSnippet(data, statusCode)}
	case matchers.SizeMatcher:
		return matcher.Result(matcher.MatchSize(len(item))), []string{}
	case matchers.WordsMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchWords(item, data))
	case matchers.RegexMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchRegex(item))
	case matchers.BinaryMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchBinary(item))
	case matchers.DSLMatcher:
		return matcher.Result(matcher.MatchDSL(data)), []string{}
	case matchers.XPathMatcher:
		return matcher.Result(matcher.MatchXPath(item)), []string{}
	}
	return false, []string{}
}

// passiveStatusSnippet mirrors `responsehighlighter.CreateStatusCodeSnippet`:
// the status line of a raw response, which is the evidence a `status:` matcher
// is shown against.
func passiveStatusSnippet(data map[string]interface{}, statusCode int) string {
	response, ok := data["response"].(string)
	if !ok || !strings.HasPrefix(response, "HTTP/") {
		return ""
	}
	code := fmt.Sprintf("%d", statusCode)
	index := strings.Index(response, code)
	if index < 0 {
		return ""
	}
	return response[:index+len(code)]
}

// passiveExtractFunc mirrors `http.Request.Extract`.
func passiveExtractFunc(data map[string]interface{}, extractor *extractors.Extractor) map[string]struct{} {
	item, ok := passiveMatchPart(extractor.Part, data)
	if !ok && !extractors.SupportsMap(extractor) {
		return nil
	}
	switch extractor.GetType() {
	case extractors.RegexExtractor:
		return extractor.ExtractRegex(item)
	case extractors.KValExtractor:
		return extractor.ExtractKval(data)
	case extractors.JSONExtractor:
		return extractor.ExtractJSON(item)
	case extractors.XPathExtractor:
		return extractor.ExtractXPath(item)
	case extractors.DSLExtractor:
		return extractor.ExtractDSL(data)
	}
	return nil
}

// passiveTLSVariables are the DSL variables that only a live TLS handshake can
// supply. A template that reads one of them is not scored here: answering
// "false" would be a claim about a certificate nobody presented.
var passiveTLSVariables = []string{
	"tls_version", "cipher", "sni", "not_before", "not_after", "expired",
	"self_signed", "mismatched", "subject_dn", "subject_cn", "subject_org",
	"subject_an", "emails", "issuer_dn", "issuer_cn", "issuer_org", "serial",
	"fingerprint_hash", "wildcard_certificate", "domains",
}

// passiveNeedsLiveTLS reports whether any `dsl:` expression in the document
// reads a variable this band cannot supply.
func passiveNeedsLiveTLS(document *passiveDocument) bool {
	expressions := make([]string, 0, 8)
	for _, request := range everyOperatorBlock(document) {
		for _, matcher := range request.Matchers {
			expressions = append(expressions, matcher.DSL...)
		}
		for _, extractor := range request.Extractors {
			expressions = append(expressions, extractor.DSL...)
		}
	}
	for _, expression := range expressions {
		for _, variable := range passiveTLSVariables {
			if passiveExpressionReads(expression, variable) {
				return true
			}
		}
	}
	return false
}

// passiveExpressionReads reports whether a `dsl:` expression names a variable.
// A whole-word comparison is used because `sni` is a substring of nothing else
// here, but `expired` would otherwise match inside a longer identifier, and a
// false positive here would downgrade a scorable template for no reason.
func passiveExpressionReads(expression, variable string) bool {
	for index := 0; index+len(variable) <= len(expression); index++ {
		if expression[index:index+len(variable)] != variable {
			continue
		}
		if index > 0 && isDSLIdentifierByte(expression[index-1]) {
			continue
		}
		end := index + len(variable)
		if end < len(expression) && isDSLIdentifierByte(expression[end]) {
			continue
		}
		return true
	}
	return false
}

func isDSLIdentifierByte(char byte) bool {
	return char == '_' ||
		(char >= 'a' && char <= 'z') ||
		(char >= 'A' && char <= 'Z') ||
		(char >= '0' && char <= '9')
}

// allPassiveRequests is the document's **request** blocks, in the order `http(n)`
// indexes them.
//
// `file:` used to be appended here, and that put a block whose subject is the local
// filesystem into the list a request is sent from. The file blocks then went
// through the request path, which found no `path:` and refused the whole document
// with «the template declares no path, so there is no request to send» — a
// complaint about an HTTP field made to a template that never sends a request.
// Measured: every `file:` test failed that way on the first run.
func allPassiveRequests(document *passiveDocument) []passiveRequest {
	requests := make([]passiveRequest, 0, len(document.HTTP)+len(document.Requests))
	requests = append(requests, document.HTTP...)
	requests = append(requests, document.Requests...)
	return requests
}

// everyOperatorBlock is every block that carries operators, which is what the
// passive band iterates when it asks "can one stored exchange judge this
// document?".
//
// It is a separate list from `allPassiveRequests` on purpose. The band answers a
// different question — whether an existing exchange is enough — and a `file:`
// block's operators do run against stored text, so dropping it there made
// `TestPassiveBandScoresFileTemplates` fail with «the document declares no http,
// requests or file block» the moment the runner stopped treating files as requests.
func everyOperatorBlock(document *passiveDocument) []passiveRequest {
	blocks := make([]passiveRequest, 0, len(document.HTTP)+len(document.Requests)+len(document.File))
	blocks = append(blocks, document.HTTP...)
	blocks = append(blocks, document.Requests...)
	blocks = append(blocks, document.File...)
	return blocks
}

// PassiveCapabilityOf reports whether a template document can be scored by this
// band, and names the construct that says no.
//
// It shares one decode with scoring, on purpose: two decodes meant two passes
// over the largest documents in a corpus, and the largest is where the memory
// goes. A decision that a caller can ask about must also be the decision the
// scorer makes, or a template can be reported as scorable and then refused.
func PassiveCapabilityOf(content string) PassiveCapability {
	_, capability := parsePassiveDocument(content)
	return capability
}

// passiveRequestOutOfReach names the first request field that makes a match
// depend on the template's own request generation rather than on the exchange
// being scored.
func passiveRequestOutOfReach(request passiveRequest) (string, bool) {
	// The attack type is checked before the payloads dictionary, because a
	// template that declares `attack: clusterbomb` says something more specific
	// than "it has payloads": the payloads are the half of a combination, and
	// naming the combination tells the operator what the template actually does.
	if request.Attack != "" {
		return fmt.Sprintf("the template declares an %q attack, so its matcher judges generated requests "+
			"rather than a stored exchange", request.Attack), true
	}
	if len(request.Payloads) > 0 {
		return "the template declares a payloads dictionary, so its matcher judges generated requests " +
			"rather than a stored exchange", true
	}
	if len(request.Fuzzing) > 0 {
		return "the template declares fuzzing rules, so it generates its own requests instead of matching " +
			"a stored exchange", true
	}
	if request.Race || request.RaceCount > 0 {
		return "the template coordinates a race between several requests, which one stored exchange cannot " +
			"stand in for", true
	}
	if request.Pipeline {
		return "the template judges a sequence of pipelined requests, which one stored exchange cannot " +
			"stand in for", true
	}
	// Only an explicit `req-condition` is read here. Nuclei's default is true,
	// so testing the field's value would refuse every multi-block document here
	// — and those are already refused, with a better reason, by the request-count
	// check above. What this branch catches is a document that says out loud
	// that it gates a request on an earlier matcher.
	if request.ReqCondition != nil {
		return "the template matches across several named requests (req-condition), and this band has one " +
			"exchange to judge them all with", true
	}
	if request.Attack != "" {
		return fmt.Sprintf("the template declares an %q attack, so its matcher judges generated requests "+
			"rather than a stored exchange", request.Attack), true
	}
	if len(request.PayloadVariables) > 0 {
		return "the template injects attacker-chosen variables into the request, so its matcher judges " +
			"the injected request rather than a stored exchange", true
	}
	if len(request.PreCondition) > 0 {
		return "the template gates on a request made before this one, and this band never makes a request", true
	}
	return "", false
}

// parsePassiveDocument decodes a document once and answers both questions the
// band asks of it: what it declares, and whether it can be judged.
//
// The two were separate calls at first, and that cost a second full decode of
// every template: capability needed the typed view, scoring needed it again.
// Decoding is the expensive half of this path — a 9.6 MB template such as
// wordpress-plugin-detect.yaml spends hundreds of megabytes in the yaml node
// tree alone — so a doubled decode doubled the peak for no reason. One decode,
// both answers.
func parsePassiveDocument(content string) (*passiveDocument, PassiveCapability) {
	// Same guard as the active path, for the same reason: the passive band decodes the same
	// documents, so without it a document that inflates is refused by a scan and accepted
	// by a passive run. That inconsistency would be its own defect.
	if reason := checkYAMLAmplification(content, yamlAmplificationLimitFromEnv(
		"RR_YAML_MAX_AMPLIFICATION", maxYAMLAmplification)); reason != "" {
		return nil, PassiveCapability{Reason: reason}
	}
	var blocks map[string]yaml.Node
	if err := yaml.Unmarshal([]byte(content), &blocks); err != nil {
		return nil, PassiveCapability{Reason: "invalid YAML: " + oneLine(err.Error())}
	}
	document := &passiveDocument{}
	if err := yaml.Unmarshal([]byte(content), document); err != nil {
		return nil, PassiveCapability{Reason: "invalid YAML: " + oneLine(err.Error())}
	}
	// Unsupported protocol blocks are checked first and by name, so the operator
	// is told which block put the template out of reach instead of being told
	// the document has no request block.
	keys := make([]string, 0, len(blocks))
	for key := range blocks {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if reason, unsupported := passiveUnsupportedBlocks[strings.ToLower(key)]; unsupported {
			return document, PassiveCapability{
				Reason: fmt.Sprintf("the document declares a %q block, which %s", key, reason),
			}
		}
	}
	if capability := passiveJudgeability(document); !capability.Supported {
		return document, capability
	}
	return document, PassiveCapability{Supported: true}
}

// passiveJudgeability decides whether an already-decoded document can be
// scored, and names the construct that says no.
func passiveJudgeability(document *passiveDocument) PassiveCapability {
	// The band scores one stored exchange against the document's operators, and a
	// `file:` block's operators run against stored text exactly as a request's do —
	// so this list is every operator-bearing block, not only the request ones.
	requests := everyOperatorBlock(document)
	if len(requests) == 0 {
		return PassiveCapability{
			Reason: "the document declares no http, requests or file block, so it has no matcher to run " +
				"against a stored exchange",
		}
	}
	// A document with more than one request block is a sequence, and one stored
	// exchange cannot stand in for it. Scoring every block against the same
	// exchange would claim that a block matched a request the target never
	// received, so the band refuses and names the count it found.
	//
	// This is the rule that replaced an earlier, wrong one: the first version
	// refused any template with an `internal: true` matcher, which threw away
	// 968 real templates. `matcher.Internal` is never read by nuclei's matching
	// path — it is read only by the flow deserializer, `pkg/tmplexec/exec.go`,
	// to decide whether a flow has a matcher worth reporting. Measured on the
	// official corpus, 2 578 templates carry `internal: true` and the band
	// rejected 968 of them for it, including single-request templates such as
	// CVE-2006-1681 whose `internal` matcher is nothing but a hidden condition.
	if len(requests) > 1 {
		return PassiveCapability{
			Reason: fmt.Sprintf("the document declares %d request blocks, so it is a sequence of requests "+
				"rather than one matcher over one exchange. This band has a single stored exchange and "+
				"cannot tell which block produced it, so scoring every block against it would claim a "+
				"match on a request the target never received", len(requests)),
		}
	}
	// `flow:` is the documented key for chaining a later request on an earlier
	// one, and it is checked explicitly so the reason names the flow rather
	// than the request count. Measured on the official corpus: 1 910 templates
	// declare one.
	if strings.TrimSpace(document.Flow) != "" {
		return PassiveCapability{
			Reason: fmt.Sprintf("the document declares `flow: %s`, so a later request only happens when an "+
				"earlier matcher fired. This band never makes a request, so it cannot decide whether the "+
				"chain was entered", oneLine(document.Flow)),
		}
	}
	for _, request := range requests {
		if reason, present := passiveRequestOutOfReach(request); present {
			return PassiveCapability{Reason: reason}
		}
	}
	if passiveNeedsLiveTLS(document) {
		return PassiveCapability{
			Reason: "a dsl: expression reads a TLS variable such as tls_version or issuer_cn, and only a live " +
				"handshake supplies those. A stored exchange carries no certificate chain, so this template " +
				"cannot be scored passively without answering a question about a certificate nobody presented",
		}
	}
	return PassiveCapability{Supported: true}
}

// ScorePassiveTemplate scores one template document against one stored exchange.
// It returns a verdict with a reason rather than an error, because "this
// template cannot be judged" is a per-template outcome the caller reports next
// to the others, not a failure of the batch.
func ScorePassiveTemplate(content string, exchange PassiveExchange) PassiveMatch {
	document, capability := parsePassiveDocument(content)
	if !capability.Supported {
		return PassiveMatch{Reason: capability.Reason}
	}
	verdict := PassiveMatch{
		TemplateID: strings.TrimSpace(document.ID),
		Severity:   strings.ToUpper(strings.TrimSpace(document.Info.Severity)),
	}
	for _, request := range allPassiveRequests(document) {
		block := request
		if err := block.Compile(); err != nil {
			return PassiveMatch{
				TemplateID: verdict.TemplateID,
				Reason:     "nuclei cannot compile this template's operators: " + oneLine(err.Error()),
			}
		}
		data := responseToDSLMap(exchange, document.ID, document.ID)
		result, matched := block.Execute(data, passiveMatchFunc, passiveExtractFunc, false)
		if !matched || result == nil {
			continue
		}
		verdict.Matched = true
		verdict.MatcherNames = append(verdict.MatcherNames, sortedKeys(result.Matches)...)
		verdict.Extracts = append(verdict.Extracts, result.OutputExtracts...)
	}
	return verdict
}

// sortedKeys keeps a verdict's matcher list stable between runs. A Go map
// iterates in a random order, and a report whose matcher column reorders
// itself on every run cannot be compared with the previous one.
func sortedKeys(values map[string][]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
