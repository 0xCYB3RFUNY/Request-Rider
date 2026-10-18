package scanner

// The passive band is judged against nuclei itself, not against a description
// of nuclei. These tests pin three things:
//
//  1. the DSL map carries every key the plan names, so a version bump that
//     renames one fails here rather than silently evaluating `dsl:` against a
//     missing variable;
//  2. an exchange that nuclei would call a match is called a match here, and
//     one it would not call is not;
//  3. a template the band cannot judge is named, never silently passed over.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func passiveTestExchange() PassiveExchange {
	return PassiveExchange{
		Method:     "GET",
		URL:        "https://shop.example.com/admin/login",
		Host:       "https://shop.example.com",
		RawRequest: "GET /admin/login HTTP/1.1\r\nHost: shop.example.com\r\n\r\n",
		RawResponse: "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/html; charset=utf-8\r\n" +
			"Server: nginx/1.24.0\r\n" +
			"Set-Cookie: session=abc123; Path=/; HttpOnly\r\n" +
			"\r\n" +
			"<title>Admin Login</title><form action=\"/admin/login\" method=\"post\">",
		StatusCode: 200,
		Body:       "<title>Admin Login</title><form action=\"/admin/login\" method=\"post\">",
		// The header set is the response's own, and it has to carry Set-Cookie
		// for the cookie assertion below: the band parses cookies out of the
		// header the way nuclei does, not out of the raw response text.
		Header: http.Header{
			"Content-Type": {"text/html; charset=utf-8"},
			"Server":       {"nginx/1.24.0"},
			"Set-Cookie":   {"session=abc123; Path=/; HttpOnly"},
		},
		Duration:      1500 * time.Millisecond,
		ContentLength: 70,
	}
}

// TestResponseToDSLMapCarriesEveryDocumentedKey pins the exact key set the plan
// lists. The names are nuclei variable names, so this is the test that turns a
// nuclei version bump into a named failure instead of a silently different
// verdict: `dsl:` expressions reference these keys by string, and govaluate
// reports a missing key as "no result", not as an error.
func TestResponseToDSLMapCarriesEveryDocumentedKey(t *testing.T) {
	data := responseToDSLMap(passiveTestExchange(), "login-panel", "http/admin/login.yaml")

	for _, key := range []string{
		"status_code", "body", "all_headers", "header", "request", "response",
		"duration", "content_length", "host", "matched", "type", "template-id",
	} {
		if _, present := data[key]; !present {
			t.Errorf("DSL map is missing the %q key the plan pins; a dsl: matcher that reads it would "+
				"evaluate against nothing", key)
		}
	}
	// `host` is the documented alias of `path` in nuclei's own offline
	// evaluator, and the plan names it explicitly, so both spellings are
	// asserted rather than assumed.
	if data["host"] != "https://shop.example.com" {
		t.Errorf("host = %#v, want the exchange host", data["host"])
	}
	if data["path"] != data["host"] {
		t.Errorf("path = %#v, want it to mirror host the way nuclei's offline evaluator does", data["path"])
	}
	if data["status_code"] != 200 {
		t.Errorf("status_code = %#v, want the int 200 — a string here breaks `status_code == 200`", data["status_code"])
	}
	if data["type"] != "http" {
		t.Errorf("type = %#v, want \"http\"", data["type"])
	}
	if data["template-id"] != "login-panel" {
		t.Errorf("template-id = %#v, want the template id", data["template-id"])
	}
	if data["content_length"] != int64(70) {
		t.Errorf("content_length = %#v, want the int64 70", data["content_length"])
	}
	if data["duration"] != 1.5 {
		t.Errorf("duration = %#v, want 1.5 seconds", data["duration"])
	}
	// Headers reach the map the way nuclei spells them: lowercased, dashes
	// replaced by underscores, values joined by a space.
	if data["content_type"] != "text/html; charset=utf-8" {
		t.Errorf("content_type = %#v, want the Content-Type value under nuclei spelling", data["content_type"])
	}
	if data["server"] != "nginx/1.24.0" {
		t.Errorf("server = %#v, want the Server header value", data["server"])
	}
	// A cookie is addressable by its lowercased name, which is how nuclei
	// exposes it.
	if data["session"] != "abc123" {
		t.Errorf("session = %#v, want the Set-Cookie value", data["session"])
	}
}

// TestContentLengthFallsBackToTheBodyWhenTheWireIsSilent mirrors
// utils.CalculateContentLength: -1 means the header was absent, and the body
// length is then the answer. A DSL matcher testing `content_length > 0` would
// read a negative value as a truth about the exchange that is not true.
func TestContentLengthFallsBackToTheBodyWhenTheWireIsSilent(t *testing.T) {
	exchange := passiveTestExchange()
	exchange.ContentLength = -1
	data := responseToDSLMap(exchange, "t", "t")
	if data["content_length"] != int64(len(exchange.Body)) {
		t.Errorf("content_length = %#v, want the body length %d", data["content_length"], len(exchange.Body))
	}
}

// The templates below are scored against one exchange. Each asserts a verdict
// nuclei would reach, so the band is measured against the binary's semantics
// rather than against the band's own idea of them.

const passiveStatusTemplate = `
id: passive-status
info:
  name: Passive status match
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/login"
    matchers:
      - type: status
        status:
          - 200
`

const passiveDSLTemplate = `
id: passive-dsl
info:
  name: Passive DSL match
  author: test
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/login"
    matchers:
      - type: dsl
        dsl:
          - "status_code == 200 && contains(to_lower(body), 'admin login')"
`

const passiveWordHeaderTemplate = `
id: passive-header
info:
  name: Passive header word match
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/login"
    matchers:
      - type: word
        part: header
        words:
          - "nginx/1.24.0"
`

const passiveNegativeStatusTemplate = `
id: passive-negative
info:
  name: Passive negative status
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/login"
    matchers:
      - type: status
        status:
          - 404
        negative: true
`

const passiveAndConditionTemplate = `
id: passive-and
info:
  name: Passive AND condition
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/login"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "a-word-that-is-not-present"
`

const passiveExtractorTemplate = `
id: passive-extract
info:
  name: Passive extractor
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/login"
    matchers:
      - type: status
        status:
          - 200
    extractors:
      - type: regex
        name: form-action
        regex:
          - "action=\"([^\"]+)\""
        group: 1
`

func TestPassiveBandAgreesWithNucleiOnAMatch(t *testing.T) {
	for name, document := range map[string]string{
		"status":    passiveStatusTemplate,
		"dsl":       passiveDSLTemplate,
		"word":      passiveWordHeaderTemplate,
		"negative":  passiveNegativeStatusTemplate,
		"extractor": passiveExtractorTemplate,
	} {
		verdict := ScorePassiveTemplate(document, passiveTestExchange())
		if verdict.Reason != "" {
			t.Errorf("%s: template was not scored: %s", name, verdict.Reason)
			continue
		}
		if !verdict.Matched {
			t.Errorf("%s: no match, but nuclei matches this exchange", name)
		}
	}
}

func TestPassiveBandAgreesWithNucleiOnNoMatch(t *testing.T) {
	verdict := ScorePassiveTemplate(passiveAndConditionTemplate, passiveTestExchange())
	if verdict.Reason != "" {
		t.Fatalf("template was not scored: %s", verdict.Reason)
	}
	if verdict.Matched {
		t.Error("matched, but one of the two AND matchers is absent — nuclei reports this as no match")
	}
}

func TestPassiveExtractorsSurfaceTheirValues(t *testing.T) {
	verdict := ScorePassiveTemplate(passiveExtractorTemplate, passiveTestExchange())
	found := false
	for _, extract := range verdict.Extracts {
		if extract == "/admin/login" {
			found = true
		}
	}
	if !found {
		t.Errorf("extracts = %#v, want the form action pulled out of the body", verdict.Extracts)
	}
}

// A status matcher must not silently depend on the part it defaults to. nuclei
// resets an empty part to `body` for non-DSL matchers, and a template that
// pins `part: header` must read the headers. Getting this backwards turns every
// header matcher into a silent never-match.
func TestPartHeaderReadsHeadersAndDefaultsToBody(t *testing.T) {
	document := `
id: passive-parts
info:
  name: Passive parts
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        part: header
        words:
          - "nginx"
      - type: word
        words:
          - "Admin Login"
`
	verdict := ScorePassiveTemplate(document, passiveTestExchange())
	if !verdict.Matched {
		t.Error("no match: part: header did not read the headers, or the default part did not read the body")
	}
}

// The band must not judge a template whose matchers are not pure functions of
// the exchange. Each case names its own construct, because "the band skipped
// it" is not actionable and a silently unscored template is indistinguishable
// from a clean one.
func TestPassiveBandNamesEveryTemplateItCannotJudge(t *testing.T) {
	cases := map[string]struct {
		document string
		mentions string
	}{
		"code template": {
			document: "id: c\ninfo:\n  name: c\n  author: t\n  severity: info\ncode:\n  - engine:\n      sh: \"id\"\n",
			mentions: "code",
		},
		"dns template": {
			document: "id: d\ninfo:\n  name: d\n  author: t\n  severity: info\ndns:\n  - name: \"{{FQDN}}\"\n    matchers:\n      - type: word\n        words: [\"a\"]\n",
			mentions: "dns",
		},
		"network template": {
			document: "id: n\ninfo:\n  name: n\n  author: t\n  severity: info\nnetwork:\n  - host: \"{{Hostname}}\"\n",
			mentions: "network",
		},
		"ssl template": {
			document: "id: s\ninfo:\n  name: s\n  author: t\n  severity: info\nssl:\n  - host: \"{{Hostname}}\"\n",
			mentions: "ssl",
		},
		"javascript template": {
			document: "id: j\ninfo:\n  name: j\n  author: t\n  severity: info\njavascript:\n  - code: \"1\"\n",
			mentions: "javascript",
		},
		"headless template": {
			document: "id: h\ninfo:\n  name: h\n  author: t\n  severity: info\nheadless:\n  - steps:\n      - action: navigate\n",
			mentions: "headless",
		},
		"fuzzing template": {
			document: "id: f\ninfo:\n  name: f\n  author: t\n  severity: info\nfuzzing:\n  - type: replace\n    input: http://host/a\n",
			mentions: "fuzzing",
		},
		"payloads dictionary": {
			document: "id: p\ninfo:\n  name: p\n  author: t\n  severity: info\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/{{FUZZ}}\"]\n    payloads:\n      FUZZ: [a, b]\n    matchers:\n      - type: word\n        words: [\"x\"]\n",
			mentions: "payloads",
		},
		"race request": {
			document: "id: r\ninfo:\n  name: r\n  author: t\n  severity: info\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}\"]\n    race: true\n    matchers:\n      - type: word\n        words: [\"x\"]\n",
			mentions: "race",
		},
		"req-condition": {
			document: "id: rc\ninfo:\n  name: rc\n  author: t\n  severity: info\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}\"]\n    req-condition: true\n    matchers:\n      - type: word\n        words: [\"x\"]\n",
			mentions: "req-condition",
		},
		"attack type": {
			document: "id: at\ninfo:\n  name: at\n  author: t\n  severity: info\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/{{FUZZ}}\"]\n    attack: clusterbomb\n    payloads:\n      FUZZ: [a]\n    matchers:\n      - type: word\n        words: [\"x\"]\n",
			mentions: "clusterbomb",
		},
		"multi-request sequence": {
			document: "id: seq\ninfo:\n  name: seq\n  author: t\n  severity: info\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}\"]\n    matchers:\n      - type: word\n        words: [\"Cherokee\"]\n        internal: true\n  - method: GET\n    path: [\"{{BaseURL}}/x\"]\n    matchers:\n      - type: word\n        words: [\"y\"]\n",
			mentions: "2 request blocks",
		},
		"flow chain": {
			document: "id: fl\ninfo:\n  name: fl\n  author: t\n  severity: info\nflow: http(1) && http(2)\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}\"]\n    matchers:\n      - type: word\n        words: [\"x\"]\n",
			mentions: "flow",
		},
		"tls dsl": {
			document: "id: t\ninfo:\n  name: t\n  author: t\n  severity: info\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}\"]\n    matchers:\n      - type: dsl\n        dsl:\n          - \"tls_version == 'tls13'\"\n",
			mentions: "TLS",
		},
		"no request block": {
			document: "id: e\ninfo:\n  name: e\n  author: t\n  severity: info\n",
			mentions: "no http",
		},
		"broken yaml": {
			document: "id: [unclosed\n",
			mentions: "invalid YAML",
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			capability := PassiveCapabilityOf(testCase.document)
			if capability.Supported {
				t.Fatalf("reported as scorable, but this band cannot judge it: %s", testCase.document)
			}
			if capability.Reason == "" {
				t.Fatal("reported as unsupported with no reason, which is the one case an operator cannot act on")
			}
			if !strings.Contains(capability.Reason, testCase.mentions) {
				t.Errorf("reason = %q, want it to name %q", capability.Reason, testCase.mentions)
			}
			// The same refusal has to reach the verdict, or a caller that
			// scores many templates would see this one as clean.
			verdict := ScorePassiveTemplate(testCase.document, passiveTestExchange())
			if verdict.Reason == "" {
				t.Error("the verdict carries no reason, so this template would be reported as clean")
			}
			if verdict.Matched {
				t.Error("matched a template the band declared it cannot judge")
			}
		})
	}
}

// An `internal: true` matcher is an ordinary matcher, not a reason to refuse.
//
// This is a regression test for a rule that was wrong the first time it was
// written: the band refused every template carrying an internal matcher, which
// threw away 968 templates of the official corpus including single-request
// ones such as CVE-2006-1681, whose `internal` matcher is only a hidden
// condition. nuclei never reads `matcher.Internal` on the matching path — it is
// read only by the flow deserializer in `pkg/tmplexec/exec.go` — so refusing on
// it was refusing on a field that cannot change a verdict.
func TestAnInternalMatcherIsScoredRatherThanRefused(t *testing.T) {
	document := `
id: internal-matcher
info:
  name: Internal matcher
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/login"
    matchers:
      - type: word
        name: hidden
        internal: true
        words:
          - "Admin Login"
`
	capability := PassiveCapabilityOf(document)
	if !capability.Supported {
		t.Fatalf("refused a single-request template over an internal matcher: %s", capability.Reason)
	}
	verdict := ScorePassiveTemplate(document, passiveTestExchange())
	if !verdict.Matched {
		t.Error("no match: an internal matcher is still a matcher, and its word is in the stored body")
	}
}

// A template with no `dsl:` at all is still scored, because the band is not only
// a DSL evaluator — word, regex, status, size, binary and xpath matchers all
// run on a stored exchange, and they are the majority of the corpus.
func TestPassiveBandScoresTemplatesWithoutDSL(t *testing.T) {
	document := `
id: no-dsl
info:
  name: No DSL here
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/login"
    matchers:
      - type: regex
        regex:
          - "(?i)<title>admin login</title>"
      - type: size
        size:
          - 70
`
	if capability := PassiveCapabilityOf(document); !capability.Supported {
		t.Fatalf("a word/regex/size template is scorable: %s", capability.Reason)
	}
	if verdict := ScorePassiveTemplate(document, passiveTestExchange()); !verdict.Matched {
		t.Error("no match, but the regex is present in the body and the size is the body length")
	}
}

// A `file` template's matchers are pure functions of the file content, so the
// band scores them too. Its parts are spelled differently from http's, and
// getting that wrong makes every file matcher a silent never-match.
func TestPassiveBandScoresFileTemplates(t *testing.T) {
	document := `
id: file-template
info:
  name: File template
  author: test
  severity: info
file:
  - extensions:
      - all
    matchers:
      - type: word
        part: data
        words:
          - "secret"
`
	capability := PassiveCapabilityOf(document)
	if !capability.Supported {
		t.Fatalf("a file template with a word matcher is scorable: %s", capability.Reason)
	}
}

// TestTheBandSendsNothingToTheTarget is the acceptance criterion stated as a
// measurement rather than as a claim about the code.
//
// The band's whole premise is that it scores an exchange that already happened,
// so a request to the target would be a defect that no amount of reading the
// source would rule out. A real listener counts what reaches it, and the count
// has to stay at zero while a template that matches the *stored* exchange is
// scored successfully. A band that quietly fetched the target would report a
// match too, which is exactly why the counter is the assertion and the verdict
// alone is not.
func TestTheBandSendsNothingToTheTarget(t *testing.T) {
	var requests int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// The template names the live listener, and the stored exchange is a
	// different host entirely — so a fetch would be visible both as a request
	// to the server and as a verdict about a host that was never contacted.
	document := `
id: live-target
info:
  name: Live target
  author: test
  severity: info
http:
  - method: GET
    path:
      - "` + server.URL + `/admin/login"
    matchers:
      - type: word
        words:
          - "Admin Login"
`
	verdict := ScorePassiveTemplate(document, passiveTestExchange())
	if verdict.Reason != "" {
		t.Fatalf("template was not scored: %s", verdict.Reason)
	}
	if !verdict.Matched {
		t.Error("no match, but the stored exchange carries the word being matched")
	}
	if got := atomic.LoadInt64(&requests); got != 0 {
		t.Errorf("the band sent %d request(s) to the target; it is supposed to score stored exchanges "+
			"and issue no request at all", got)
	}
}

// The memory bound has to be real and it has to be readable, because the plan
// asked for it as `ExecutorOptions.DoNotCache` and that field does not exist in
// the 627-package rung this band imports. A bound nobody can read is a bound
// nobody can show the operator.
func TestTheCompileCacheLimitIsVisibleAndApplied(t *testing.T) {
	original := PassiveCompileCacheLimit()
	t.Cleanup(func() { SetPassiveCompileCacheLimits(original, original) })

	if original != DefaultPassiveCompileCache {
		t.Errorf("default cache limit = %d, want the documented %d", original, DefaultPassiveCompileCache)
	}
	if applied := SetPassiveCompileCacheLimits(64, 64); applied != 64 {
		t.Errorf("after setting 64, the reported limit is %d", applied)
	}
	if reported := PassiveCompileCacheLimit(); reported != 64 {
		t.Errorf("reported limit = %d, want the value that was set", reported)
	}
	// A template is still scored with the small cache, so the bound costs
	// compiled-pattern reuse and not capability.
	verdict := ScorePassiveTemplate(passiveWordHeaderTemplate, passiveTestExchange())
	if verdict.Reason != "" {
		t.Fatalf("a template stopped being scored once the cache was bounded: %s", verdict.Reason)
	}
	if !verdict.Matched {
		t.Error("no match under a bounded cache, so the bound changed the verdict rather than the reuse")
	}
	// A zero argument means "leave this one alone", so bounding only the regex
	// cache cannot silently unbind the DSL cache.
	SetPassiveCompileCacheLimits(32, 0)
	if reported := PassiveCompileCacheLimit(); reported != 32 {
		t.Errorf("reported limit = %d, want 32", reported)
	}
}

// The band must never claim it can judge something it cannot. The check is
// deliberately about a word-boundary comparison: `expired` is a prefix of
// nothing here, but a naive substring test would also fire on an identifier
// that merely contains it, downgrading a scorable template for no reason.
func TestTLSVariableDetectionUsesWordBoundaries(t *testing.T) {
	document := `
id: wordy
info:
  name: Word boundary
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"]
`
	_ = document
	if passiveExpressionReads("contains(body, 'expiration_date')", "expired") {
		t.Error("matched `expiration_date` as if it read the `expired` variable")
	}
	if !passiveExpressionReads("expired == true", "expired") {
		t.Error("did not read a bare `expired` reference")
	}
	if !passiveExpressionReads("not_after < now()", "not_after") {
		t.Error("did not read a `not_after` reference")
	}
}
