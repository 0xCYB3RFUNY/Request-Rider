// The enumeration corpus: 5522 checks that ask a server for paths it should not
// be answering for, and say what an answer would look like.
//
// # Why this exists
//
// The active scanner reasons about injections, headers and banners. It does not
// enumerate: it probes 21 paths, of which 8 appear in a corpus of 5550. That gap
// is not a tuning mistake, it is a whole detector class that was never built, and
// it is the largest single difference between this scanner and Nikto.
//
// The corpus was converted from Nikto's `program/databases/db_tests`. Upstream's COPYING restricts
// the database files to use with Nikto itself; the repository owner directed that
// the corpus be taken and reworked. That is recorded in the data file's own header
// and in DEVELOPMENT_LOG.md rather than left implicit, so the provenance of every
// row is answerable without archaeology.
//
// # What a row is
//
// A row is a request and a match, and nothing else. The corpus carries no
// description of a vulnerability class, no remediation text and no severity:
// those belong to the engine that produces the finding, not to a data file, and a
// corpus that carried its own copy of them would be a second, drifting copy.
//
// # Why the match kinds are a closed set
//
// `CODE`, `BODY` and `HEADER` are the only kinds the engine evaluates. The
// converter drops everything else rather than emitting a row the runner would
// skip, because a row that cannot run and a row that found nothing are
// indistinguishable in a report, and only one of them is true.

package scanner

import (
	"bufio"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// embeddedCorpus is the converted check corpus, compiled into the binary.
//
// It is embedded rather than read from disk because the engine is started from
// several working directories — the repository root, the container image, the test
// runner — and a data file that only resolves from one of them is a scanner that
// reports a clean site on the other two, because an unreadable corpus is an empty
// selection.
//
//go:embed nikto_corpus.tsv
var embeddedCorpus []byte

// Match kinds the engine evaluates.
const (
	// MatchCode is a status code: `CODE:200`.
	MatchCode = "CODE"
	// MatchBody is a regular expression over the response body.
	MatchBody = "BODY"
	// MatchHeader is a regular expression over a response header value.
	MatchHeader = "HEADER"
	// MatchAnd is a conjunction: `CODE:200&&BODY:not found` reads "answers 200 and
	// the body does not contain 'not found'".
	//
	// The body and header halves are negative. That is upstream's convention, not a
	// guess: in this database a positive alternative is written with `||`, so a
	// `&&` body half can only be a condition the response must fail. These checks
	// are how a soft 404 is told from a real document, and they are the largest
	// single class in the base — 684 rows, dropped wholesale by an earlier version
	// of the converter.
	MatchAnd = "AND"
)

// CorpusCheck is one executable check.
type CorpusCheck struct {
	// ID is the upstream check identifier, carried so a finding can be traced
	// back to the row it came from.
	ID string
	// Method is the HTTP method to send.
	Method string
	// Path is the absolute request path.
	Path string
	// Kind is one of MatchCode, MatchBody, MatchHeader.
	Kind string
	// Value is the match argument: a status code for MatchCode, a pattern
	// otherwise.
	Value string
	// Tags are upstream's tuning letters, which select which classes a run spends
	// requests on. Empty means the check has no class and always runs.
	Tags string
	// Description is upstream's one-line explanation of what the path is.
	Description string

	// pattern is Value compiled once at load. It is nil for MatchCode, which
	// compares an integer and needs no pattern.
	pattern *regexp.Regexp
	// patterns holds one compiled pattern per `&&` half, keyed by the half as it
	// was written. A conjunction needs several and they cannot share one field.
	patterns map[string]*regexp.Regexp
}

// Tags a check can carry, matching upstream's tuning letters.
//
// The letters are named rather than stringly typed because a run selects on them
// and a typo in a filter would silently select nothing — a scan that reports a
// clean site because the operator misspelled a category.
const (
	// TagInterestingFile is upstream's "interesting file / seen in logs".
	TagInterestingFile = "a"
	// TagMisconfiguration is upstream's "misconfiguration / default file".
	TagMisconfiguration = "b"
	// TagInformation is upstream's "information disclosure".
	TagInformation = "c"
	// TagRemoteFileInclusion is upstream's "remote file inclusion".
	TagRemoteFileInclusion = "d"
	// TagDenialOfService is upstream's "denial of service".
	TagDenialOfService = "e"
	// TagRetrievalOfInformation is upstream's "retrieval of information via
	// an external resource".
	TagRetrievalOfInformation = "f"
)

// CorpusTags is every tag a run can filter on, in upstream's own order.
var CorpusTags = []string{
	TagInformation,
	TagMisconfiguration,
	TagRemoteFileInclusion,
	TagDenialOfService,
	TagRetrievalOfInformation,
	TagInterestingFile,
}

// HasTag reports whether the check carries a tuning letter.
//
// A check with no tags runs under every filter. That is upstream's own default —
// a check it gave no class to is not something the operator chose to narrow away,
// and a filter that hid it would be a filter that silently changed what a scan
// means.
func (c CorpusCheck) HasTag(tag string) bool {
	if c.Tags == "" {
		return true
	}
	return strings.Contains(c.Tags, tag)
}

// Match evaluates the check against a response.
//
// It takes the status code, the body and the headers rather than a *http.Response
// so that a check can be evaluated against a response the engine read through
// its own recording transport, which is not the type this package would otherwise
// import for one field.
func (c CorpusCheck) Match(statusCode int, body string, header http.Header) bool {
	// A conjunction is the one shape whose body halves are negative, so the
	// "content only counts on success" guard below would invert it: `CODE:404&&
	// BODY:something` is a check about a refused response. Conjunctions are therefore
	// evaluated before this guard.
	if c.Kind == MatchAnd {
		return c.matchConjunction(statusCode, body, header)
	}

	// A body or header match is only evidence on a response that claims success.
	//
	// Measured: against a live site the very first corpus row raised a finding on a
	// 404 whose body was the site's own error template — the pattern matched the
	// page the server substitutes for every path that does not exist. Every real
	// server has such a page, so a body check without this rule matches it
	// eventually, and a finding that says "this path exists" because the error page
	// contains a word is worse than no finding.
	//
	// A status check is exempt: "this path answers 403" is a real observation about
	// a real path, and the operator decides what it means.
	if c.Kind != MatchCode && statusCode >= 400 {
		return false
	}

	switch c.Kind {
	case MatchCode:
		want, err := strconv.Atoi(strings.TrimSpace(c.Value))
		if err != nil {
			// A code check whose argument is not a number cannot be evaluated,
			// and the converter is what should have caught it. Reporting nothing
			// here would turn a data error into a clean result.
			return false
		}
		return statusCode == want
	case MatchBody:
		if c.pattern == nil {
			return false
		}
		return c.pattern.MatchString(body)
	case MatchHeader:
		if c.pattern == nil {
			return false
		}
		for _, values := range header {
			for _, value := range values {
				if c.pattern.MatchString(value) {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
}

// matchConjunction evaluates `A&&B`.
//
// The code half is the positive half; the body and header halves must **not**
// match. Treating them as positive would invert the meaning of every check in the
// class: `CODE:200&&BODY:not found` would then mean "200 and the body says not
// found", which is precisely the soft 404 the check exists to reject.
func (c CorpusCheck) matchConjunction(statusCode int, body string, header http.Header) bool {
	// `||` at the top level makes the whole expression one group of alternatives.
	if alternatives := splitDSL(c.Value, "||"); len(alternatives) > 1 {
		for _, alternative := range alternatives {
			if c.matchConjunctionText(strings.TrimSpace(alternative), statusCode, body, header) {
				return true
			}
		}
		return false
	}
	return c.matchConjunctionText(strings.TrimSpace(c.Value), statusCode, body, header)
}

// matchConjunctionText evaluates one conjunction: `A&&B&&!C`.
//
// The rules are upstream's, read from its parser rather than guessed at. Every
// half whose label carries no `!` must hold, and a half that does carry one must
// fail; a single unheld positive or held negative loses the whole check. A leading
// `!` negates the **half**, not its label: `BODY:x&&!CODE:404` is "the body matches
// x and the status is not 404".
//
// An earlier version of this assumed a body half inside a conjunction was always
// negative, reasoning from `CODE:200&&BODY:not found` alone. The database
// disproves that reading in 280 rows of `CODE:200&&BODY:alert\(8754\)&&!BODY:…`,
// where the plain body half is plainly what the check looks for, and the original
// source settles it: `parse_dsl` files a bare `BODY:x` under `body_pos` and only a
// `!`-prefixed one under `body_neg`. Every positive half must therefore match the
// body, which is the opposite of what the first version did for all 672 rows.
func (c CorpusCheck) matchConjunctionText(expression string, statusCode int, body string, header http.Header) bool {
	required := false

	for _, token := range splitDSL(expression, "&&") {
		token = strings.TrimSpace(token)
		token = strings.TrimSuffix(token, ",")
		if token == "" {
			continue
		}

		// `@LFI()` is a runtime payload, not a condition: upstream skips such tokens
		// outright (`parse_dsl`), so a check carrying one is not held back by it.
		if lfiCall.MatchString(token) {
			continue
		}

		// Patterns are recorded under the half **as written**, `!` included, because
		// that is the text the loader has and the only thing both agree on. Stripping
		// it first and looking the stripped text up misses the entry and silently
		// turns every negated half into an unevaluable one.
		negated := strings.HasPrefix(token, "!")
		kindToken := token
		if negated {
			token = strings.TrimSpace(strings.TrimPrefix(token, "!"))
		}

		// A parenthesised sub-expression is itself a group of alternatives.
		if strings.HasPrefix(token, "(") && !strings.HasPrefix(token, "(?") && strings.HasSuffix(token, ")") {
			matched := false
			for _, alternative := range splitDSL(token[1:len(token)-1], "||") {
				if c.matchConjunctionText(strings.TrimSpace(alternative), statusCode, body, header) {
					matched = true
					break
				}
			}
			if matched == negated {
				return false
			}
			required = true
			continue
		}

		kind, pattern, _ := strings.Cut(token, ":")
		kind = strings.ToUpper(strings.TrimSpace(kind))
		if kind == "HEADERS" {
			kind = MatchHeader
		}
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			return false
		}
		// A half whose value must be compared against a pattern but has none compiled
		// cannot be evaluated, and calling a nil *Regexp would panic the whole run
		// over one incomplete row. A bare `CODE:200` and a bare `HEADER:Server`
		// compare without one and are not asked for.
		switch kind {
		case MatchBody:
			if c.patterns[kindToken] == nil {
				return false
			}
		case MatchCode:
			if _, err := strconv.Atoi(pattern); err != nil {
				if _, err := regexp.Compile("^(?:" + pattern + ")$"); err != nil {
					return false
				}
			}
		case MatchHeader:
			if _, _, hasRegex := strings.Cut(pattern, ":"); hasRegex && c.patterns[kindToken] == nil {
				return false
			}
		default:
			return false
		}
		required = true

		switch kind {
		case MatchCode:
			// Upstream compares the status as a string against a regex, which is what
			// lets a row write `CODE:200|301`. An exact integer is the common case and
			// is answered first, without a regex.
			want, err := strconv.Atoi(pattern)
			if err == nil {
				if (statusCode == want) == negated {
					return false
				}
				continue
			}
			re := c.patterns[kindToken]
			if re == nil {
				compiled, err := regexp.Compile("^(?:" + pattern + ")$")
				if err != nil {
					return false
				}
				re = compiled
			}
			matched := re.MatchString(strconv.Itoa(statusCode))
			if matched == negated {
				return false
			}
		case MatchBody:
			if c.patterns[kindToken].MatchString(body) == negated {
				return false
			}
		case MatchHeader:
			// `HEADER:Name` requires the header to be present; `HEADER:Name:regex`
			// requires it and requires the value to match. Negated, the first form
			// requires the header to be absent and the second requires it to differ.
			name, want, hasRegex := strings.Cut(pattern, ":")
			name = strings.TrimSpace(name)
			values, present := header[name]
			if negated {
				if !present {
					continue
				}
				if !hasRegex {
					return false
				}
				want = strings.TrimSpace(want)
				for _, one := range values {
					if c.patterns[kindToken].MatchString(one) {
						return false
					}
				}
				continue
			}
			if !present {
				return false
			}
			if !hasRegex {
				continue
			}
			want = strings.TrimSpace(want)
			found := false
			for _, one := range values {
				if c.patterns[kindToken].MatchString(one) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		default:
			return false
		}
	}

	// Nothing was asked for, so nothing was proven.
	return required
}

// splitDSL splits on a top-level operator, leaving separators inside parentheses
// alone: `(?:of|for)` and `index of /` both contain characters the split must not
// trip over.
func splitDSL(text, operator string) []string {
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && strings.HasPrefix(text[i:], operator) {
			parts = append(parts, text[start:i])
			i += len(operator) - 1
			start = i + 1
		}
	}
	return append(parts, text[start:])
}

// lfiCall matches the runtime payload token upstream skips.
var lfiCall = regexp.MustCompile(`^@?LFI\(\)$`)

// LoadCorpus reads a converted corpus file.
//
// A pattern that does not compile is an error naming the check id, not a skipped
// row. The corpus is generated, so a broken pattern is a defect in the generator
// or in the source data, and both are worth seeing fail loudly at load time
// rather than as a scan that quietly found less.
func LoadCorpus(path string) ([]CorpusCheck, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("scanner: open corpus %s: %w", path, err)
	}
	defer file.Close()
	return ParseCorpus(file)
}

// ParseCorpus reads a converted corpus from a stream.
//
// It is separated from LoadCorpus so the embedded copy and a file on disk go
// through exactly one parser: a second reader would be a second definition of what
// a valid row is, and the two drift.
func ParseCorpus(source io.Reader) ([]CorpusCheck, error) {
	var checks []CorpusCheck
	scanner := bufio.NewScanner(source)
	// Upstream descriptions are single sentences, but a generated row can carry a
	// long one; the default 64 KiB line limit is raised rather than relied upon.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Split(text, "\t")
		if len(fields) < 6 {
			return nil, fmt.Errorf("scanner: corpus line %d: expected 6 tab-separated fields, got %d",
				line, len(fields))
		}

		check := CorpusCheck{
			ID:     fields[0],
			Method: fields[1],
			Path:   fields[2],
			Kind:   fields[3],
			Value:  fields[4],
			Tags:   fields[5],
		}
		if len(fields) > 6 {
			check.Description = fields[6]
		}

		switch check.Kind {
		case MatchAnd:
			check.patterns = map[string]*regexp.Regexp{}
			for _, part := range splitDSL(check.Value, "&&") {
				part = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(part), ","))
				if part == "" || lfiCall.MatchString(part) {
					continue
				}
				_, value, _ := strings.Cut(part, ":")
				value = strings.TrimSpace(value)
				if value == "" {
					return nil, fmt.Errorf("scanner: corpus line %d: check %s has an empty half in its conjunction %q",
						line, check.ID, check.Value)
				}
				pattern, err := regexp.Compile(value)
				if err != nil {
					return nil, fmt.Errorf("scanner: corpus line %d: check %s (%s) has an uncompilable half %q: %w",
						line, check.ID, check.Path, value, err)
				}
				check.patterns[part] = pattern
			}
		default:
			if check.Kind != MatchCode {
				pattern, err := regexp.Compile(check.Value)
				if err != nil {
					return nil, fmt.Errorf("scanner: corpus line %d: check %s (%s) has an uncompilable %s pattern: %w",
						line, check.ID, check.Path, check.Kind, err)
				}
				check.pattern = pattern
			}
		}

		switch check.Kind {
		case MatchCode, MatchBody, MatchHeader, MatchAnd:
		default:
			return nil, fmt.Errorf("scanner: corpus line %d: check %s has unknown match kind %q",
				line, check.ID, check.Kind)
		}

		checks = append(checks, check)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner: read corpus: %w", err)
	}
	if len(checks) == 0 {
		return nil, fmt.Errorf("scanner: the corpus carried no checks")
	}
	return checks, nil
}

// corpusOnce guards the embedded default so a package-level accessor does not
// re-parse five thousand patterns on every call in a run that checks thousands of
// paths.
//
// The cached value and its error are package-level on purpose. A `sync.Once` around
// a function-local variable parses once and then returns the zero value forever
// after, because the second call's `Do` does not run and its local is still nil —
// so the first caller gets the corpus and everyone after it gets none. That failure
// looks exactly like an empty corpus, which looks exactly like a clean site.
var (
	corpusOnce   sync.Once
	cachedCorpus []CorpusCheck
	cachedErr    error
)

// LoadDefaultCorpus returns the embedded corpus, parsed once per process.
//
// The copy is handed out as a fresh slice each call so a caller that filters in
// place cannot rewrite the shared one for every later caller — a filter that
// destructively narrows the corpus turns the second scan of a run into a scan of
// nothing, and reports it as a clean target.
func LoadDefaultCorpus() ([]CorpusCheck, error) {
	corpusOnce.Do(func() {
		cachedCorpus, cachedErr = ParseCorpus(strings.NewReader(string(embeddedCorpus)))
	})
	if cachedErr != nil {
		return nil, cachedErr
	}
	out := make([]CorpusCheck, len(cachedCorpus))
	copy(out, cachedCorpus)
	return out, nil
}

// FilterCorpus returns the checks a run should spend requests on.
//
// An empty filter returns everything. The result is a slice the caller owns, so
// a run that narrows mid-flight cannot be disturbed by a shared backing array.
func FilterCorpus(checks []CorpusCheck, tags []string) []CorpusCheck {
	if len(tags) == 0 {
		out := make([]CorpusCheck, len(checks))
		copy(out, checks)
		return out
	}
	out := make([]CorpusCheck, 0, len(checks))
	for _, check := range checks {
		for _, tag := range tags {
			if check.HasTag(tag) {
				out = append(out, check)
				break
			}
		}
	}
	return out
}

// CorpusRequest is one request and every check that reads its answer.
//
// # Why the corpus is grouped
//
// Several ids routinely probe the same path with different match expressions:
// `/` answers a banner check, a CMS check and a directory-listing check at once.
// Sending one request per id would triple the cost of the whole enumeration class
// to learn the same thing three times, so the runner groups by method and path
// and evaluates every check against the single response.
//
// The cost is visible rather than hidden: `CorpusStats.Selected` counts checks and
// `CorpusStats.UniquePaths` counts requests, and they are reported as separate
// numbers precisely because they are different units.
type CorpusRequest struct {
	// Method is the HTTP method to send.
	Method string
	// Path is the absolute request path.
	Path string
	// Checks are the checks this one response answers.
	Checks []CorpusCheck
}

// Key is the grouping key: the request identity of a row.
func (c CorpusCheck) Key() string { return c.Method + " " + c.Path }

// GroupCorpus collapses checks into the requests that answer them.
//
// Order follows first appearance, so a run's traffic is reproducible and the
// order an operator sees in a log matches the order the corpus lists.
func GroupCorpus(checks []CorpusCheck) []CorpusRequest {
	index := make(map[string]int, len(checks))
	grouped := make([]CorpusRequest, 0, len(checks))
	for _, check := range checks {
		key := check.Key()
		at, seen := index[key]
		if !seen {
			index[key] = len(grouped)
			grouped = append(grouped, CorpusRequest{Method: check.Method, Path: check.Path})
			at = len(grouped) - 1
		}
		grouped[at].Checks = append(grouped[at].Checks, check)
	}
	return grouped
}

// CorpusStats describes a corpus without running it, so an operator can see what
// a run is about to spend requests on before it spends them.
type CorpusStats struct {
	// Total is every check in the corpus.
	Total int `json:"total"`
	// Selected is what the current filter leaves.
	Selected int `json:"selected"`
	// ByTag counts the selected checks per tuning letter.
	ByTag map[string]int `json:"by_tag"`
	// UniquePaths is how many distinct request paths the selection probes. It is
	// smaller than Selected because several ids can probe one path with
	// different match expressions, and one request answers all of them.
	UniquePaths int `json:"unique_paths"`
}

// DescribeCorpus reports the shape of a selection.
func DescribeCorpus(selected []CorpusCheck) CorpusStats {
	stats := CorpusStats{
		Total:    len(selected),
		Selected: len(selected),
		ByTag:    map[string]int{},
	}
	paths := make(map[string]struct{}, len(selected))
	for _, check := range selected {
		paths[check.Method+" "+check.Path] = struct{}{}
		if check.Tags != "" {
			for _, tag := range check.Tags {
				stats.ByTag[string(tag)]++
			}
		}
	}
	stats.UniquePaths = len(paths)
	return stats
}
