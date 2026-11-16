// The detector contract and the primitives every detector shares.
//
// # The one thing this file exists to enforce
//
// A detector that looks for a string in a response body has to answer a
// question the string alone cannot: was that string there *because of* the
// injection, or was it already on the page? A page that lists usernames, shows
// a SQL error in its own help text, renders `/etc/passwd` in a documentation
// block, or contains the number 49 anywhere, matches the fingerprint of a
// vulnerability without being vulnerable to anything.
//
// The upstream implementation this descends from applies that check in some
// detectors and not others: SQLi, SSTI and CMDi compare against a baseline,
// LFI does not, and the XSS escalation looks for `onload=` or `<img` anywhere in
// the body — a signature that a real page contains routinely. A detector that
// skips the check is not a weaker detector, it is a different instrument, and
// the report cannot say which one produced a row.
//
// So the check is not available to detectors as an option. `Session` takes the
// baseline once per surface and hands it to every probe, and `Fresh` is the only
// way to accept a body fingerprint. A detector that wants to report a string it
// found in a response has to have checked where that string was not.
//
// # Why the baseline is fetched once and not per payload
//
// A surface with twelve probes would otherwise spend twelve extra requests
// re-reading a page the scanner already has. On a real target that is twelve
// more entries in the operator's access log, twelve more exchanges in their own
// History, and twelve more chances to be rate-limited by something that was
// working a moment ago. The baseline is a property of the surface, not of the
// payload.
package active

import (
	"context"
	"html"
	"net/url"
	"strings"
)

// Level selects how often a detector runs.
type Level int

const (
	// LevelParam runs once per injectable surface. Injection lives in a
	// parameter, so this is the level for anything that fires a payload.
	LevelParam Level = iota
	// LevelEndpoint runs once per unique URL with no parameter.
	LevelEndpoint
	// LevelHost runs once per host.
	LevelHost
)

// Module is one detector.
type Module interface {
	// Name is the stable identifier used in finding IDs and in the report.
	Name() string
	// Level selects how often the detector runs.
	Level() Level
	// Scan probes one surface and returns what it demonstrated.
	//
	// baseline is the surface's own unmodified response, or nil when the
	// request could not be made. A nil baseline is not permission to trust a
	// fingerprint: Fresh refuses in that case, because a detector that cannot
	// tell "already there" from "appeared" has nothing to report.
	Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding
}

// Session holds what a scan shares across every detector of one run.
type Session struct {
	// Transport issues the requests. It is the recording one, so every probe
	// lands in the operator's History with its full raw exchange.
	Transport *Transport
	// Target is the scan's root URL, used by the detectors that reason about
	// the origin rather than a single page.
	Target string
	// MarkerHost is the operator-controlled host used by out-of-band and
	// redirect probes. It is never resolved by the scanner — for a redirect
	// probe it only has to appear in a Location header — so a scan works
	// without one, and a detector that needs a callback to have arrived reports
	// nothing rather than guessing.
	MarkerHost string
	// Version is the version the target reported, and VersionSource names
	// where it came from. A finding whose existence depends on a version
	// carries them, so "the scanner saw it, the exploit did not fire" has a
	// concrete answer attached.
	Version       string
	VersionSource string
}

// Baseline returns the surface's unmodified response.
//
// It is the caller's job to take this once per surface and pass it down; this
// function exists so a detector that needs to refresh it — because an earlier
// probe may have changed the application's state — can, without inventing its
// own request.
func (s *Session) Baseline(ctx context.Context, p Point) *Response {
	resp, err := s.Transport.Baseline(ctx, p, false)
	if err != nil {
		return nil
	}
	return resp
}

// Fresh is the only way to accept a body fingerprint.
//
// It answers the question a substring match cannot: does the injected response
// contain the fingerprint, and did the unmodified surface not? A fingerprint
// that was already there is a property of the page, not evidence of an
// injection, and reporting it as one is how a scanner teaches an analyst to
// ignore it.
//
// A nil baseline returns false. The honest reading of "I could not read the
// original page" is "I cannot tell", and a detector that reports anyway is
// guessing with a severity attached.
func Fresh(baseline, injected *Response, fingerprint string) bool {
	if injected == nil || fingerprint == "" {
		return false
	}
	if !strings.Contains(injected.Body, fingerprint) {
		return false
	}
	if baseline == nil {
		return false
	}
	return !strings.Contains(baseline.Body, fingerprint)
}

// FreshFold is Fresh for a fingerprint whose case the target controls.
//
// A database does not promise a capital "You have an error in your SQL syntax";
// it promises the words, and different versions, locales and proxies capitalise
// them differently. A case-sensitive test against a lowercase pattern therefore
// misses the most common diagnostic in existence, which is worse than a false
// negative nobody notices — it is a scanner that reports SQL injection on almost
// nothing and looks like it works.
func FreshFold(baseline, injected *Response, fingerprint string) bool {
	if injected == nil || fingerprint == "" {
		return false
	}
	if !strings.Contains(strings.ToLower(injected.Body), strings.ToLower(fingerprint)) {
		return false
	}
	if baseline == nil {
		return false
	}
	return !strings.Contains(strings.ToLower(baseline.Body), strings.ToLower(fingerprint))
}

// Changed is Fresh for a whole-body difference rather than a substring.
//
// A boolean-differential detector compares two responses that both lack the
// fingerprint, so the question is whether the injection changed anything at
// all. It answers false when the baseline is missing, for the same reason Fresh
// does.
func Changed(baseline, injected *Response) bool {
	if baseline == nil || injected == nil {
		return false
	}
	return baseline.Body != injected.Body
}

// Match returns a compiled-once matcher for a detector's fingerprints.
//
// Every fingerprint in this package goes through it rather than through a
// package-level regexp, because a regexp built at init time is a regexp that
// cannot be read next to the code that uses it, and a pattern table is easier
// to review when it is written as a table in the detector that owns it.
type Match func(body string) string

// Literal builds a Match for a fixed string.
func Literal(needle string) Match {
	return func(body string) string {
		if strings.Contains(body, needle) {
			return needle
		}
		return ""
	}
}

// Snippet returns the body text surrounding a match, for evidence.
//
// Evidence is the excerpt, not a description of one. A triager reads this
// field to decide whether to believe the row, and "an error appeared" is not
// something they can check; the forty characters on either side of the match
// are.
func Snippet(body, match string, span int) string {
	if match == "" {
		return ""
	}
	index := strings.Index(body, match)
	if index < 0 {
		return match
	}
	start := index - span/2
	if start < 0 {
		start = 0
	}
	end := index + len(match) + span/2
	if end > len(body) {
		end = len(body)
	}
	return strings.TrimSpace(body[start:end])
}

// pageURL parses a URL the way a detector wants it: trimmed, and `nil` rather
// than an error, because every caller is asking "is this a URL at all?" and none
// of them wants to distinguish "unparseable" from "not a URL".
//
// It also fills the scheme in when it is missing. A detector that derives a
// candidate from a path — a backup file beside the one being served, a second
// page to re-read for a stored value — has to resolve that candidate against the
// surface it was derived from, and `(*url.URL).Parse` resolves a relative
// reference against a base with an empty scheme into something useless. The three
// callers are `BackupFiles`, `StoredClass` and the h2c half of `TLSCertificate`,
// and all three were written against this behaviour.
func pageURL(raw string) *url.URL {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil {
		return nil
	}
	if parsed.Scheme == "" && parsed.Host != "" {
		parsed.Scheme = "http"
	}
	return parsed
}

// stripEcho removes a submitted payload from a response body.
//
// It exists for the detectors that compare two responses which both echo what was
// sent. Stripping the echo is what makes such a comparison about the *result*:
// after removal, a page that only echoed is byte-identical and a page whose result
// set changed still differs.
//
// The multi-encoding pass is not optional. A reflecting page is entitled to emit
// the value back encoded, and the two common forms disagree with each other —
// `html.EscapeString` writes `"` as `&#34;` while a hand-written escaper writes
// `&quot;` — so stripping only the raw payload leaves the escaped copy behind and
// the comparison then measures the escaping rather than the result. That was found
// by mutation: with a single-variant strip the decoy control compared two *echoed*
// documents, they differed by three characters of escaped quotes, and the probe
// still reported an injection on a page that had evaluated nothing.
// confirmDivergence re-fires both arms of a differential probe and reports whether
// the difference reproduced.
//
// It exists because of a live run, and the reasoning is short. A differential
// detector fires payload A once, fires payload B once, and calls the difference
// signal. That is only sound if the target answers the same request the same way
// twice, and a live target under a burst of probes does not: a rate limiter, a
// captcha interstitial, a rotating banner or a cache that expires mid-run all
// produce a pair of answers that differ for reasons that have nothing to do with
// the payload. Against a real news site the NoSQL, LDAP and XPath detectors
// reported rows on endpoints that answer 165 bytes to everything — measured, not
// assumed — and every one of those rows was that noise.
//
// The confirmation costs two extra requests and only on a positive, so a target
// that really evaluates the expression pays it once per genuine row and a target
// that merely wobbled pays it to find out it did. Requiring the difference to
// appear twice in a row is what turns "these two answers differ" into "this
// payload changes the result".
//
// The floor is passed in rather than fixed so each technique keeps its own
// threshold; this function only answers whether the difference reproduced.
func confirmDivergence(ctx context.Context, t *Transport, p Point, a, b string, floor float64) bool {
	truth, err := t.Fire(ctx, p, p.Param, a, false, nil)
	if err != nil {
		return false
	}
	falsy, err := t.Fire(ctx, p, p.Param, b, false, nil)
	if err != nil {
		return false
	}
	truthBody := stripEcho(truth.Body, a)
	falsyBody := stripEcho(falsy.Body, b)
	if truthBody == falsyBody {
		return false
	}
	return Divergence(truthBody, falsyBody) >= floor
}

func stripEcho(body, payload string) string {
	for _, variant := range echoVariants(payload) {
		if variant == "" {
			continue
		}
		body = strings.ReplaceAll(body, variant, "")
	}
	return body
}

// echoVariants is the set of forms a page may render a payload in.
//
// `html.EscapeString` and a hand-rolled escaper disagree on the quote entities and
// agree on the rest, so both are produced here rather than choosing one and hoping.
//
// The percent-encoded forms were added after a live run, and they are the ones that
// mattered. A run against a real news site reported NoSQL, LDAP and XPath rows whose
// entire basis was that the probe answer and the decoy answer differed by about one
// character — the length of the submitted value. The site reflected the value into
// `href` and into a script variable, percent-encoded, so `stripEcho` matched nothing
// and the echo survived into the measurement. A fixture that reflected the raw value
// passed throughout: it exercised the stripping and never the gap, which is exactly
// what a green fixture cannot tell you.
//
// `QueryEscape` writes a space as `+` while `encodeURIComponent` writes `%20`, and a
// page is free to use either, so both are produced.
func echoVariants(payload string) []string {
	escaped := html.EscapeString(payload)
	query := url.QueryEscape(payload)
	return []string{
		payload,
		escaped,
		strings.NewReplacer(`"`, "&quot;", `'`, "&#39;").Replace(payload),
		strings.ReplaceAll(escaped, `&#34;`, "&quot;"),
		query,
		strings.ReplaceAll(query, "+", "%20"),
		url.PathEscape(payload),
	}
}

// Divergence measures how much of a document had to change, from 0 to 1.
//
// A differential detector asks one question: did the page's content change, and
// how much of it? Both common answers to that question are wrong in ways this
// function is written to avoid.
//
// Comparing bytes answers "yes, something changed" for a rotating banner, a
// request id or a timestamp, and a detector calibrated on that reports every
// dynamic page as an injection.
//
// Scoring 4-gram overlap answers it with the wrong weight. A set of distinct
// grams throws away repetition, so a page with twenty identical navigation
// links looks almost unchanged by a real difference; counting occurrences
// instead fixes that and introduces the opposite error, because the same
// twenty links now dominate the score and hide a difference elsewhere in the
// page. Real documents are mostly shared boilerplate, so whichever way the
// count is taken, the boilerplate wins.
//
// What the question actually needs is positional: find the text the two
// documents share at the front, the text they share at the back, and measure
// the gap between. Boilerplate at the end is found as the shared suffix and
// costs nothing, so the measure lands on the region that really differs. One
// word changed in a thousand is a small divergence, and the same word changed
// in a ten-word line is a large one, because the measure is relative to the
// document rather than to a set of shingles.
func Divergence(a, b string) float64 {
	longest := len(a)
	if len(b) > longest {
		longest = len(b)
	}
	if longest == 0 {
		return 0
	}
	if a == b {
		return 0
	}
	prefix := 0
	for prefix < len(a) && prefix < len(b) && a[prefix] == b[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(a)-prefix && suffix < len(b)-prefix &&
		a[len(a)-1-suffix] == b[len(b)-1-suffix] {
		suffix++
	}
	changed := len(a) + len(b) - 2*prefix - 2*suffix
	if changed <= 0 {
		return 0
	}
	return float64(changed) / float64(longest)
}
