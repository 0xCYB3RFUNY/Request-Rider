package intruder

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Detection answers the question a brute force actually has to answer: the
// login form answered `200 OK` for the wrong password too, so the status code
// proves nothing. This file turns "the response is different" into an explicit
// verdict with named reasons, and it does so without pretending a difference is
// always a success.
//
// The shape of the problem is what forces the two-part design:
//
//   - Calibration. Before the run the engine replays the marked request with
//     every marker replaced by a generated value that cannot be a real
//     credential. Whatever the target answers is, by construction, a *failed*
//     login. Several samples are taken because a live login page embeds a
//     CSRF nonce, a timestamp and a request id, so one sample would make every
//     real response look different. The samples give a baseline: the status,
//     the length band, the set of body fingerprints, the redirect target and
//     the cookie names a failed login produces.
//
//   - Signals and rules. A signal says "this response deviates from the
//     baseline". A rule says "this response contains what a success looks
//     like". Both can mark a result, and both write down which one fired.
//
// Signals alone are not a verdict, and saying so is the honest part. A CMS
// that answers `200` distinguishes "unknown username" from "wrong password"
// with two different pages of two different lengths, so a run against it makes
// the baseline fire on *every* real username. That is exactly the case a rule
// exists for: `body_contains`, `header_contains`, `status_equals`,
// `body_not_contains`. When the operator has written rules they decide; when
// they have not, the baseline signals decide and the UI shows which fired.

// Signal names one way a response can deviate from the failed-login baseline.
// The set is fixed because the UI offers exactly these five toggles and the
// export reports them by name; an unknown name from a stored attack is dropped
// rather than treated as "everything", so a typo cannot silently widen a run.
const (
	SignalStatus   = "status"
	SignalRedirect = "redirect"
	SignalCookie   = "cookie"
	SignalLength   = "length"
	SignalBody     = "body"
)

// Rule types an operator can write against a response. Four is the whole set:
// a grep-style rule is what decides a case the baseline cannot, and every extra
// type is another validation path and another translation key.
const (
	RuleStatusEquals    = "status_equals"
	RuleBodyContains    = "body_contains"
	RuleBodyNotContains = "body_not_contains"
	RuleHeaderContains  = "header_contains"
)

// DefaultSignals is what a run compares until the operator chooses otherwise.
// Status, redirect and cookie are the cheap exact differences; length and body
// are the ones that survive a form that answers 200 for everything.
func DefaultSignals() []string {
	return []string{SignalStatus, SignalRedirect, SignalCookie, SignalLength, SignalBody}
}

// Rule is one operator-written condition. `Regex` is opt-in because a login
// page is full of characters that mean something to a regular expression, so
// literal matching has to stay the default and the operator has to say so.
type Rule struct {
	Type  string `json:"type"`
	Name  string `json:"name,omitempty"`
	Value string `json:"value"`
	Regex bool   `json:"regex,omitempty"`
}

// DetectionConfig is the per-run detection request. Zero value means disabled,
// which keeps every stored attack that predates the feature behaving exactly as
// it did before.
type DetectionConfig struct {
	Enabled     bool     `json:"enabled"`
	Signals     []string `json:"signals,omitempty"`
	Tolerance   int      `json:"tolerance,omitempty"`
	Calibration int      `json:"calibration_requests,omitempty"`
	Rules       []Rule   `json:"rules,omitempty"`
}

// DefaultCalibrationRequests is how many failed-login samples are taken when
// the field is empty. Three is the smallest number that survives a nonce and a
// rotating body without making every operator wait for a warm-up they cannot
// see. The field is visible and the operator may change it in either direction.
const DefaultCalibrationRequests = 3

// CalibrationRequests returns the sample count to use, clamped to something a
// login form can actually answer. A zero or negative field falls back to the
// documented default rather than silently disabling calibration, because a run
// with no baseline can only use rules and the operator would not know why.
func (c DetectionConfig) CalibrationRequests() int {
	if c.Calibration <= 0 {
		return DefaultCalibrationRequests
	}
	return c.Calibration
}

// Tolerance clamps a negative field to zero. A negative tolerance would widen
// the baseline band without any way to see the number, which is the hidden cap
// the project forbids in a different shape.
func (c DetectionConfig) ToleranceBytes() int {
	if c.Tolerance < 0 {
		return 0
	}
	return c.Tolerance
}

// UseSignals returns the enabled signal names, defaulting to DefaultSignals when
// the run did not name any. Unknown names are dropped; the returned slice never
// contains a value the evaluator does not know, so a stored attack cannot smuggle
// a wildcard in through the JSON field.
func (c DetectionConfig) UseSignals() []string {
	known := map[string]bool{}
	for _, name := range DefaultSignals() {
		known[name] = true
	}
	out := make([]string, 0, len(DefaultSignals()))
	for _, name := range c.Signals {
		if known[name] {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return DefaultSignals()
	}
	return out
}

// Sample is one response as the detector sees it: the parts that decide a login
// and nothing else. Raw body and headers stay out of it so a calibration sample
// cannot turn into a second copy of the target's page.
type Sample struct {
	Status      int
	Length      int
	Fingerprint string
	Location    string
	Cookies     []string
}

// Baseline is the failed-login reference built from one or more samples.
// `Status` and `Location` come from the first sample because they are exact;
// `MinLength`/`MaxLength` and the fingerprint set come from all of them, because
// a page that varies is the normal case and a single sample would report every
// real response as different.
type Baseline struct {
	Status       int      `json:"status"`
	MinLength    int      `json:"min_length"`
	MaxLength    int      `json:"max_length"`
	Lengths      []int    `json:"lengths"`
	Fingerprints []string `json:"fingerprints"`
	Location     string   `json:"location"`
	CookieNames  []string `json:"cookie_names"`
	Samples      int      `json:"samples"`
}

// CaptureBaseline turns the calibration responses into a baseline. An empty
// input still returns a usable zero value so a caller never has to nil-check
// before comparing, and `Samples` tells the operator that nothing was captured.
func CaptureBaseline(samples []Sample) Baseline {
	if len(samples) == 0 {
		return Baseline{}
	}
	baseline := Baseline{Status: samples[0].Status, Location: samples[0].Location}
	seenFingerprints := map[string]bool{}
	seenCookies := map[string]bool{}
	first := true
	for _, sample := range samples {
		baseline.Lengths = append(baseline.Lengths, sample.Length)
		if first {
			baseline.MinLength, baseline.MaxLength = sample.Length, sample.Length
			first = false
		} else {
			if sample.Length < baseline.MinLength {
				baseline.MinLength = sample.Length
			}
			if sample.Length > baseline.MaxLength {
				baseline.MaxLength = sample.Length
			}
		}
		if !seenFingerprints[sample.Fingerprint] {
			seenFingerprints[sample.Fingerprint] = true
			baseline.Fingerprints = append(baseline.Fingerprints, sample.Fingerprint)
		}
		// The union of every failed-login cookie, not just the first sample's.
		// A target may hand out its test cookie on the first form view and not
		// on the second, and the point of the baseline is "what a failed login
		// leaves behind", which is the union of what the samples left behind.
		for _, name := range sample.Cookies {
			if name != "" && !seenCookies[name] {
				seenCookies[name] = true
				baseline.CookieNames = append(baseline.CookieNames, name)
			}
		}
	}
	sort.Ints(baseline.Lengths)
	sort.Strings(baseline.Fingerprints)
	sort.Strings(baseline.CookieNames)
	baseline.Samples = len(samples)
	return baseline
}

// Verdict is the answer attached to one Intruder result. `Matched` is what the
// table shows; `Reasons` is why, so a match can be checked instead of trusted.
type Verdict struct {
	Matched bool     `json:"matched"`
	Signals []string `json:"signals,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
	Delta   int      `json:"delta,omitempty"`
}

// Evaluate compares one response with the baseline and applies the operator's
// rules. Rules decide when there are any: a form that answers 200 with a
// different page per failure reason produces baseline noise that only the
// operator's own condition can separate, so the run must not silently prefer the
// noisier of the two judgements. With no rules the signals decide and name
// themselves.
func Evaluate(config DetectionConfig, baseline Baseline, sample Sample, body string, headers map[string]string) Verdict {
	verdict := Verdict{}
	matchedSignals := baselineSignals(config, baseline, sample)
	matchedRules := matchRules(config.Rules, sample, body, headers)

	switch {
	case len(config.Rules) > 0:
		verdict.Matched = len(matchedRules) > 0
		verdict.Signals = matchedSignals
		verdict.Reasons = matchedRules
	case len(matchedSignals) > 0:
		verdict.Matched = true
		verdict.Signals = matchedSignals
		verdict.Reasons = append([]string(nil), matchedSignals...)
	}
	if baseline.Samples > 0 {
		verdict.Delta = sample.Length - baseline.MinLength
	}
	return verdict
}

// baselineSignals names every deviation the enabled signals can see. All of
// them are collected even when a rule already decided the row: the operator
// still wants to know the length moved.
func baselineSignals(config DetectionConfig, baseline Baseline, sample Sample) []string {
	if baseline.Samples == 0 {
		return nil
	}
	enabled := map[string]bool{}
	for _, name := range config.UseSignals() {
		enabled[name] = true
	}
	var signals []string
	if enabled[SignalStatus] && sample.Status != baseline.Status {
		signals = append(signals, SignalStatus)
	}
	if enabled[SignalRedirect] && sample.Location != baseline.Location && sample.Location != "" {
		signals = append(signals, SignalRedirect)
	}
	if enabled[SignalCookie] && hasNewCookie(baseline.CookieNames, sample.Cookies) {
		signals = append(signals, SignalCookie)
	}
	if enabled[SignalLength] {
		tolerance := config.ToleranceBytes()
		if sample.Length < baseline.MinLength-tolerance || sample.Length > baseline.MaxLength+tolerance {
			signals = append(signals, SignalLength)
		}
	}
	if enabled[SignalBody] && !containsString(baseline.Fingerprints, sample.Fingerprint) {
		signals = append(signals, SignalBody)
	}
	sort.Strings(signals)
	return signals
}

func hasNewCookie(known []string, received []string) bool {
	seen := map[string]bool{}
	for _, name := range known {
		seen[name] = true
	}
	for _, name := range received {
		if name != "" && !seen[name] {
			return true
		}
	}
	return false
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

// matchRules applies the operator's conditions and returns one reason per rule
// that fired, in the order the rules were written. An unparsable regular
// expression never matches and never aborts the run: a bad pattern is the
// operator's typo, and stopping a brute force because of it would destroy the
// evidence the run exists to produce.
func matchRules(rules []Rule, sample Sample, body string, headers map[string]string) []string {
	var reasons []string
	for _, rule := range rules {
		if ruleFires(rule, sample, body, headers) {
			reasons = append(reasons, ruleReason(rule))
		}
	}
	return reasons
}

func ruleFires(rule Rule, sample Sample, body string, headers map[string]string) bool {
	value := rule.Value
	switch rule.Type {
	case RuleStatusEquals:
		want, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return false
		}
		return sample.Status == want
	case RuleBodyContains:
		return valueMatches(value, rule.Regex, body)
	case RuleBodyNotContains:
		return !valueMatches(value, rule.Regex, body)
	case RuleHeaderContains:
		return valueMatches(value, rule.Regex, headerValue(headers, rule.Name))
	default:
		return false
	}
}

func ruleReason(rule Rule) string {
	if rule.Type == RuleHeaderContains && strings.TrimSpace(rule.Name) != "" {
		return fmt.Sprintf("%s %s: %s", rule.Type, rule.Name, rule.Value)
	}
	return fmt.Sprintf("%s: %s", rule.Type, rule.Value)
}

func headerValue(headers map[string]string, name string) string {
	if len(headers) == 0 {
		return ""
	}
	wanted := strings.ToLower(strings.TrimSpace(name))
	// Header names are case-insensitive and a target may send `Set-Cookie`
	// while the operator writes `set-cookie`, so the lookup folds both sides
	// instead of reporting a rule that silently never fires.
	for key, value := range headers {
		if strings.ToLower(key) == wanted {
			return value
		}
	}
	return ""
}

func valueMatches(needle string, useRegex bool, haystack string) bool {
	if needle == "" {
		return false
	}
	if !useRegex {
		return strings.Contains(haystack, needle)
	}
	pattern, err := regexp.Compile(needle)
	if err != nil {
		return false
	}
	return pattern.MatchString(haystack)
}

// payloadPlaceholder is what an injected value is replaced with before the body
// is measured. Its length is part of the measurement on both sides, which is
// what makes the comparison independent of how long the operator's payload
// happens to be.
const payloadPlaceholder = "§payload§"

// FingerprintBody reduces a response body to a signature that ignores what
// changes on every request and keeps what does not. Three classes are masked:
// the injected payload values themselves, every run of digits, and every long
// opaque token — which is what a CSRF nonce, a session id and an ETag are.
// Without this the body signal fires on the whole corpus, because no two
// responses of a live login page are byte-identical.
func FingerprintBody(body string, injected []string) string {
	digest := sha256.Sum256([]byte(normalizeBody(body, injected)))
	return hex.EncodeToString(digest[:8])
}

// NormalizedBodyLength measures the body with the same masking the fingerprint
// uses, and it exists because of a measured trap rather than a theoretical one.
//
// A login page usually echoes the submitted username back into its error text.
// Calibration submits a generated 32-character token, a real job submits the
// operator's payload, so the *failed* answers differ in length by the
// difference between those two strings — 27 bytes for "admin" against the
// calibration token — and the length signal fires on every row of the run.
// Measuring the masked body removes exactly that: both sides carry the same
// placeholder, so only a page that really is a different page is longer.
//
// The raw response size is deliberately not what gets compared. It stays in the
// result the operator already reads, which is the number worth reading; what the
// detector compares is the number that does not move with the dictionary.
func NormalizedBodyLength(body string, injected []string) int {
	return len(normalizeBody(body, injected))
}

func normalizeBody(body string, injected []string) string {
	normalized := body
	for _, value := range injected {
		if value == "" {
			continue
		}
		normalized = strings.ReplaceAll(normalized, value, payloadPlaceholder)
	}
	normalized = maskLongTokens(normalized)
	normalized = maskDigitRuns(normalized)
	return normalized
}

// tokenThreshold is the length at which a run of token characters is treated as
// an opaque value rather than as text.
const tokenThreshold = 16

// maskLongTokens replaces every long opaque token with a placeholder.
//
// The class is deliberately wider than hexadecimal, and the reason is measured
// rather than guessed. Masking only hex runs handled a WordPress nonce and
// nothing else: Django's `csrfmiddlewaretoken` is base64 and contains letters
// outside `[0-9a-f]`, so the mask cut it into a different skeleton on every
// render. Three calibration samples of the same Django admin page produced three
// different fingerprints, every response then differed from all three, and the
// body signal fired on the entire corpus — measured on a live target, not
// derived.
//
// Sixteen characters is the threshold because that is where prose stops and
// machine-generated values start. Masking a long token is the conservative
// direction: it hides a difference rather than inventing one.
func maskLongTokens(text string) string {
	var builder strings.Builder
	run := make([]rune, 0, 32)
	flush := func() {
		if len(run) >= tokenThreshold {
			builder.WriteString("#")
		} else {
			builder.WriteString(string(run))
		}
		run = run[:0]
	}
	for _, symbol := range text {
		if isTokenSymbol(symbol) {
			run = append(run, symbol)
			continue
		}
		flush()
		builder.WriteRune(symbol)
	}
	flush()
	return builder.String()
}

func isTokenSymbol(symbol rune) bool {
	return (symbol >= '0' && symbol <= '9') ||
		(symbol >= 'a' && symbol <= 'z') ||
		(symbol >= 'A' && symbol <= 'Z') ||
		symbol == '_' || symbol == '-' || symbol == '+' || symbol == '/' || symbol == '='
}

func maskDigitRuns(text string) string {
	var builder strings.Builder
	inDigits := false
	for _, symbol := range text {
		if symbol >= '0' && symbol <= '9' {
			inDigits = true
			continue
		}
		if inDigits {
			builder.WriteRune('#')
			inDigits = false
		}
		builder.WriteRune(symbol)
	}
	if inDigits {
		builder.WriteRune('#')
	}
	return builder.String()
}
