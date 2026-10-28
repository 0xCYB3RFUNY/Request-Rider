package enrich

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// SecretRule is one vendor detection rule.
//
// Port of the rule schema, not the code: `praetorian-inc/titus`
// (`pkg/types/rule.go`, upstream commit 510c4076c81c17d73f254bdadaeb5286b3ec7dc3)
// is Apache-2.0, so the rule bodies in `secrets_data.go` are carried over as
// written. What is ours is this shape and the four decisions a rule needs that
// the regex cannot express.
//
// The requirements are kept as data rather than folded into the pattern because
// upstream keeps them as data too, and folding them would make a rule that fails
// its requirement indistinguishable from a rule that never matched.
type SecretRule struct {
	// ID is upstream's own `np.<vendor>.<n>`. It is stable and it is what a
	// Titus user would search for, so it is the identifier that travels into
	// PostgreSQL and into every export.
	ID string
	// Name is the human label. It is never translated here: the report owns
	// language, and a translated provider name stops matching the vendor.
	Name string
	// Regex is the upstream pattern, compiled once.
	Regex *regexp.Regexp
	// Group is the 1-based capture group holding the secret itself.
	Group int
	// Score is upstream's `base_score`, 0..100.
	Score int
	// MinEntropy is bits per character the captured value must reach. Zero
	// disables the check, which is upstream's own convention.
	MinEntropy float64
	// Reject is a second expression applied to the captured value: a match that
	// satisfies Regex and also satisfies Reject is thrown away.
	//
	// It exists because Go's regexp is RE2 and RE2 has no lookahead, while the
	// upstream rules are Python and four of them exclude a value with a negative
	// lookahead. Rewriting those exclusions as RE2 is impossible — "not a
	// SNAKE_CASE constant" has no equivalent single expression — so the exclusion
	// is carried as data instead, which is checkable and testable where a
	// dropped lookahead would be neither. The four rules that need it are named
	// in the generator's RE2_REWRITES table with their reason.
	Reject *regexp.Regexp
	// RejectReason explains the exclusion in the report, so a rejected match is
	// a decision the analyst can read rather than a hole.
	RejectReason string

	// Requirement is the character-class and content constraint.
	Requirement CharacterRequirements
	// Noisy marks rules upstream disables by default. They are kept — a rule
	// the analyst asked for and did not get is a silent loss — but they are
	// excluded from the default pass and are counted separately, so "12 findings,
	// 9 of them noisy" is a different claim from "12 findings".
	Noisy bool
	// Categories are upstream's classification tags.
	Categories []string
}

// CharacterRequirements is the minimum shape a captured value must have.
type CharacterRequirements struct {
	MinDigits        int
	MinUpper         int
	MinLower         int
	MinSpecial       int
	SpecialChars     string
	IgnoreIfContains []string
}

// Satisfied reports whether value meets the requirement, and says which part it
// failed. Returning the reason is what lets the report say "matched, rejected:
// too few digits" instead of silently dropping a match the analyst expected.
func (r CharacterRequirements) Satisfied(value string) (bool, string) {
	if len(r.IgnoreIfContains) > 0 {
		lowered := strings.ToLower(value)
		for _, needle := range r.IgnoreIfContains {
			if needle != "" && strings.Contains(lowered, strings.ToLower(needle)) {
				return false, "value contains " + needle
			}
		}
	}
	var digits, upper, lower, special int
	for _, c := range value {
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'A' && c <= 'Z':
			upper++
		case c >= 'a' && c <= 'z':
			lower++
		default:
			if r.SpecialChars == "" || strings.ContainsRune(r.SpecialChars, c) {
				special++
			}
		}
	}
	if digits < r.MinDigits {
		return false, "needs at least " + itoa(r.MinDigits) + " digits, has " + itoa(digits)
	}
	if upper < r.MinUpper {
		return false, "needs at least " + itoa(r.MinUpper) + " uppercase, has " + itoa(upper)
	}
	if lower < r.MinLower {
		return false, "needs at least " + itoa(r.MinLower) + " lowercase, has " + itoa(lower)
	}
	if special < r.MinSpecial {
		return false, "needs at least " + itoa(r.MinSpecial) + " special characters, has " + itoa(special)
	}
	return true, ""
}

// SecretFinding is one accepted match.
//
// The value is carried whole. That is the owner's decision of 2026-09-30 for
// JavaScript secrets, and it is applied here for the same reason: a redacted
// finding cannot be used, and this is the analyst's own workspace. The
// fingerprint exists for the opposite case — naming the same secret twice
// without printing it twice.
type SecretFinding struct {
	Rule        string   `json:"rule"`
	Name        string   `json:"name"`
	Value       string   `json:"value"`
	Fingerprint string   `json:"fingerprint"`
	Score       int      `json:"score"`
	Severity    string   `json:"severity"`
	Line        int      `json:"line"`
	Categories  []string `json:"categories,omitempty"`
	Noisy       bool     `json:"noisy,omitempty"`
}

// RejectedMatch records a hit that was thrown away, with the reason.
//
// A rule set that silently drops its own matches is the failure this project
// already paid for once: a port that looked complete while quietly missing
// capabilities. Counting rejections is how a false-positive filter becomes
// visible instead of becoming a hole.
type RejectedMatch struct {
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
	Line   int    `json:"line"`
}

// SecretScan is the whole verdict for one body.
type SecretScan struct {
	Findings       []SecretFinding `json:"findings"`
	Rejected       []RejectedMatch `json:"rejected,omitempty"`
	RulesRun       int             `json:"rules_run"`
	RulesAvailable int             `json:"rules_available"`
	// RulesPreFiltered counts rules whose required literals were absent from the
	// body, so their regex was never run. It is reported rather than kept silent
	// because "12 findings" reads as coverage, and how much of the rule set was
	// actually consulted against this body is part of that claim.
	RulesPreFiltered int `json:"rules_prefiltered"`
}

// secretRuleRegistry is the compiled rule set, loaded once.
var secretRuleRegistry = titusRules

// SecretRules returns the rule set, exported so a test can prove the count and
// so the report can name which rules this build actually carries.
func SecretRules() []SecretRule { return secretRuleRegistry }

// placeholderFragments are strings that mark a value as an example rather than a
// credential. Titus does this per rule via `ignore_if_contains`; this list covers
// the shapes that are placeholders in every vendor's documentation.
var placeholderFragments = []string{
	"example", "xxxxxx", "your-", "your_", "changeme", "placeholder",
	"redacted", "dummy", "sample", "insert-", "todo", "test-key",
	"abcdef123456", "0123456789", "aaaaaaaa",
}

// ScanSecrets applies the rule set to a body.
//
// Four things happen here that the pattern alone cannot do, and each was a real
// defect in the first version:
//
//   - a match with an empty capture group is rejected rather than reported as a
//     finding with no value. Upstream rules such as the OAuth and Slack families
//     match on context, not on the token, and reading group 0 reports the word
//     "token" as if it were the token.
//   - a value whose Shannon entropy is below the rule's `min_entropy` is
//     rejected. Length and shape do not make a value random, and `min_entropy`
//     exists precisely because they do not.
//   - identical values found by two rules are deduplicated by fingerprint, and
//     the **highest-scoring** rule wins. One leaked key reported twice reads as
//     two incidents, and one reported by the weaker of two rules understates it.
//   - a rule sees the whole body, not one line at a time, so a rule whose shape
//     spans a line break can match at all. See `scanWithRules` for the measured
//     cost of getting this wrong: two rules, including the highest-scoring PEM
//     rule in the set, were structurally unreachable.
func ScanSecrets(text string, includeNoisy bool) SecretScan {
	return scanWithRules(text, secretRuleRegistry, includeNoisy)
}

// credentialGroup is which capture group of a rule holds the credential itself.
//
// The table's `Group` column comes from the generator's own preference list, which
// ranks a named group by what it is called: `secret`, `secret_key`, `token`, `key`,
// `api_key`. Six connection-string rules name their groups `username`, `password`
// and `host` — and none of those names is in the preference list, so the generator
// fell through to the first named group, which is the username.
//
// Measured consequence, and it is the question the operator asked: for
// `postgres://app_user:s3cr3tP4ssw0rd7@db.internal:5432/o` the finding carried
// `app_user`, and the password — present in the regex, matched, and discarded at
// the moment the group was chosen. Six rules did this: `np.postgres.1`,
// `np.redis.1`, `np.mongodb.1`, `kingfisher.rabbitmq.1`, `kingfisher.credentials.1`
// and `kingfisher.curl.1`. `np.redis.2` already delivered the password, because
// `password` happens to be its first named group.
//
// So the preference is applied here rather than by editing the generated table, for
// three reasons. The table carries `DO NOT EDIT` and is byte-comparable with
// upstream, so a hand edit would be lost at the next sync. The generator needs the
// upstream YAML checkout (`pkg/rule/rules`) to run, which this repository does not
// carry, so a generator change could not be verified here. And the correction
// belongs to the reader anyway: it is a statement about what a group *named*
// `password` means, and that is true of every rule, present and future, instead of
// of six rows that happened to be written down once.
//
// A rule whose chosen group already is the password keeps it: `SubexpIndex` returns
// the same index, and `np.redis.2` is therefore unchanged.
func credentialGroup(rule SecretRule) int {
	if rule.Regex == nil {
		return rule.Group
	}
	if index := rule.Regex.SubexpIndex("password"); index > 0 {
		return index
	}
	return rule.Group
}

// scanWithRules is the body of ScanSecrets with the rule set injected.
//
// It exists because one guard — "the capture group was empty" — cannot be
// reached by any of the 539 upstream rules: every one of them declares a group
// that participates whenever the pattern matches. A guard that cannot be
// reached is a guard that cannot be tested, and an untested guard is the kind of
// line that is quietly deleted and quietly needed. Injecting the set makes the
// branch testable without inventing a fake rule in the shipped table.
//
// # A rule runs on the whole body, not on one line at a time
//
// This is the second version, and the reason for it is measured. The first
// version did `strings.Split(text, "\n")` and ran every rule on every line
// separately. That made every rule whose body contains `\s`, `[\n\r]`, `(?s)` or
// `(?is)` structurally unreachable, because a newline can never occur inside one
// line — the class it needs to match was cut out of the input before the rule
// ever saw it.
//
// Measured on this build: **2 of 543 rules** matched a real body when given the
// whole text and matched zero lines of it:
//
//   - `np.pem.1` `PEM-Encoded Private Key`, upstream `base_score` 92
//   - `kingfisher.privkey.2` `Contains Private Key`
//
// So a page serving a PEM-encoded private key reported nothing at all — not a
// shortened value, not a rejected match, simply zero findings for the highest
// scoring rule in the set. `-----BEGIN RSA PRIVATE KEY----- … -----END RSA PRIVATE
// KEY-----`, and the same for the `EC`, `OPENSSH`, `PKCS8` and `PGP` headers,
// all returned `findings=0 rejected=0`. A rule that is present, scored 92, and
// can never fire is worse than an absent rule, because the rule count says 534
// rules ran.
//
// 307 of the 543 rules carry a newline-capable class. Only two are unreachable
// today, and that is luck rather than design: nothing stops the next rule from
// being the third.
//
// The line number is therefore computed from the match offset instead of from
// the loop variable, so the report still points at the line the analyst reads in
// their editor. `lineAt` counts newlines before the match; it is 1-based, which
// is the same convention `Match` uses for pattern hits.
func scanWithRules(text string, rules []SecretRule, includeNoisy bool) SecretScan {
	scan := SecretScan{RulesAvailable: len(rules)}
	if strings.TrimSpace(text) == "" {
		return scan
	}
	// (filter removal 2026-10-16): fingerprint dedup map removed; no filtering applied.

	// The prefilter asks each rule for the literals a match of it must contain and
	// skips the rule when the body has none of them. The lowercased copy of the body
	// is what case-insensitive literals are looked for in, and it is built at most
	// once per scan, and only when some rule actually asks a folded question.
	var folded string
	foldedReady := false
	foldedBody := func() string {
		if !foldedReady {
			folded = strings.ToLower(text)
			foldedReady = true
		}
		return folded
	}

	for _, rule := range rules {
		if rule.Noisy && !includeNoisy {
			continue
		}
		if rule.Regex == nil {
			continue
		}
		scan.RulesRun++
		if groups := prefilterForPattern(rule.Regex.String()); len(groups) > 0 {
			if !prefilterAllows(groups, text, foldedBody()) {
				scan.RulesPreFiltered++
				continue
			}
		}
		group := credentialGroup(rule)
		// The indexed form is what makes the line number possible: a match carries
		// its byte span, and the span is what maps back to a line. The indexed
		// slice is laid out as [start0, end0, start1, end1, …] over the groups, so
		// group n occupies the pair at 2n and 2n+1, and -1 marks a group that did
		// not participate.
		for _, span := range rule.Regex.FindAllStringSubmatchIndex(text, -1) {
			line := lineAt(text, matchStart(span))
			value := capturedValue(span, group, text)
			// Filter removal (owner instruction 2026-10-16): every match that reaches
			// this point becomes a finding. The six post-regex verdicts — empty
			// capture group, vendor reject expression, character requirements,
			// entropy floor, placeholder stand-ins and fingerprint dedup — are
			// disabled, so `scan.Rejected` stays empty and the regex hits are not
			// dropped. An empty capture carries no credential and is skipped without
			// being recorded as a rejection.
			if value == "" {
				continue
			}
			fingerprint := secretFingerprint(value)
			scan.Findings = append(scan.Findings, SecretFinding{
				Rule:        rule.ID,
				Name:        rule.Name,
				Value:       value,
				Fingerprint: fingerprint,
				Score:       rule.Score,
				Severity:    secretSeverity(rule.Score),
				Line:        line,
				Categories:  rule.Categories,
				Noisy:       rule.Noisy,
			})
		}
	}

	sort.SliceStable(scan.Findings, func(i, j int) bool {
		if scan.Findings[i].Score != scan.Findings[j].Score {
			return scan.Findings[i].Score > scan.Findings[j].Score
		}
		if scan.Findings[i].Line != scan.Findings[j].Line {
			return scan.Findings[i].Line < scan.Findings[j].Line
		}
		return scan.Findings[i].Rule < scan.Findings[j].Rule
	})
	return scan
}

// capturedValue reads the rule's capture group out of an indexed match, falling
// back to the whole match only when the rule declares group 0.
//
// The indexed slice is laid out as [start0, end0, start1, end1, …]: pair n covers
// group n, and a group that did not participate carries -1 in both slots. A group
// that did not participate is not an empty string, it is an absent slice, and
// conflating the two is how a rule that matched nothing gets reported as a finding
// with no value.
func capturedValue(span []int, group int, text string) string {
	if group <= 0 {
		if len(span) < 2 {
			return ""
		}
		return text[span[0]:span[1]]
	}
	pair := 2 * group
	if pair+1 >= len(span) {
		return ""
	}
	start, end := span[pair], span[pair+1]
	if start < 0 || end < 0 {
		return ""
	}
	return text[start:end]
}

// matchStart is the byte offset the whole match begins at, which is what the line
// number is computed from.
func matchStart(span []int) int {
	if len(span) < 2 {
		return 0
	}
	if span[0] < 0 {
		return 0
	}
	return span[0]
}

// lineAt is the 1-based line number of a byte offset in text.
//
// It counts the newlines before the offset rather than splitting the body into
// lines first, because the rule now sees the whole body: the split that the line
// number would need is the very thing that made multi-line rules unreachable.
// A body with no newline at all is line 1, and an offset past the end still names
// the last real line rather than a line that does not exist.
func lineAt(text string, offset int) int {
	if offset <= 0 {
		return 1
	}
	if offset > len(text) {
		offset = len(text)
	}
	return 1 + strings.Count(text[:offset], "\n")
}

// secretSeverity turns upstream's 0..100 score into a band the UI can colour.
// The bands are named, not numbered, because "score 85" is a number the report
// can print but not rank.
func secretSeverity(score int) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

// secretFingerprint is a stable short identifier: enough to recognise the same
// value twice, not enough to publish it.
func secretFingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	head := value
	if len([]rune(value)) > 6 {
		head = string([]rune(value)[:6])
	}
	return head + "…" + hex.EncodeToString(sum[:])[:8]
}

func isPlaceholderValue(value string) bool {
	cleanVal := strings.Trim(strings.ToLower(value), " \t\r\n'\"`:=,;")
	if cleanVal == "secret" || cleanVal == "secrets" || cleanVal == "null" || cleanVal == "undefined" {
		return true
	}
	lowered := strings.ToLower(value)
	for _, fragment := range placeholderFragments {
		if strings.Contains(lowered, fragment) {
			return true
		}
	}
	return false
}

// trimFloat renders an entropy for a report. Three decimals is enough to see
// 2.500 from 2.4999 and short enough to keep a rejection list readable.
func trimFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', 3, 64)
}
