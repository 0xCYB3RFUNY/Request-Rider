package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// urlPathEscape is the escaping used for every GitHub path segment the secret
// scan builds, named apart from `url.PathEscape` so a reader can see that the
// scan is not sharing a helper with the URL parser on purpose: a repository name
// is one segment, and a value that already parsed as a URL must not be escaped
// twice.
func urlPathEscape(value string) string {
	return url.PathEscape(value)
}

// hashSecret is the digest that makes a fingerprint unique without keeping the
// secret. It is a plain SHA-256 of the matched value, and it is a fingerprint
// rather than a verifier: it says "the same value again", not "this key is
// valid", and the engine never calls a provider to check one.
func hashSecret(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// Secret rules.
//
// The reference tools this replaces were separate binaries: a Rust scanner, two
// Python scanners and two Go crawlers. None of them can be installed in this
// deployment, and more importantly a binary cannot be given this project's route
// generation, its `source_ip` and its provenance rules — a finding that came
// through the Tor route has to be recorded as coming through the Tor route. So
// the rules live here, in the engine, and read through the same `toolClient` every
// other transform uses.
//
// Each rule is a named pattern with a severity. The name is what the operator
// reads in the graph, so it is a provider name and not a description of the
// regex: "AWS access key" tells an analyst what leaked, "rule 7" does not.
//
// A rule must be narrow enough that a false positive is rare, because a secret
// finding is an accusation about someone's infrastructure. The check every rule
// has to pass is `secretFindingsAreConsistent` below: the engine verifies that a
// finding names a provider, carries a fingerprint, and that the fingerprint is
// not something any rule would match in ordinary prose.
type secretRule struct {
	// id is the provider name reported on the finding.
	id string
	// pattern must capture the secret itself in group 1.
	pattern *regexp.Regexp
	// severity is a short operator-facing hint about what the key is.
	severity string
	// valueGroup names the capture group that holds the secret, when the rule
	// needs more than "the first group". An assignment rule captures the
	// variable's name on the left and the credential on the right, and reading
	// that group off the pattern keeps the text scan and the JavaScript matcher
	// answering the same question from one place.
	valueGroup int
	// lettersAlone lifts the "must contain a digit as well as a letter"
	// requirement of `secretValueIsUsable` for this one rule.
	//
	// The requirement exists because the shipped bundles hardcode tokens, not
	// because a credential cannot be alphabetic: it keeps `password: "true"` and
	// `token: "undefined"` out of the findings. Applied to a username it is
	// simply wrong — `admin_root`, `svc_moderator`, `support` and `root` are
	// the names accounts actually have, and JS-Analyser reported two of them on
	// the capability fixture where this project reported none. So the shape
	// check is a property of the rule rather than of the registry, and the rule
	// that must not have it says so.
	lettersAlone bool
	// digitRequired asks for the same digit requirement on a rule that matches a
	// bare literal rather than a `name = value` pair.
	//
	// It exists because the requirement used to be tied to the *shape* of the
	// match — a rule that captured an assignment had to prove its value — and so
	// it silently applied to no rule at all that captured the token itself. That
	// left `pinkerton_artifactory_password` free to accuse Yandex.Metrica's
	// minified `context.js` of leaking a password: the bundle contains
	// `{key:"APExcludedBlocks", get:…}`, the pattern admits lowercase, and the
	// finding was reported to the operator on a live crawl of ria.ru.
	//
	// Measured on that bundle and two controls, 2026-10-04: one match in 433 KB,
	// and it was the property key. Both properties measured in the file
	// (`APExcludedBlocks`, `APExceptionBlocks`) carry no digit at all, 0 of 2.
	// A JFrog reference token is 73 characters of base62, so the gate cannot cost
	// a real one — and `TestARealArtifactoryTokenIsStillReported` holds that
	// half down, because a gate that also drops real tokens is not a gate.
	digitRequired bool
	// declinesSpecificShape asks the rule to step aside for a value that a more
	// specific rule in this same registry recognises by its own shape.
	//
	// It exists because one credential is folded into one row: the first rule to
	// claim a value wins, and the project's own rules come first. So a broad
	// assignment rule silently renames a specific finding whenever the two capture
	// the same bytes. Measured, not argued: with `.` added to the value class — so
	// that a key is not cut at its first dot — `generic_api_key_assignment` began
	// capturing a whole three-segment JWT, its fingerprint matched `jwt_token`'s,
	// and the finding the operator reads became "generic secret assignment" instead
	// of "JWT". `TestJWTRuleNeedsThreeRealSegments` failed on it.
	//
	// The flag is a property of the rule rather than a branch on its id, because the
	// surrounding code already learned that lesson once: deciding this by id left a
	// second place to forget to update when a rule was added.
	declinesSpecificShape bool
}

// secretRules is deliberately small and high-signal. A list of hundreds of
// vendor patterns would look like coverage while raising false positives, and a
// graph full of invented findings is worse than a short honest one: the operator
// cannot tell a real AWS key from a placeholder, so they stop trusting the tool.
// The upper bounds below are ceilings, not descriptions of the format.
//
// A class like `[0-9A-Za-z-]{10,48}` does not report a long Slack token — it
// reports the first 48 characters of it and the analyst never learns that. That
// was measured, not assumed: a 54-character `xoxb-…-…-…` token was handed to
// the UI as 32 characters, and a 212-character FCM key as 152. A finding whose
// value is a prefix of the secret is a finding nobody can use, because a key that
// does not validate is indistinguishable from a wrong one.
//
// So every tail is given room well past any vendor's current length, and the
// ceiling stays finite on purpose: an unbounded class would let one base64 blob
// in a minified bundle swallow the rest of the file, and a swallowed value is
// wrong in the other direction. `aws_access_key_id` and `sendgrid_api_key` keep
// their exact widths because those are fixed by the vendor and a longer string
// with the same prefix is not one of them.
var secretRules = []secretRule{
	{
		id:       "aws_access_key_id",
		pattern:  regexp.MustCompile(`\b((?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|APKA)[0-9A-Z]{16})\b`),
		severity: "AWS access key id",
	},
	{
		id:       "github_token",
		pattern:  regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z]{36,400})\b`),
		severity: "GitHub personal access token",
	},
	{
		id:       "slack_webhook",
		pattern:  regexp.MustCompile(`(https://hooks\.slack\.com/services/T[A-Za-z0-9]{6,30}/B[A-Za-z0-9]{6,30}/[A-Za-z0-9]{20,300})`),
		severity: "Slack incoming webhook",
	},
	{
		id:       "stripe_secret_key",
		pattern:  regexp.MustCompile(`\b(sk_(?:live|test)_[0-9A-Za-z]{16,200})\b`),
		severity: "Stripe secret key",
	},
	{
		id:       "google_api_key",
		pattern:  regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{20,200})\b`),
		severity: "Google API key",
	},
	{
		id:       "sendgrid_api_key",
		pattern:  regexp.MustCompile(`\b(SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43})\b`),
		severity: "SendGrid API key",
	},
	{
		id:       "npm_token",
		pattern:  regexp.MustCompile(`\b(npm_[0-9A-Za-z]{36,200})\b`),
		severity: "npm access token",
	},
	{
		// The body is part of the capture on purpose. The header alone is
		// identical for every private key ever written, so a fingerprint taken
		// from it would collapse a thousand distinct keys into one finding. The
		// first bytes of the key material differ per key and make the
		// fingerprint mean "this key", which is the only thing a fingerprint can
		// honestly mean.
		id:       "private_key_block",
		pattern:  regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,200}`),
		severity: "private key block",
	},
	{
		id: "generic_api_key_assignment",
		// The weakest rule here, and the one that needs the assignment shape:
		// a bare word `key` is a word, not a secret. It demands a provider-ish
		// name on the left, an equals or colon, and a long opaque value.
		//
		// The bare `token` name is here because JS-Analyser has it
		// (`(?i)(token|secret|auth[_-]?token)\s*[:=]`) and the capability fixture
		// showed the difference: its `token = 'b7c9…'` was reported there and
		// dropped here, because this pattern listed only `access_token`,
		// `auth_token` and `client_secret`. `token` is last in the alternation
		// so every named form keeps matching itself first; the length floor and
		// the assignment shape are what keep `token: length` and `token:
		// "undefined"` out.
		//
		// The names below were measured, not chosen. A matrix of 24 names a program
		// actually gives a credential, crossed with six value shapes, left 69 of 144
		// cells empty — and they were empty because the *name* was absent from the
		// alternation, not because the value was refused:
		//
		//	api_key_v2  api_token  apiToken  refresh_token  credentials
		//	private_key  session_key  encryption_key  auth  jwt
		//
		// `api_key_v2` fails differently from the rest: the trailing `\b` meant any
		// name carrying a suffix segment was refused outright, so the suffix is now
		// part of the name instead of something the word boundary has to survive.
		// `auth` is last because a bare `auth` is a configuration key, and what keeps
		// `auth: true` and `auth: {"type": "oauth"}` out is the length floor, the
		// assignment shape and the digit-and-letter requirement — not the name itself.
		//
		// `jwt` was in this list and was removed again, measured rather than argued.
		// A registry folds one credential into one row and the project's own rules
		// claim a value first, so a name-based `jwt` rule takes the value before
		// `jwt_token` ever sees it — and a three-segment JWT was then reported as
		// "generic secret assignment". `TestJWTRuleNeedsThreeRealSegments` failed on
		// it. A finding that says which credential it is beats a finding that says
		// only that there is one, so the specific rule wins and `jwt` stays out. What
		// that costs: a variable named `jwt` holding an opaque base62 string is not
		// reported, and that is a real, named loss rather than a silent one.
		//
		// The value class gained the punctuation a real generated secret carries.
		// Measured: `Tr0ub4dor&3xK9!vLmQ2#zXpW7@cRsD5*nHjF1@uBgY6^` under `api_key`,
		// `secret` and `token` was not found at all, because the old class stopped at
		// the first `&`. Quote, whitespace, backtick, comma, brace, bracket, angle
		// bracket and semicolon stay out, so the capture cannot run past the value it
		// is meant to hold.
		declinesSpecificShape: true,
		pattern:               regexp.MustCompile(`(?i)\b((?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|api[_-]?token|id[_-]?token|bearer[_-]?token|client[_-]?secret|private[_-]?key|session[_-]?key|encryption[_-]?key|signing[_-]?key|credentials?|passphrase|secret|token|auth)(?:[_-][A-Za-z0-9]+)*\b\s*[:=]\s*["']?([A-Za-z0-9_\-/+.$!~^&*#@%=]{24,})["']?)`),
		severity:              "generic secret assignment",
		valueGroup:            secretAssignmentValueGroup,
	},
	{
		// Ported from zack0x01/JS-Analyser, which reports hardcoded credentials
		// as three patterns — `password|passwd|pwd`, `db_password` and
		// `username|user_name|login`. They are one rule here, and that is a
		// measured correction rather than a simplification: upstream's first two
		// patterns both fire on `dbPassword = '…'`, so one line produced two
		// findings saying the same thing.
		//
		// Two details are upstream's, and both were measured rather than chosen.
		// The name is matched without a leading word boundary, because a
		// boundary there silently loses every camelCase name — `userPassword =
		// '…'` is the most common way a bundle writes one, and the first version
		// of this rule reported only `dbPassword`. The value must be a quoted
		// string, which is what upstream required and what keeps
		// `password: isDisabled` out of the findings.
		//
		// The value is group 2 because group 1 is the name the pattern needs in
		// order to match at all — the same shape as the assignment rule above,
		// which is why the group is a property of the rule and not of its id.
		id:         "hardcoded_password",
		pattern:    regexp.MustCompile(`(?i)([A-Za-z0-9_]*pass(?:word|wd)|pwd)\b\s*[:=]\s*["']([^"']{6,})["']`),
		severity:   "hardcoded password",
		valueGroup: secretAssignmentValueGroup,
	},
	{
		id:         "hardcoded_username",
		pattern:    regexp.MustCompile(`(?i)([A-Za-z0-9_]*(?:username|user_name|login))\b\s*[:=]\s*["']([^"']{3,})["']`),
		severity:   "hardcoded username",
		valueGroup: secretAssignmentValueGroup,
		// No digit requirement, and the reason is measured rather than argued:
		// `var login = 'admin_root'` and `var userName = 'svc_moderator'` were
		// both reported by JS-Analyser on the capability fixture, and by neither
		// path here before this flag existed — the shape check threw away the
		// two most ordinary account names there are. See `lettersAlone`.
		lettersAlone: true,
	},
	{
		// The upstream Slack pattern is `xox[baprs]-…`. The existing rule above
		// covers the webhook URL, which is a different credential with a
		// different blast radius, so both stay.
		id: "slack_token",
		// The underscore is in the class because, measured, its absence truncated
		// the token: for
		// `xoxb-2947483729-2947483729-aBcDeFgHiJkLmNoPq…-_` a class
		// of `[0-9A-Za-z-]` stopped at the `-` and delivered 65 characters of a
		// 66-character token. A rule that returns the first 65 characters of a key
		// is worse than one that returns none, because the finding looks complete.
		pattern:  regexp.MustCompile(`\b(xox[baprs]-[0-9A-Za-z_-]{10,200})\b`),
		severity: "Slack token",
	},
	{
		// A connection string is where a database password most often sits, and it
		// has no credential-shaped name for an assignment rule to read: there is
		// nothing on the left but a URL scheme.
		//
		// Measured before this rule existed, on five shapes a bundle really carries:
		// `postgres`, `mysql`, `redis` with and without a user name, and `mongodb`.
		// All five reported nothing. That is not a narrow miss — a connection string
		// is how a front-end bundle reaches a database at all, and a password in one
		// is the credential most worth reporting.
		//
		// The user name is optional because the common Redis form has none:
		// `redis://:password@host` is the password and nothing else. The password
		// group stops at the first `@`, so neither the host, nor its port, nor the
		// path ends up inside the secret.
		//
		// The digit requirement is the same trade-off `generic_api_key_assignment`
		// makes and for the same measured reason, so `guest:guest` is not reported:
		// a default pair with no digit is far more often a documentation example than
		// a leaked credential. It is `digitRequired` and not `valueGroup`, and that
		// choice is measured rather than stylistic: the JavaScript path sorts rules by
		// their value group, and a rule that claims to be assignment-shaped is matched
		// against `name: value` with the match anchored at the first byte. The name of
		// a connection-string variable is `dsn`, `dbUrl` or `config`, so an anchored
		// URL pattern can never match and the first version of this rule reported
		// nothing on any of the five shapes it was written for. A literal rule is read
		// off each string literal instead, which is where a URL actually lives.
		id:            "connection_string_password",
		pattern:       regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.\-]{1,31}://[a-z0-9._~%!$&'()*+,;=-]{0,128}:([^@/\s'"<>\x60]{4,256})@[a-z0-9.\-]+`),
		severity:      "credential in connection string",
		digitRequired: true,
	},
	{
		id:       "paypal_token",
		pattern:  regexp.MustCompile(`(access_token\$production\$[a-zA-Z0-9]{22}\$[a-zA-Z0-9]{86})`),
		severity: "PayPal access token",
	},
	{
		id:       "firebase_messaging_key",
		pattern:  regexp.MustCompile(`(AAAA[A-Za-z0-9_-]{4,40}:[A-Za-z0-9_-]{20,400})`),
		severity: "Firebase Cloud Messaging server key",
	},
	{
		// Upstream writes the JWT pattern loosely and then filters the result in
		// code — three parts and at least 50 characters, or it is base64 that
		// happens to start with `eyJ`. That filter is expressed in the pattern
		// here instead, because a rule that cannot match on its own is a rule
		// whose quality depends on a caller remembering to clean it up.
		id:       "jwt_token",
		pattern:  regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`),
		severity: "JSON Web Token",
	},
	{
		// The publishable half of a Stripe pair. It is not a secret — it is
		// shipped to every visitor by design — but it names the account, and an
		// account name is what an analyst needs to recognise the pair.
		id:       "stripe_publishable_key",
		pattern:  regexp.MustCompile(`\b(pk_(?:live|test)_[0-9A-Za-z]{16,200})\b`),
		severity: "Stripe publishable key",
	},
	// The next five are the gaps against `m4ll0k/SecretFinder`, read from its
	// `SecretFinder.py` at commit d06119dedd9c1505137d1ec4792d5d5b65c7425d. That
	// tool lists about twenty-five patterns and this list had sixteen; these are
	// the ones whose shape is specific enough to keep the promise this file's own
	// header makes — a short list the analyst can trust.
	//
	// Three of its patterns are deliberately **not** here, and the reason is the
	// same one that keeps the list short: `AC[0-9a-zA-Z_-]{32}` (Twilio account
	// SID) matches any identifier that starts with two letters and is 34 long,
	// `SK[0-9a-fA-F]{32}` matches any 34-character hex digest that happens to begin
	// `SK`, and `basic\s*[a-zA-Z0-9=:_+/-]+` matches the word `basic` followed by
	// half a bundle. Each would add a row per minified file and teach the analyst
	// to ignore the column.
	{
		id: "google_oauth_token",
		// No trailing `\b`: an underscore is a word character, so a token that ends in
		// one has no boundary after it and the rule would silently never fire on
		// the tokens that actually end that way.
		pattern:  regexp.MustCompile(`\b(ya29\.[0-9A-Za-z\-_]{10,300})`),
		severity: "Google OAuth access token",
	},
	{
		id:       "google_captcha_site_key",
		pattern:  regexp.MustCompile(`\b(6L[0-9A-Za-z_-]{38})\b`),
		severity: "Google reCAPTCHA site key",
	},
	{
		id:       "amazon_mws_auth_token",
		pattern:  regexp.MustCompile(`\b(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
		severity: "Amazon MWS auth token",
	},
	{
		id:       "facebook_access_token",
		pattern:  regexp.MustCompile(`\b(EAACEdEose0cBA[0-9A-Za-z]{10,200})\b`),
		severity: "Facebook access token",
	},
	{
		id:       "square_access_token",
		pattern:  regexp.MustCompile(`\b(sqOatp-[0-9A-Za-z\-_]{22,64}|EAAA[a-zA-Z0-9]{60})\b`),
		severity: "Square access token",
	},
}

// The Pinkerton rules are appended, not merged: the registry above is ours and
// has ids and severities of our own choosing, while `pinkertonRules` is
// generated from `src/pinkerton/modules/secret.py` of `000pp/Pinkerton` and carries upstream's commit in
// its header. Merging the two into one literal would mean hand-editing a
// generated file on the next upstream sync, and the generated part is exactly
// the part that must stay byte-comparable with the original.
func init() {
	secretRules = append(secretRules, pinkertonRules...)
}

// secretValueIsUsable applies the one extra requirement an assignment-shaped
// rule makes of the value it captured.
//
// Measured on a live target: the translation bundle of vk.com contains
// `"guest_password":"Password"`, `"login_enter":"Sign in"` and four more labels
// whose left side carries the word `password` or `login`. All six were reported
// as hardcoded credentials, and a report that accuses a translation file of six
// leaked passwords is a report the analyst stops reading.
//
// A credential has structure a label does not: it carries a digit as well as
// letters, and it is one token rather than a sentence. Both are statements about
// what the value *is*, not a blocklist of words — a blocklist is upstream's
// approach and it is unbounded by construction.
//
// The rule does not touch a vendor rule: `pk_live_…` and `xoxb-…` are
// recognised by their own shape, and demanding a digit of them would be
// redundant rather than careful.
func secretValueIsUsable(rule secretRule, value string) bool {
	// The digit requirement is asked for by shape (an assignment rule) or by
	// name (`digitRequired`), and nothing else. Both are statements about what
	// this one value is, not a blocklist.
	if rule.valueGroup != secretAssignmentValueGroup && !rule.digitRequired {
		return true
	}
	if rule.lettersAlone {
		// The space rule still applies: a value with a space in it is a label,
		// not a name. What is lifted is only the digit requirement, and only
		// for a rule that says so.
		return !strings.ContainsFunc(value, unicode.IsSpace)
	}
	hasDigit := false
	hasLetter := false
	for _, character := range value {
		switch {
		case unicode.IsSpace(character):
			// A sentence is a label. A credential with a space in it is possible
			// and is not what the shipped bundles carry.
			return false
		case unicode.IsDigit(character):
			hasDigit = true
		case unicode.IsLetter(character):
			hasLetter = true
		}
	}
	return hasDigit && hasLetter
}

// placeholderFragments are the values a template, a test fixture or a masked
// example always contains. A match on one of these is a documentation string
// about a secret, not a secret, and reporting it would be the fastest way to lose
// the operator's trust in the whole graph.
var placeholderFragments = []string{
	"xxxxxxxx", "your-", "your_", "example", "placeholder", "changeme",
	"replace-me", "replaceme", "insert-", "insert_", "dummy", "sample",
	"fake", "todo", "redacted", "<", "abcdef123456", "0123456789",
	"test-key", "notreal", "not-real", "secretkey", "apikey",
}

// isPlaceholderValue reports whether a matched value is a stand-in rather than a
// live credential.
func isPlaceholderValue(value string) bool {
	lowered := strings.ToLower(value)
	for _, fragment := range placeholderFragments {
		if strings.Contains(lowered, fragment) {
			return true
		}
	}
	// A value made of one repeated character is never a real key, and every
	// provider has a well-formed length, so a run of one byte is a fixture.
	if len(value) > 3 {
		first := value[0]
		repeated := true
		for index := 0; index < len(value); index++ {
			if value[index] != first {
				repeated = false
				break
			}
		}
		if repeated {
			return true
		}
	}
	return false
}

// secretFingerprint is what makes a finding checkable without storing the secret.
//
// The full value is never written anywhere. A graph is exported into project
// bundles, rendered into reports and pasted into chats, and a real key that
// leaves the tool becomes a real key that is now in three more places. What the
// graph keeps is a truncated prefix — enough to recognise the key again in a
// different file — and a hash of the whole value, which is what makes the same
// key seen twice report as one finding instead of two.
func secretFingerprint(value string) (prefix, digest string) {
	prefixLength := 6
	if len(value) < prefixLength {
		prefixLength = len(value)
	}
	return value[:prefixLength], hashSecret(value)
}

// secretFinding is one match, before it becomes an entity.
type secretFinding struct {
	rule string
	// value is the credential itself, exactly as it was found. The analyst who
	// ran the scan is the one who needs it: a finding that names a provider, a
	// repository and a fingerprint but not the key leaves the whole scan to be
	// repeated by hand before anything can be done with it.
	value       string
	severity    string
	fingerprint string
	repository  string
	commit      string
	file        string
	line        int
}

// applySecretRules scans one text for every rule and returns the findings.
//
// The same secret found in many commits is one finding: the deduplication key is
// the fingerprint, not the location. A key committed once and then re-touched in
// fifty commits is one exposure, and a report that lists it fifty times reads as
// fifty separate problems.
func applySecretRules(text, repository, commit string) []secretFinding {
	if text == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	findings := make([]secretFinding, 0, 4)
	// Один секрет — одна знахідка. Ключ згортання — відбиток значення, а не
	// правило: два правила, які впізнали той самий ключ, дають один рядок, а
	// не два. Без цього звіт показує дві проте вразливість на одному ключі —
	// і тим більше, чим більше правил у реєстрі.
	reported := make(map[string]bool, 4)
	for _, rule := range secretRulesInPriorityOrder() {
		valueGroup := secretValueGroup(rule)
		for _, match := range rule.pattern.FindAllStringSubmatch(text, -1) {
			if len(match) <= valueGroup {
				continue
			}
			value := match[valueGroup]
			if value == "" {
				continue
			}
			if isPlaceholderValue(value) || !secretValueIsUsable(rule, value) {
				continue
			}
			prefix, digest := secretFingerprint(value)
			fingerprint := prefix + "…" + digest[:12]
			if reported[fingerprint] {
				continue
			}
			reported[fingerprint] = true
			findings = append(findings, secretFinding{
				rule:        rule.id,
				value:       value,
				severity:    rule.severity,
				fingerprint: fingerprint,
				repository:  repository,
				commit:      commit,
				file:        "",
				line:        secretLineOf(lines, value),
			})
		}
	}
	return findings
}

// secretAssignmentValueGroup is the capture group an assignment rule keeps its
// value in: group 1 is the variable's name, group 2 is the credential.
//
// It is a constant because two readers need it — `secretValueGroup` below and
// the JavaScript matcher that has to decide whether a rule can match a string
// literal at all — and two copies of the number 2 is how they drift apart.
const secretAssignmentValueGroup = 2

// secretValueGroup names the capture group that holds the secret itself.
//
// It reads the group off the pattern rather than off the rule id, which is what
// keeps a new rule from being silently dropped: the first version hard-coded the
// group per rule, and a rule without a group simply never matched — a private
// key block is a real finding and it could never be reported.
//
// It is a function rather than a line inside the loop because the Target
// crawler now applies the same rules to a JavaScript parse tree
// (`analyzeJavaScript` in target_js.go), and a rule that answers "which group
// is the value" in two places answers it differently the first time one of them
// is edited.
func secretValueGroup(rule secretRule) int {
	if rule.pattern.NumSubexp() == 0 {
		return 0
	}
	if rule.valueGroup > 0 {
		return rule.valueGroup
	}
	return 1
}

// secretLineOf names the line a value first appears on, so the report can point at
// something an operator can open.
func secretLineOf(lines []string, value string) int {
	for index, line := range lines {
		if strings.Contains(line, value) {
			return index + 1
		}
	}
	return 0
}

// transformGitSecrets scans the public commit history of a GitHub account for
// credentials that were committed and are still visible in the public diff.
//
// This is the part of the reference toolchain that is worth keeping and the part
// that was not reproducible: the scanners read a local checkout, which needs a
// clone this project deliberately does not perform — every outbound request here
// goes through the route so the finding carries the operator's `source_ip`. The
// public commit diff is the same evidence without the clone.
//
// A finding names a provider, a repository, a commit and the credential the
// commit exposed. The value is kept whole: the operator ran the scan to get it,
// and a report that says which key leaked but not what it is sends them back to
// the same commit by hand.
func transformGitSecrets(s *server, ctx context.Context, result *osintTransformResult, input osintTransformInput, collector *transformCollector) error {
	if !input.ConfirmNetwork {
		return transformError("NETWORK_CONFIRMATION_REQUIRED", "the commit secret scan performs a public network request")
	}
	username, endpoint := githubScanTarget(input.Value)
	if username == "" {
		return transformError("INVALID_GITHUB_USERNAME", "value must be a GitHub username or a public repository URL")
	}
	result.LocalOnly = false
	result.NetworkUsed = true
	client := s.toolClient(ctx)

	maxRepos, maxCommitPages, commitsPerRepo := githubScanLimits(input.Options)
	setTransformMetadata(result, "max_repos", maxRepos)
	setTransformMetadata(result, "max_commit_pages", maxCommitPages)
	setTransformMetadata(result, "commits_per_repo", commitsPerRepo)
	setTransformMetadata(result, "github_token_configured", githubToken() != "")
	setTransformMetadata(result, "secret_value_stored", true)

	// One repository was named: the scan does not widen to the owner's other
	// repositories, because a URL is a specific target and widening it would be a
	// different question than the one that was asked.
	repositories, err := githubRepositories(ctx, client, username, maxRepos)
	if err != nil {
		return err
	}
	if endpoint != "" && len(repositories) > 1 {
		repositories = filterGitHubRepository(repositories, endpoint)
	}
	if len(repositories) == 0 {
		result.Warnings = append(result.Warnings, "No public repository was available to scan.")
		return nil
	}
	setTransformMetadata(result, "repositories_scanned", len(repositories))
	if collector != nil {
		collector.setIndexTotal(ctx, len(repositories))
	}

	seen := map[string]bool{}
	findingCount := 0
	duplicates := 0
	commitsFetchedTotal := 0
	commitsExaminedTotal := 0
	for index, repository := range repositories {
		if err := collector.checkpoint(ctx); err != nil {
			break
		}
		if collector != nil {
			collector.indexPosition(ctx, repository.Name, index, len(repositories))
		}
		commitsFetched, commitsExamined := gitScanRepositorySecrets(
			ctx, client, username, repository, maxCommitPages, commitsPerRepo, collector,
			func(finding secretFinding) {
				// The same credential re-touched across commits is one exposure,
				// and the count of how many times it was seen is reported so the
				// operator can tell a single leak from a repeated one.
				if seen[finding.fingerprint] {
					duplicates++
					return
				}
				seen[finding.fingerprint] = true
				findingCount++
				result.Entities = append(result.Entities, secretEntity(finding))
				result.Relations = append(result.Relations, transformRelation{
					Type:       "exposes_secret",
					SourceType: "username",
					Source:     username,
					TargetType: "url",
					Target:     finding.repository + "#" + finding.fingerprint,
				})
			})
		commitsFetchedTotal += commitsFetched
		commitsExaminedTotal += commitsExamined
	}

	setTransformMetadata(result, "secrets_found", findingCount)
	setTransformMetadata(result, "secrets_deduplicated", duplicates)
	setTransformMetadata(result, "rules_applied", len(secretRules))
	// How much was actually read. The warning below talks about "the commits that
	// were read", and a result that does not say how many those were makes the
	// sentence unfalsifiable: an empty scan and a scan of three hundred commits
	// look identical from the outside. Measured 2026-10-01 against
	// `octocat/Hello-World`, where the reference tool reports two findings and
	// this one reports none — the two are committed by other people, the account
	// filter excludes them, and before this counter existed "excluded" was a claim
	// rather than something the result could show.
	setTransformMetadata(result, "commits_fetched", commitsFetchedTotal)
	setTransformMetadata(result, "commits_examined", commitsExaminedTotal)
	if findingCount == 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"No credential pattern matched in the %d of %d fetched commits that were read as diffs "+
				"across %d repositories, using %d rules. That is a statement about those commits, not about "+
				"the account: a secret can be committed through a host this scan never asked, and one removed "+
				"from the current tree stays visible in the history either way. Commits made by other people "+
				"are not counted, so a repository this account merely contributed to reads as no exposure.",
			commitsExaminedTotal, commitsFetchedTotal, len(repositories), len(secretRules)))
	}
	return nil
}

// githubScanTarget reads either a bare username or a public repository URL and
// returns the owner plus the repository that was named, if any.
//
// Four spellings are accepted because all four are what an operator actually
// pastes: `owner`, `owner/repo`, `github.com/owner/repo`, and the full URL. A
// form that was not recognised here would read as "no such account", which is a
// wrong answer rather than a missing one.
func githubScanTarget(value string) (username, repository string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", ""
	}
	path := parsed.Path
	if parsed.Host == "" {
		// No scheme: `url.Parse` put the whole thing in `Path`, so the host is
		// the first segment and has to be taken out by hand.
		segments := strings.Split(strings.Trim(trimmed, "/"), "/")
		if len(segments) > 0 && strings.EqualFold(segments[0], "github.com") {
			path = "/" + strings.Join(segments[1:], "/")
		}
	}
	segments := splitNonEmpty(path)
	if len(segments) == 0 {
		return "", ""
	}
	if !githubUsernamePattern.MatchString(segments[0]) {
		return "", ""
	}
	if len(segments) == 1 {
		return segments[0], ""
	}
	// A trailing `.git` is how a clone URL ends and is not part of the name.
	name := strings.TrimSuffix(segments[1], ".git")
	return segments[0], name
}

func splitNonEmpty(path string) []string {
	var out []string
	for _, segment := range strings.Split(path, "/") {
		if segment != "" {
			out = append(out, segment)
		}
	}
	return out
}

func filterGitHubRepository(repositories []githubRepository, name string) []githubRepository {
	for _, repository := range repositories {
		if strings.EqualFold(repository.Name, name) {
			return []githubRepository{repository}
		}
	}
	return nil
}

// secretEntity turns a finding into a graph entity.
//
// The identity is the repository plus the fingerprint, not the secret: two
// findings of the same key in the same repository are one exposure, and the
// identity has to say that on its own. The provider name rides in properties so
// the graph can be filtered by what leaked, and `secret_value` carries the
// credential the commit exposed — whole, because the operator ran the scan to
// get it.
func secretEntity(finding secretFinding) transformEntity {
	return entity("url", finding.repository+"#"+finding.fingerprint, map[string]interface{}{
		"kind":                "exposed_credential",
		"provider":            finding.rule,
		"severity":            finding.severity,
		"fingerprint":         finding.fingerprint,
		"secret_value":        finding.value,
		"repository":          finding.repository,
		"commit":              finding.commit,
		"line":                finding.line,
		"secret_value_stored": true,
	}, map[string]interface{}{"source": "github_commit_diff"})
}

// githubDiffPrefixLimit bounds a commit diff read. A diff is the one response
// here that is genuinely unbounded in the wild — a commit that reformats a
// generated file is megabytes — and the engine's rule is that it must not read a
// target response whole. The bound is a prefix, not a refusal: a credential in
// the head of a diff is found, and a diff that is too large to read says so
// instead of silently ending the scan.
const githubDiffPrefixLimit = 2 << 20

// githubCommitDiff reads the public diff of one commit.
//
// The `.diff` endpoint is used rather than `.patch` because the patch wraps the
// diff in a mail header block whose `From:` line carries the author's address,
// which is a different transform's job and would make this one report an address
// under a credential rule.
func githubCommitDiff(ctx context.Context, client *http.Client, username, repository, sha string) (string, bool) {
	endpoint := fmt.Sprintf("https://github.com/%s/%s/commit/%s.diff",
		urlPathEscape(username), urlPathEscape(repository), urlPathEscape(sha))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", false
	}
	request.Header.Set("User-Agent", archiveUserAgent)
	request.Header.Set("Accept", "application/vnd.github.v3.diff")
	response, err := client.Do(request)
	if err != nil {
		return "", false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, githubDiffPrefixLimit))
	if err != nil || len(body) == 0 {
		return "", false
	}
	return string(body), true
}

// gitScanRepositorySecrets reads the public diffs of one repository's recent
// commits and reports the credentials they still contain.
//
// It returns how many commits were fetched from the API and how many of those were
// actually read as a diff. Both numbers are needed to make the result falsifiable:
// the transform's own warning says "no credential pattern matched in the scanned
// public diffs", and without them that sentence cannot be checked against
// anything. Measured 2026-10-01 against `octocat/Hello-World`, where the reference
// tool reports two findings and this scan reports none: the two are committed by
// other people, so the account filter correctly excludes them — and the result
// said nothing at all about how much had been read, so "correctly excluded" was an
// assumption rather than a measurement.
func gitScanRepositorySecrets(
	ctx context.Context,
	client *http.Client,
	username string,
	repository githubRepository,
	maxCommitPages, commitsPerRepo int,
	collector *transformCollector,
	report func(secretFinding),
) (fetched, examined int) {
	name := repository.Name
	if name == "" {
		return
	}
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits?per_page=100",
		urlPathEscape(username), urlPathEscape(name))
	var scanned []gitHubCommit
	// `checked` is declared before the page walk because an error part-way
	// through returns both counts: a run that fetched forty commits and read two
	// is a different result from one that fetched none, and both have to be
	// reportable rather than indistinguishable.
	checked := 0
	examined = 0
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return len(scanned), examined
		}
		var batch []gitHubCommit
		status, err := githubAPIGet(ctx, client, fmt.Sprintf("%s&page=%d", endpoint, page), &batch)
		if err != nil || status < 200 || status >= 300 {
			return len(scanned), examined
		}
		if len(batch) == 0 {
			break
		}
		scanned = append(scanned, batch...)
		if maxCommitPages > 0 && page >= maxCommitPages {
			break
		}
		if len(batch) < 100 {
			break
		}
	}
	if len(scanned) == 0 {
		return
	}
	// Oldest first, for the same reason the address scan walks that way: a
	// credential that is still in a recent commit is one the maintainers have
	// most likely already dealt with, and the interesting history is behind it.
	for index := len(scanned) - 1; index >= 0; index-- {
		if commitsPerRepo > 0 && checked >= commitsPerRepo {
			break
		}
		commit := scanned[index]
		if commit.SHA == "" {
			continue
		}
		if err := collector.checkpoint(ctx); err != nil {
			break
		}
		checked++
		diff, ok := githubCommitDiff(ctx, client, username, name, commit.SHA)
		if !ok {
			continue
		}
		examined++
		for _, finding := range applySecretRules(diff, name, commit.SHA) {
			report(finding)
		}
	}
	return len(scanned), examined
}
