// Credential and secret exposure.
//
// # The defect that shaped this whole module
//
// The upstream implementation decides whether a discovered token is live by
// replaying it and asking whether the server's answer changed. The check itself
// is right. The set of signals it accepts as "changed" is not:
//
//	var privilegedSignals = []string{
//	    "authorization:", "x-api-key:", "set-cookie:",
//	    "\"role\"", "\"isadmin\"", "\"admin\"", "\"scope\"", "\"permissions\"",
//	    "private", "secret", "internal",
//	}
//
// Three of those are ordinary English words. A page whose footer contains the
// word "private", a login page that says "your password is secret", a settings
// screen with an "Internal" tab — each contains a privileged signal, each is
// therefore a *gated* response, and each therefore turns a pattern match into a
// **verified** finding at **critical** severity. A chat widget's public
// `websiteToken`, which the CHANGELOG specifically claims to have fixed, is
// promoted straight back to critical by any of the three.
//
// The rule here is the opposite one: a signal only counts when it is
// *structural*. A quoted JSON key at a value position, an HTML input whose value
// is the token, a cookie the server only issues once the token is accepted. The
// word "secret" in prose is not evidence of anything, and this module is not
// allowed to use it as evidence.
//
// # Why "public by design" is a tier and not a filter
//
// A site key is a real value with a real name that looks like a secret. Filtering
// by name is how a scanner hides a genuine leak that happens to be called
// `publishableKey`. The classification is therefore made *after* the match, from
// the key the value was assigned to, and it changes the tier rather than
// suppressing the row: the value is reported, at informational, with the reason
// it is not a vulnerability. An operator can then see it and disagree.
//
// # Why the evidence is redacted
//
// A secret in a report is a secret in a file the operator will paste into a bug
// report, a chat, a ticket. The full value is never written: enough is kept to
// identify which credential it is, and the value that would let a reader use it
// is not. This is the one place in the scanner where less evidence is more
// useful, because the reader is already trusted and the audience of the report
// is not.
package active

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// secretCategory is one credential pattern worth hunting.
type secretCategory struct {
	// name is how the finding names the credential.
	name string
	// pattern matches the credential.
	pattern *regexp.Regexp
	// claimed is the severity the evidence supports if impact is proven.
	claimed Severity
	// proofRequired marks a category whose impact cannot be inferred from
	// replay and which therefore stays potential regardless of what a page
	// says: a private key block is a private key block, and no response
	// "verifies" that the file it came from was readable by an outsider.
	proofRequired bool
}

// secretCategories are the patterns, ordered most to least dangerous.
//
// The private key block and the cloud access key are here because they are
// unambiguous. The generic assignments are here last because they are the ones
// that match prose, and a scanner that cannot tell `secret: "hunter2"` in a
// README from `client_secret: "..."` in a response is a scanner that reports
// documentation.
var secretCategories = []secretCategory{
	{"AWS Access Key ID", regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`), SeverityCritical, false},
	{"Private Key Block", regexp.MustCompile(`(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----)`), SeverityCritical, true},
	{"GitHub Token", regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,255})\b`), SeverityCritical, false},
	{"Stripe Live Secret Key", regexp.MustCompile(`\b(sk_live_[A-Za-z0-9]{20,})\b`), SeverityCritical, false},
	{"Slack Bot Token", regexp.MustCompile(`\b(xoxb-[0-9A-Za-z-]{10,})\b`), SeverityCritical, false},
	{"Connection String with Credentials", regexp.MustCompile(`(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s:@/]+:([^\s@'"]{4,})@`), SeverityCritical, false},
	{"JWT", regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.+/=-]{10,})\b`), SeverityHigh, true},
	{"Google API Key", regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})\b`), SeverityHigh, false},
	{"Mailgun API Key", regexp.MustCompile(`\b(key-[0-9A-Za-z]{32})\b`), SeverityHigh, false},
	{"Twilio API Key", regexp.MustCompile(`\b(SK[0-9a-f]{32})\b`), SeverityMedium, false},
	{"Bearer Token Literal", regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9-_.~+/]{24,}={0,2})`), SeverityMedium, false},
	{"Hardcoded Password Assignment", regexp.MustCompile(`(?i)\b(?:password|passwd|db[_-]?pass)\s*[:=]\s*["']([^"'\s]{8,})["']`), SeverityHigh, true},
	{"Generic API Key or Secret Assignment", regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret[_-]?key|auth[_-]?token|client[_-]?secret)\s*[:=]\s*["']([A-Za-z0-9_.~+/=-]{24,})["']`), SeverityHigh, true},
}

// publicByDesign are the key names a client-side SDK publishes to every visitor
// on purpose.
//
// They are compared against the *key the value was assigned to*, not against the
// value, so a genuine credential whose own name happens to contain a hint is
// still reported — with the reason stated, which is what lets the operator
// disagree.
var publicByDesign = []string{
	"websitetoken", "sitekey", "site_key", "publickey", "public_key",
	"publishable", "pk_live", "pk_test", "clientid", "client_id",
	"appkey", "app_key", "trackingid", "analyticsid", "gtm", "recaptcha_site",
	"hcaptcha_site", "turnstile_site",
}

// placeholderValues are the filler that stands in for a credential and that no
// deployment ever used. Reporting `your-api-key-here` teaches an operator to
// ignore the rule that finds real keys.
var placeholderValues = []string{
	"your", "example", "changeme", "change_me", "placeholder", "redacted",
	"xxxxx", "todo", "insert", "sample", "dummy", "fake", "test", "notreal",
	"none", "null", "undefined",
}

// structuralPrivilege is the only shape of evidence this module accepts as
// "the token unlocked something".
//
// Two forms, both structural:
//
//   - a JSON object with a privilege-bearing key *at a value position* — the key
//     is followed by a colon and a value, inside braces;
//   - an HTML element whose value attribute carries the token, for a key that
//     names a privilege.
//
// Neither can be satisfied by prose. The word "private" in a sentence has no
// colon after it and is not inside braces. The word "admin" as a link label is
// neither. This is the entire difference between a token that was replayed and a
// page that happened to mention the word "admin".
var jsonPrivilegeKey = regexp.MustCompile(
	`(?i)"(?:role|is_?admin|is_?superuser|permissions?|scopes?|privileges?|entitlements?|is_?staff)"\s*:`)

var htmlPrivilegeValue = regexp.MustCompile(
	`(?i)<input[^>]+value\s*=\s*["'][^"']*["']`)

// Exposure is the credential exposure detector.
type Exposure struct{}

// Name implements Module.
func (Exposure) Name() string { return "exposure" }

// Level implements Module.
func (Exposure) Level() Level { return LevelEndpoint }

// Scan probes one response for credentials.
//
// The order of work is the order of the questions. First: is there a value here
// at all. Second: was it assigned to a key the platform publishes on purpose.
// Third: is it filler. Fourth: can the impact be demonstrated. Everything else
// is reporting.
//
// # Why the baseline is not consulted here
//
// Every other detector in this package compares against a baseline, and for all
// of them the baseline answers one question: did the injection cause this. This
// module sends no injection — it reads a page and asks whether the page contains
// a credential — so the baseline is the same page, byte for byte, and the
// freshness check can never be true. Applying it would suppress every finding
// this detector exists to produce.
//
// What decides a real credential is a different set of questions, and it is what
// the code below asks: is the value assigned to a name the platform publishes, is
// it filler, and does the server accept it.
func (m Exposure) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	resp, err := t.Do(ctx, p.Method, p.URL, nil, false, nil)
	if err != nil {
		return nil
	}
	var out []Finding
	for _, category := range secretCategories {
		if ctx.Err() != nil {
			return out
		}
		match := category.pattern.FindStringSubmatch(resp.Body)
		if match == nil {
			continue
		}
		value := match[1]
		if value == "" {
			continue
		}
		// A credential is reported at its pattern tier first, so a category
		// that cannot be replayed is answered without spending a request. Only
		// the ones that can are taken further.
		if !category.proofRequired {
			verified, proof := replay(ctx, t, p, value)
			if verified != nil {
				out = append(out, *verifiedFinding(p, category, value, proof))
				continue
			}
		}
		finding := classify(p, category, value, resp)
		if finding == nil {
			continue
		}
		out = append(out, *finding)
	}
	return out
}

// classify turns a matched credential into a finding with the tier its evidence
// supports.
func classify(p Point, category secretCategory, value string, resp *Response) *Finding {
	// The key the value was assigned to decides the public-by-design question,
	// and finding it is a look at the text around the match rather than at the
	// value — a real credential under a hint-like key still gets reported.
	if key, ok := assignmentKey(resp.Body, value); ok && isPublicByDesign(key) {
		finding, _ := NewFinding(Spec{
			Module:   "exposure",
			Title:    "Public Client-Side Configuration Value (" + category.name + ")",
			Claimed:  SeverityInfo,
			Tier:     TierPublic,
			Point:    p,
			Payload:  key,
			Evidence: "the value is assigned to " + quoteForEvidence(key) + ", a name the platform publishes to every visitor by design",
			Description: "The value matches the " + category.name + " pattern but is assigned to a name that " +
				"client-side SDK configuration uses. It reaches every browser that loads the page, so its " +
				"presence implies no privilege.",
			Remediation: "None required for this value. Ensure the corresponding private counterpart is never " +
				"shipped to the browser.",
		})
		return &finding
	}
	if isPlaceholder(value) {
		// Silently skipping would leave a hole in the coverage the operator
		// thinks they have, so this is a row — at informational, saying what it
		// is and why it is not a finding.
		finding, _ := NewFinding(Spec{
			Module:   "exposure",
			Title:    "Placeholder Value Matching " + category.name + " (not a credential)",
			Claimed:  SeverityInfo,
			Tier:     TierPublic,
			Point:    p,
			Payload:  redact(value),
			Evidence: "the value is a placeholder (" + quoteForEvidence(redact(value)) + "), not a deployed credential",
			Description: "The pattern matched, but the value is filler of the kind that appears in templates, " +
				"documentation and .env.example files. It is reported so the coverage is visible and is not " +
				"counted as a finding.",
			Remediation: "Remove the placeholder, or keep it — it cannot be used against anything.",
		})
		return &finding
	}
	// A pattern that cannot be replayed to demonstrate impact stays potential
	// no matter what the page says about it.
	if category.proofRequired {
		finding, _ := NewFinding(Spec{
			Module:   "exposure",
			Title:    "Potential " + category.name + " Exposure (impact not demonstrated)",
			Claimed:  category.claimed,
			Tier:     TierPotential,
			Point:    p,
			Payload:  redact(value),
			Evidence: "the " + category.name + " pattern is present; no live use was demonstrated",
			Description: "A value matching the " + category.name + " pattern is present in the response. " +
				"Whether it is live and privileged is unproven: it could be a sample, a placeholder in a " +
				"documented example, or a rotated credential whose service no longer accepts it.",
			Remediation: "Rotate the credential if it is live, and remove the value from client-visible responses.",
		})
		return &finding
	}
	finding, _ := NewFinding(Spec{
		Module:  "exposure",
		Title:   category.name + " Exposure (unverified)",
		Claimed: category.claimed,
		Tier:    TierPotential,
		Point:   p,
		Payload: redact(value),
		Evidence: "the " + category.name + " pattern is present; the credential was not replayed, so no " +
			"privileged access is demonstrated",
		Description: "A value matching the " + category.name + " pattern is returned to the client. The " +
			"pattern is a strong indicator, but severity is not assigned on a pattern match alone: whether " +
			"the credential is live is a separate question with a separate answer.",
		Remediation: "Move the credential server-side. Rotate it if it has been exposed, and audit its use.",
	})
	return &finding
}

// assignmentKey returns the name the value was assigned to, when the body shows
// one.
func assignmentKey(body, value string) (string, bool) {
	index := strings.Index(body, value)
	if index < 0 {
		return "", false
	}
	prefix := body[:index]
	// The nearest of the two conventional separators before the value is the one
	// that assigned it; the search is over the tail of the prefix so a key from
	// a previous field cannot be mistaken for this one's.
	tail := prefix
	if len(tail) > 200 {
		tail = tail[len(tail)-200:]
	}
	colon := strings.LastIndex(tail, ":")
	equals := strings.LastIndex(tail, "=")
	separator := colon
	if equals > separator {
		separator = equals
	}
	if separator < 0 {
		return "", false
	}
	key := strings.TrimSpace(tail[:separator])
	key = strings.Trim(key, `"'`)
	if key == "" || len(key) > 80 {
		return "", false
	}
	return key, true
}

// isPublicByDesign reports whether a key name is one the platform publishes.
func isPublicByDesign(key string) bool {
	lower := strings.ToLower(key)
	for _, hint := range publicByDesign {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// isPlaceholder reports whether a value is filler rather than a credential.
func isPlaceholder(value string) bool {
	lower := strings.ToLower(value)
	for _, hint := range placeholderValues {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// redact shortens a credential so a report can identify it without handing a
// usable secret to everyone the report is forwarded to.
//
// Eight characters from the front and four from the back is enough to tell two
// keys of the same kind apart, which is the question a reader actually has, and
// is not enough to authenticate anywhere.
func redact(value string) string {
	if len(value) <= 16 {
		return value
	}
	return value[:8] + strings.Repeat("*", 6) + value[len(value)-4:]
}

// quoteForEvidence wraps a value in quotes so an empty one is visible in a
// report line rather than trailing off the end of it.
func quoteForEvidence(value string) string { return `"` + value + `"` }

// privilegedStructure reports whether a response shows a token was accepted,
// which is the only evidence that raises an exposure above potential.
//
// It accepts the two structural forms and nothing else. In particular it does
// not accept a bare English word, because a footer reading "private" and a
// replayed credential returning nothing both produce one, and treating that as
// proof is how a public site key becomes a critical finding.
func privilegedStructure(resp *Response, token string) bool {
	if resp == nil {
		return false
	}
	if jsonPrivilegeKey.MatchString(resp.Body) {
		return true
	}
	// An HTML value attribute only counts when the input names a privilege and
	// carries the token, because every form on a login page has a value
	// attribute and most of them are empty.
	if htmlPrivilegeValue.MatchString(resp.Body) && token != "" &&
		strings.Contains(resp.Body, redact(token)) {
		return true
	}
	return false
}

// replay sends the credential back to the same endpoint and returns the
// authenticated response plus the evidence that the token was accepted.
//
// The request is a GET, and it carries the credential in the Authorization
// header, which is where an API key is looked for when one is used at all. No
// other method is tried: a read that changes nothing is the only kind of probe
// this scanner is allowed to make against an endpoint it did not create.
func replay(ctx context.Context, t *Transport, p Point, token string) (*Response, string) {
	anonymous, err := t.Do(ctx, p.Method, p.URL, nil, false, nil)
	if err != nil {
		return nil, ""
	}
	authenticated, err := t.Do(ctx, p.Method, p.URL, nil, false, http.Header{
		"Authorization": {"Bearer " + token},
	})
	if err != nil {
		return nil, ""
	}
	if !verifyReplayed(anonymous, authenticated, token) {
		return nil, ""
	}
	evidence := fmt.Sprintf(
		"the credential was replayed as an Authorization: Bearer header and the server answered differently "+
			"from the anonymous request (status %d vs %d, divergence %.2f) with a privileged payload present",
		authenticated.StatusCode, anonymous.StatusCode,
		Divergence(anonymous.Body, authenticated.Body))
	return authenticated, evidence
}

// verifiedFinding builds the row for a credential whose impact was demonstrated.
func verifiedFinding(p Point, category secretCategory, value, evidence string) *Finding {
	finding, _ := NewFinding(Spec{
		Module:   "exposure",
		Title:    category.name + " Exposure (replay accepted by the server)",
		Claimed:  category.claimed,
		Tier:     TierVerified,
		Point:    p,
		Payload:  redact(value),
		Evidence: evidence,
		Description: "The credential was replayed against the same endpoint and the server answered as though " +
			"it had been accepted, returning data that an anonymous request does not receive. The impact is " +
			"demonstrated rather than inferred from the pattern.",
		Remediation: "Rotate the credential immediately and audit its use. Move it server-side so it is never " +
			"returned to a client.",
	})
	return &finding
}

// verifyReplayed classifies a replay by comparing the anonymous and
// authenticated responses.
//
// Both halves matter. A status difference alone is a redirect or a rate limit. A
// body difference alone is a rotating request id. What makes a replay convincing
// is that the *same* request with a *different* credential answers differently in
// a way that shows private data, and the structural check above is what decides
// the last part.
func verifyReplayed(anonymous, authenticated *Response, token string) bool {
	if anonymous == nil || authenticated == nil {
		return false
	}
	// A 5xx on the authenticated request says nothing about the token; the
	// server failed for its own reasons.
	if authenticated.StatusCode >= 500 {
		return false
	}
	if anonymous.StatusCode == authenticated.StatusCode &&
		Divergence(anonymous.Body, authenticated.Body) < 0.03 {
		// Same status, essentially the same page: the server ignored the token.
		return false
	}
	return privilegedStructure(authenticated, token)
}
