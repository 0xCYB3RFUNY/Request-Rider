// Personal data and secrets published in responses: the grep family.
//
// # What upstream contributes, and why it is mostly a list of regexes
//
// Arachni ships this as `components/checks/passive/grep/` — seventeen checks, each
// one a pattern over the response body: `emails`, `private_ip`, `ssn`,
// `credit_card`, `cvs_svn_users`, `html_objects`, `form_upload`, `captcha`,
// `mixed_resource`, `password_autocomplete`, `unencrypted_password_forms`, and
// the cookie and header hardening ones that this package's misconfiguration
// detector already owns. Eagle ships the same idea as `plugins/spider.py`'s
// `get_secrets`, which is twenty named credential regexes.
//
// BlackWidow contributes the same capability from the crawler side: collect the
// email addresses and phone numbers a site publishes. That is collection rather
// than detection, and the project already has a place for it — the OSINT graph. So
// BlackWidow's two rows are recorded as carried by that layer rather than ported a
// second time here, which is what `AGENTS.md` calls a parallel path.
//
// What is ported here is the part that is a *finding*: data a page hands to every
// visitor which is not meant for every visitor.
//
// # The difference between a collector and a detector, and why it matters
//
// A crawler printing "found 40 email addresses" has done its job. This row says
// something a reader must act on, and the action differs per category:
//
//   - a card number or a national identity number is a compliance incident;
//   - an internal address or hostname is an internal network map published on the
//     web, and it names the systems an attacker should try first;
//   - a private IP in a response is evidence that a request is answered by
//     something that believes it is on an internal network, which is the
//     precondition for a whole class of SSRF misjudgement;
//   - a private key, a credential or an API token is the exposure detector's row
//     and not this one's, because that detector *verifies* the credential by
//     replaying it and this one cannot.
//
// # The verification bar, stated so the tiers are not mystery
//
// A national identity number, a card number and a private key block all have fixed
// prefixes and fixed lengths, so a pattern can be both specific and wrong — a page
// of test data matches them by accident. So every pattern here is anchored to the
// thing that makes it a disclosure rather than to the number alone: an SSN beside
// a label, a card beside its brand, an internal address inside a URL or a host
// header rather than in prose. A number with nothing identifying it around it is
// not reported, and the reason is in the row.
package active

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// piiCategory is one kind of published data.
type piiCategory struct {
	// name is the report label.
	name string
	// claimed is the severity the disclosure would support.
	claimed Severity
	// pattern is the matcher.
	pattern *regexp.Regexp
	// context is a second pattern that must also match. A category with no
	// context accepts a bare match; a category with one requires the data to be
	// presented, not merely to be present.
	context *regexp.Regexp
	// why says what the exposure is.
	why string
	// redact replaces the match in the evidence, so the report does not become a
	// second copy of the data it is reporting. This is not politeness: the report
	// is exported and shared, and a report that reproduces the card numbers it
	// found is a report that leaks them again.
	redact bool
}

// piiCategories is the carried pattern set.
//
// The context patterns are the interesting part of this table. `ssn` alone matches
// every American test fixture ever written, and `credit_card` alone matches every
// payment page, so each of those requires a label within a short distance of the
// number. `privateIP` requires the address to be embedded in a URL or a host line,
// because an address in prose is usually documentation *about* a private range
// rather than a leak of one.
var piiCategories = []piiCategory{
	{
		name: "email address", claimed: SeverityLow,
		pattern: regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`),
		why: "an address the site publishes to every visitor, usable for spam and for guessing the " +
			"naming convention that turns one address into a hundred",
	},
	{
		name: "internal hostname", claimed: SeverityLow,
		pattern: regexp.MustCompile(`(?i)\b(?:[a-z0-9\-]+\.)+(?:internal|corp|lan|intranet|local)\b`),
		why: "an internal name published on the public web, which maps the deployment's own naming and " +
			"often resolves from inside the network to a host that does not resolve from outside",
	},
	{
		name: "RFC 1918 address", claimed: SeverityLow,
		context: regexp.MustCompile(`(?i)(https?://|host|server|upstream|backend|internal|proxy|addr)`),
		pattern: regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`),
		why: "a private address served from a public endpoint, which both publishes the internal " +
			"topology and shows that something answering on the public interface believes it is " +
			"answering from inside",
	},
	{
		name: "loopback address", claimed: SeverityLow,
		context: regexp.MustCompile(`(?i)(https?://|host|server|upstream|backend|internal|proxy|addr)`),
		pattern: regexp.MustCompile(`\b127\.0\.0\.1\b|\blocalhost\b`),
		why: "a loopback address served from a public endpoint, which means the response was produced by " +
			"a component that resolved a host against itself — the same misconfiguration that makes an " +
			"SSRF filter useless",
	},
	{
		name: "US social security number", claimed: SeverityHigh,
		context: regexp.MustCompile(`(?i)(ssn|social\s*security|ss#|ss\s+number)`),
		pattern: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		redact:  true,
		why: "a national identity number presented beside a field that names it, which is a " +
			"compliance incident rather than a cosmetic disclosure",
	},
	{
		name: "payment card number", claimed: SeverityHigh,
		context: regexp.MustCompile(`(?i)(card|credit|cc|pan|account\s*number|payment|visa|mastercard|amex)`),
		pattern: regexp.MustCompile(`\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}\b`),
		redact:  true,
		why: "a card-shaped number presented beside a field that names it; no luhn check is applied " +
			"because a random sixteen digits that happens to be beside the word \"card\" is still a " +
			"disclosure worth a look, and the redaction means the report does not repeat it",
	},
	{
		name: "private key material", claimed: SeverityCritical,
		pattern: regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |PGP )?PRIVATE KEY`),
		redact:  true,
		why: "a private key served in a response, which is not a disclosure but a total loss of " +
			"every secret the key protects",
	},
	{
		name: "credentialed URL", claimed: SeverityMedium,
		pattern: regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.\-]*://[^\s/:@]{1,64}:[^\s/:@]{1,64}@`),
		redact:  true,
		why: "a URL carrying a password in its userinfo part, which is written to access logs, " +
			"browser history and proxy logs wherever it is rendered",
	},
	{
		name: "phone number", claimed: SeverityInfo,
		pattern: regexp.MustCompile(`\+?\d{1,3}[\s.\-]?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b`),
		why: "a phone number published to every visitor, which is ordinary for a contact page and " +
			"worth nothing beyond enumeration",
	},
}

// piiMatchLimit bounds how many distinct values one category reports.
//
// It is a reporting limit and not a detection limit: every match is counted and the
// count is reported, so a page with four hundred addresses says four hundred rather
// than saying three and looking like three was all of them. This is the same rule
// the header aggregation in `detect_misconfig.go` follows, and for the same reason.
const piiMatchLimit = 3

// PII is the published personal data detector.
type PII struct{}

// Name implements Module.
func (PII) Name() string { return "pii" }

// Level implements Module.
func (PII) Level() Level { return LevelEndpoint }

// Scan probes one endpoint.
func (m PII) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || strings.TrimSpace(baseline.Body) == "" {
		return nil
	}
	// Only HTML and plain text are read. A stylesheet, an image or a font has no
	// prose in it, so running nine regular expressions over a font to find an email
	// address is work that can only return nothing.
	if !piiReadable(baseline.HeaderValue("Content-Type"), p.URL) {
		return nil
	}
	var out []Finding
	for _, category := range piiCategories {
		if ctx.Err() != nil {
			return nil
		}
		if finding := piiFinding(category, p, baseline.Body); finding != nil {
			out = append(out, *finding)
		}
	}
	return out
}

// piiReadable reports whether a response is the kind that carries prose.
func piiReadable(contentType, raw string) bool {
	lower := strings.ToLower(contentType)
	if lower == "" {
		// No declared type. The path is used instead, because an application that
		// serves text with no Content-Type is common enough that refusing to read
		// it would lose real findings.
		lower = strings.ToLower(raw)
	}
	for _, marker := range []string{"text/", "json", "xml", "javascript"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// piiFinding builds one row for one category.
//
// The values are sorted and deduplicated so two runs over the same page produce the
// same row, and only the first few are shown with the real count beside them — a
// report that listed eight of four hundred reads as if eight were published.
func piiFinding(category piiCategory, p Point, body string) *Finding {
	if category.context != nil && !category.context.MatchString(body) {
		return nil
	}
	matches := category.pattern.FindAllString(body, -1)
	if len(matches) == 0 {
		return nil
	}
	unique := map[string]bool{}
	var values []string
	for _, match := range matches {
		if unique[match] {
			continue
		}
		unique[match] = true
		values = append(values, match)
	}
	sort.Strings(values)
	if len(values) == 0 {
		return nil
	}
	shown := values
	if len(values) > piiMatchLimit {
		shown = values[:piiMatchLimit]
	}
	evidence := fmt.Sprintf("%d distinct match(es), beginning: %s", len(values), strings.Join(shown, ", "))
	if category.redact {
		// The evidence keeps the shape and drops the value. A shared report that
		// reproduces the card numbers it found is a second copy of the incident,
		// and the count above is what the reader actually needs.
		evidence = fmt.Sprintf("%d distinct match(es); values withheld from this report", len(values))
	}
	finding, _ := NewFinding(Spec{
		Module:   "pii",
		Title:    fmt.Sprintf("Published %s (%d distinct)", category.name, len(values)),
		Claimed:  category.claimed,
		Tier:     TierVerified,
		Point:    p,
		Payload:  "GET " + p.URL,
		Evidence: evidence,
		Description: "The response publishes " + category.why + ". The row is a finding rather than a " +
			"collection note because the value reaches every visitor unauthenticated; whether that is " +
			"intended is a question for the owner of the data, and the count above is the number they need " +
			"to answer it.",
		Remediation: "Serve personal data only to the account it belongs to, and move anything that has no " +
			"reason to be on a public page into a response that requires authentication.",
	})
	return &finding
}
