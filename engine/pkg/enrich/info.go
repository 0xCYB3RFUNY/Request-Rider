package enrich

import (
	"regexp"
	"strings"
)

// InfoKind names a class of incidental intelligence found in a page body.
type InfoKind string

const (
	// InfoEmail is an address written in the page. It is a finding and not
	// noise: an address in an HTML comment or a config dump names a person or a
	// system that the site's own JS never intended to publish.
	InfoEmail InfoKind = "email"
	// InfoHTMLComment is a commented-out block. Comments are where a
	// deployment path, a disabled check and a past credential live, because
	// nobody reviews them after writing them.
	InfoHTMLComment InfoKind = "html_comment"
	// InfoInternalIP is an RFC1918 address or an IPv6 unique-local address. On
	// a public page it is a leak of the internal topology.
	InfoInternalIP InfoKind = "internal_ip"
	// InfoIPv4 is any dotted-quad, public or private.
	InfoIPv4 InfoKind = "ipv4"
	// InfoMarketingTag is a third-party analytics or tag-manager identifier. It
	// answers a question the map otherwise cannot: which vendors can see this
	// page, and therefore whose JavaScript runs with the site's cookies.
	InfoMarketingTag InfoKind = "marketing_tag"
	// InfoSocialLink is a profile link to a social platform.
	InfoSocialLink InfoKind = "social_link"
	// InfoCommentedCredential is an assignment-shaped credential inside an HTML
	// comment — the specific case where the two findings above intersect.
	InfoCommentedCredential InfoKind = "commented_credential"
)

// Info is one incidental finding, with the value and where it was.
type Info struct {
	Kind  InfoKind `json:"kind"`
	Value string   `json:"value"`
	Line  int      `json:"line"`
}

// infoRule pairs a label with the expression that finds it.
type infoRule struct {
	kind InfoKind
	re   *regexp.Regexp
}

// infoRules is the incidental-intelligence rule set.
//
// Port of the capability, not the code: `edoardottt/cariddi`
// (`pkg/scanner/info.go`, commit 5ae392d2f064bc6e3a59ed999e337c4a03f4e9e4) is
// GPL-3.0, so the four upstream expressions are re-derived here rather than
// copied, and four more classes are added on top of them (marketing tags,
// social links, commented credentials). Each addition is its own row in
// `cariddi_reconciliation.md`.
//
// Two upstream decisions are carried over on purpose because they are correct:
//
//   - the internal-IP class matches `172.x`, `192.168.x`, `10.x` and
//     `fe80::`-`feff::`, and *not* `127.x`. A loopback address in a page is
//     almost always a developer's own note, while an RFC1918 address is a
//     router that exists.
//   - the upstream table keeps two rules commented out — a BTC address
//     regex and a base64-JSON regex — with the reason "too many false
//     positives". A commented-out rule is not coverage, so it is not counted
//     as coverage here either; the verdicts say so.
var infoRules = []infoRule{
	{InfoEmail, regexp.MustCompile(
		`(?i)\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\b`)},
	{InfoHTMLComment, regexp.MustCompile(
		`(?s)<!--(.*?)-->`)},
	{InfoInternalIP, regexp.MustCompile(
		`\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3})\b|\b[fF][eE][89aAbBcCdDeEfF][0-9a-fA-F]{0,3}:[0-9a-fA-F:]*`)},
	{InfoIPv4, regexp.MustCompile(
		`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`)},
	{InfoMarketingTag, regexp.MustCompile(
		`(?i)\b(?:UA-\d{4,10}-\d|GTM-[A-Z0-9]{4,10}|G-[A-Z0-9]{8,12}|AW-\d{9,12}|UA-\d{6,}-(?:[0-9]{1,3}|[A-Z0-9]{3,6})|ym-\d{6,}|_ga|_gid|_gcl_au|fbq\s*\(|googletagmanager\.com|google-analytics\.com|connect\.facebook\.net|static\.hotjar\.com|mc\.hotjar\.com|matomo\.js|piwik\.js|segment\.io|api\.mixpanel\.com|clarity\.ms|hm\.baidu\.com|cnzz\.com|metrika)\b`)},
	{InfoSocialLink, regexp.MustCompile(
		`(?i)\b(?:https?://)?(?:www\.)?(?:facebook\.com|fb\.com|twitter\.com|x\.com|instagram\.com|linkedin\.com|github\.com|gitlab\.com|youtube\.com|youtu\.be|t\.me|telegram\.me|wa\.me|whatsapp\.com|reddit\.com|pinterest\.com|tiktok\.com|vk\.com|ok\.ru|rutube\.ru|dzen\.ru|habr\.com)\b`)},
	{InfoCommentedCredential, regexp.MustCompile(
		`(?i)\b(?:api[_-]?key|secret|password|passwd|pwd|token|access[_-]?key|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*["']?([A-Za-z0-9/+_\-]{8,})["']?`)},
}

// infoRuleOf returns the expression for a kind, or nil.
//
// Lookup by kind rather than by index: the table is append-only in practice and
// an index that silently starts pointing at a different rule is the kind of
// defect that only shows up as a wrong finding.
func infoRuleOf(kind InfoKind) *regexp.Regexp {
	for _, rule := range infoRules {
		if rule.kind == kind {
			return rule.re
		}
	}
	return nil
}

// FindInfo runs every incidental rule over body and returns the hits, one entry
// per occurrence, ordered by line then by rule order.
//
// Comments are scanned twice on purpose: once as a block, so the analyst sees
// that a comment exists and where, and once through the credential rule, so a
// token inside a comment is reported as the thing it is rather than as inert
// text. Reporting the comment block alone would hide the only part that matters.
func FindInfo(body string) []Info {
	if strings.TrimSpace(body) == "" {
		return nil
	}
	lines := strings.Split(body, "\n")
	var out []Info
	seen := make(map[string]bool)
	for _, rule := range infoRules {
		for i, line := range lines {
			for _, value := range rule.re.FindAllString(line, -1) {
				trimmed := strings.TrimSpace(value)
				if trimmed == "" {
					continue
				}
				// An internal address is also an IPv4 address. Reporting both
				// would double every private address in the report, so the
				// narrower class wins and the broader one stands down.
				if rule.kind == InfoIPv4 {
					if internalIPRe.MatchString(trimmed) {
						continue
					}
				}
				key := string(rule.kind) + "\x00" + trimmed + "\x00" + itoa(i+1)
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, Info{Kind: rule.kind, Value: trimmed, Line: i + 1})
			}
		}
	}
	sortInfos(out)
	return out
}

var internalIPRe = regexp.MustCompile(`\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3})\b|\b[fF][eE][89aAbBcCdDeEfF][0-9a-fA-F]{0,3}:[0-9a-fA-F:]*`)

// CommentBodies returns the text inside every HTML comment, in document order.
// The CSRF and credential analysers read comments through this rather than
// re-implementing the comment scan, so there is one definition of "a comment"
// in the package.
func CommentBodies(body string) []string {
	commentRe := infoRuleOf(InfoHTMLComment)
	if commentRe == nil {
		return nil
	}
	var out []string
	for _, match := range commentRe.FindAllStringSubmatch(body, -1) {
		if len(match) < 2 {
			continue
		}
		out = append(out, match[1])
	}
	return out
}

func sortInfos(infos []Info) {
	for i := 1; i < len(infos); i++ {
		item := infos[i]
		j := i - 1
		for j >= 0 && (infos[j].Line > item.Line ||
			(infos[j].Line == item.Line && infos[j].Kind > item.Kind)) {
			infos[j+1] = infos[j]
			j--
		}
		infos[j+1] = item
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for v > 0 {
		pos--
		buf[pos] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[pos:])
}
