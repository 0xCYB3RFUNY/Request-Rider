package enrich

import (
	"net/http"
	"strings"
)

// Page is everything the analysers found on one crawled exchange.
//
// It is one struct rather than four separate maps because the crawler publishes
// a page as a single record on the first poll, and four separately-attached maps
// would let a client see a page with some analyses and without others depending
// on nothing more than which attachment ran first.
type Page struct {
	// NotableFiles are discovered URLs whose extension ranks them.
	NotableFiles []NotableFile `json:"notable_files,omitempty"`
	// Patterns are the pattern hits, per occurrence.
	Patterns []Matches `json:"patterns,omitempty"`
	// Info is the incidental intelligence: emails, comments, addresses, tags.
	Info []Info `json:"info,omitempty"`
	// References are the document's href/src/action values, classified.
	References []Reference `json:"references,omitempty"`
	// ExternalHosts are the hostnames the page talks to that are not its own.
	ExternalHosts []string `json:"external_hosts,omitempty"`
	// Subdomains are the hosts under the crawled site's own registrable domain
	// that this one page already references.
	Subdomains []string `json:"subdomains,omitempty"`
	// CSRF is the form verdict, omitted for non-HTML bodies.
	CSRF *CSRFReport `json:"csrf,omitempty"`
	// PatternCounts is the per-pattern tally for the status line.
	PatternCounts map[string]int `json:"pattern_counts,omitempty"`
	// Secrets is the vendor-rule verdict: accepted findings, and the matches
	// that were thrown away with the reason for each.
	Secrets *SecretScan `json:"secrets,omitempty"`
}

// Counts summarises a page for the status line, so the UI does not have to walk
// the slices and so the numbers in the table, the report and the export come
// from one place.
type Counts struct {
	NotableFiles int `json:"notable_files"`
	Patterns     int `json:"patterns"`
	Info         int `json:"info"`
	Hosts        int `json:"hosts"`
	Subdomains   int `json:"subdomains"`
	CSRFIssues   int `json:"csrf_issues"`
	ReusedTokens int `json:"reused_tokens"`
	// Secrets and RejectedSecrets are counted apart: "3 keys found" and
	// "3 keys found, 210 matches rejected" are different things to read, and one
	// number cannot say which.
	Secrets         int `json:"secrets"`
	RejectedSecrets int `json:"rejected_secrets"`
	SecretRulesRun  int `json:"secret_rules_run"`
}

// Counts reduces the page to the numbers the UI shows.
func (p Page) Counts() Counts {
	c := Counts{
		NotableFiles: len(p.NotableFiles),
		Patterns:     len(p.Patterns),
		Info:         len(p.Info),
		Hosts:        len(p.ExternalHosts),
		Subdomains:   len(p.Subdomains),
	}
	if p.CSRF != nil {
		c.CSRFIssues = len(p.CSRF.Issues)
		c.ReusedTokens = len(p.CSRF.Reused)
	}
	if p.Secrets != nil {
		c.Secrets = len(p.Secrets.Findings)
		c.RejectedSecrets = len(p.Secrets.Rejected)
		c.SecretRulesRun = p.Secrets.RulesRun
	}
	return c
}

// Options control which analysers run.
//
// The defaults run everything. An operator who wants the map fast can turn the
// pattern set off without losing the extension ranking, and the choice is
// visible in the report — a page analysed with patterns off says so, instead of
// reporting "0 patterns" as if the page were clean.
type Options struct {
	// Patterns runs the gf-style pattern sets. Empty means all of them.
	Patterns []string
	// SkipPatterns disables the pattern stage entirely.
	SkipPatterns bool
	// SkipInfo disables the incidental-intelligence stage.
	SkipInfo bool
	// SkipCSRF disables the form assessment.
	SkipCSRF bool
	// SkipSecrets disables the vendor rule set.
	SkipSecrets bool
	// IncludeNoisy runs the rules upstream marks as producing false positives.
	// They are excluded by default and counted apart when included, because a
	// rule the analyst did not ask for must not inflate the count they did.
	IncludeNoisy bool
	// MinFileSeverity is the lowest extension severity to report.
	MinFileSeverity int
	// SameSiteCookies is what the response's Set-Cookie headers actually said.
	SameSiteCookies bool
	// OriginHost is the host being crawled; references to any other host are
	// external. Empty disables the external-host report.
	OriginHost string
}

// Analyse runs the analysers over one crawled exchange.
//
// `contentType` decides which stage runs: a pattern scan over a PNG is a scan
// for text that is not there, and the counts it produces would read as "this
// page has no findings" when the truth is "this page was never read".
func Analyse(pageURL string, body []byte, header http.Header, contentType string, opts Options) Page {
	var out Page
	text := string(body)
	isMarkup := isTextualContentType(contentType)

	if opts.MinFileSeverity == 0 {
		opts.MinFileSeverity = SeverityLow
	}

	if isMarkup && !opts.SkipInfo {
		out.Info = FindInfo(text)
	}

	if isMarkup && !opts.SkipCSRF {
		report := CSRFAssess(text, opts.SameSiteCookies)
		out.CSRF = &report
	}

	if isMarkup {
		refs := ExtractReferences(text)
		out.References = refs
		fetchable := Fetchable(refs)
		out.NotableFiles = NotableFiles(fetchable, opts.MinFileSeverity)
		out.ExternalHosts = externalHosts(refs, opts.OriginHost)
		out.Subdomains = Subdomains(refs, opts.OriginHost)
	}

	if isMarkup && !opts.SkipSecrets {
		scan := ScanSecrets(text, opts.IncludeNoisy)
		out.Secrets = &scan
	}

	if !opts.SkipPatterns {
		out.Patterns = Match(opts.Patterns, text)
		out.PatternCounts = CountByPattern(out.Patterns)
	}
	return out
}

// isTextualContentType reports whether a body is worth reading as text.
//
// A `charset` on the wrong type is still text — servers lie about it, and a
// mislabelled JavaScript file is the most common way one. So the decision is made
// on the MIME type alone and `application/octet-stream` is treated as text when
// the bytes look like text, rather than discarded.
func isTextualContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	if ct == "" {
		return true
	}
	switch {
	case strings.Contains(ct, "text/"):
		return true
	case strings.Contains(ct, "json"),
		strings.Contains(ct, "xml"),
		strings.Contains(ct, "javascript"),
		strings.Contains(ct, "ecmascript"),
		strings.Contains(ct, "x-www-form-urlencoded"),
		strings.Contains(ct, "yaml"),
		strings.Contains(ct, "graphql"):
		return true
	}
	return false
}

// externalHosts lists the hostnames the page references that are not the crawled
// one. The origin's own host is filtered by the caller-supplied value; without
// it every reference is reported, which is the honest answer when we were not
// told where the crawl started.
func externalHosts(refs []Reference, originHost string) []string {
	all := Hosts(refs)
	if originHost == "" {
		return all
	}
	want := strings.ToLower(originHost)
	if h, _, found := strings.Cut(want, ":"); found {
		want = h
	}
	out := make([]string, 0, len(all))
	for _, host := range all {
		if host == want {
			continue
		}
		out = append(out, host)
	}
	return out
}
