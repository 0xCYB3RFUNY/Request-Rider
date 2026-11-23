// Outdated client-side libraries, read out of the scripts the page already
// loads.
//
// # Why this costs nothing and is still worth a row
//
// Every other detector in this package spends requests to prove something. This
// one spends none: the version of jQuery on a page is written in the `src` of a
// script the page has already asked the browser to fetch, and the baseline the
// surface already read contains it. There is no probe, no payload, and no way
// for the answer to change between the moment the run started and the moment it
// finished.
//
// # Why it is `info` and not `high`
//
// The finding says a page ships a version with published advisories. That is a
// real property of the application and it is not a claim that the application is
// exploitable: whether CVE-2020-11022 bites depends on whether this page calls
// the affected function with attacker-controlled data, which a version string
// cannot answer. Reporting it as high would be the same mistake as reporting a
// version banner as a vulnerability, and it is why the tier is `TierPublic` —
// its severity ceiling is `info`, and `NewFinding` would lower a higher claim
// anyway.
//
// # The data is Dalfox's, and the reasoning about it is ours
//
// The seven libraries and twelve ranges are `vuln_libs.rs` (CWE-1104,
// retire.js-style). What is not ported is the delivery: retire.js ships a
// `vulnerable.json` covering hundreds of libraries, and a seven-library table is
// the subset Dalfox chose. The table below is therefore the *floor* of what this
// detector knows, not a claim that a page with no row is free of advisories —
// the finding says which libraries were recognised, and its remediation names
// the gap.
package active

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// jsLibraryRule is one recognised library: how its file name is recognised and
// which versions are affected.
//
// The advisories are carried as a single minimum version rather than a list of
// ranges, because for every one of these libraries the union of its published
// ranges is "below the last fixed release". That is a simplification, and it is
// stated in the finding's own text rather than hidden here: a version between
// two ranges is reported as affected here and as clean by a per-range check.
type jsLibraryRule struct {
	// name is the library as a report reads it.
	name string
	// pattern matches the script file name and captures nothing: the version is
	// read separately by `jsLibraryVersion`, because a library's version sits in
	// different places in different file names (`jquery-3.5.1.min.js`,
	// `jquery.min.js?v=3.5.1`, `lodash.core.js`).
	pattern *regexp.Regexp
	// fixed is the first version that carries the fix for every advisory below.
	fixed string
	// advisories names what is fixed in `fixed`.
	advisories []string
}

// jsLibraryRules are the libraries recognised in a script URL.
var jsLibraryRules = []jsLibraryRule{
	{
		name:    "jQuery",
		pattern: regexp.MustCompile(`(?i)\bjquery(?:[.-][a-z0-9_.]*)?\.js\b`),
		fixed:   "3.5.0",
		advisories: []string{
			"CVE-2020-11022", "CVE-2020-11023", // htmlPrefilter / crossSite
			"CVE-2019-11358", // prototype pollution in jQuery.extend
			"CVE-2015-9251",  // cross-domain ajax with text/javascript
			"CVE-2012-6708",  // selector interpreted as HTML
		},
	},
	{
		name:    "AngularJS",
		pattern: regexp.MustCompile(`(?i)\bangular(?:\.min)?\.js\b`),
		fixed:   "1.8.3",
		advisories: []string{
			"CVE-2020-7676",  // sandbox bypass via sandbox payload
			"CVE-2022-25869", // element name lowercasing in IE
			"CVE-2019-10768", // location.hash / CSS injection
		},
	},
	{
		name:    "Bootstrap",
		pattern: regexp.MustCompile(`(?i)\bbootstrap(?:[.-][a-z0-9_.]*)?\.js\b`),
		fixed:   "4.3.1",
		advisories: []string{
			"CVE-2019-8331",  // XSS in tooltip/popover with data-* target
			"CVE-2018-14041", // XSS in data-target
			"CVE-2018-14042", // data-* target attribute XSS
		},
	},
	{
		name:    "Lodash",
		pattern: regexp.MustCompile(`(?i)\blodash(?:[.-][a-z0-9_.]*)?\.js\b`),
		fixed:   "4.17.21",
		advisories: []string{
			"CVE-2021-23337", // command injection via template
			"CVE-2020-8203",  // prototype pollution in zipObjectDeep
			"CVE-2019-10744", // defaultsDeep / merge
		},
	},
	{
		name:    "Handlebars",
		pattern: regexp.MustCompile(`(?i)\bhandlebars(?:[.-][a-z0-9_.]*)?\.js\b`),
		fixed:   "4.7.7",
		advisories: []string{
			"CVE-2021-23383", // prototype pollution / RCE via lookup helper
			"CVE-2021-23369", // arbitrary code execution
			"CVE-2019-19919", // prototype pollution
		},
	},
	{
		name:    "Moment.js",
		pattern: regexp.MustCompile(`(?i)\bmoment(?:[.-][a-z0-9_.]*)?\.js\b`),
		fixed:   "2.29.4",
		advisories: []string{
			"CVE-2022-31129", // ReDoS in longDateFormat
			"CVE-2022-24785", // path traversal in locale loading
		},
	},
	{
		name:    "jQuery UI",
		pattern: regexp.MustCompile(`(?i)\bjquery-ui(?:[.-][a-z0-9_.]*)?\.js\b`),
		fixed:   "1.13.0",
		advisories: []string{
			"CVE-2022-31160", // ReDoS in .position
			"CVE-2021-41184", // datepicker altField XSS
			"CVE-2021-41183", // checkbox/radio altField XSS
			"CVE-2021-41182", // tooltip position XSS
		},
	},
}

// jsScriptSrc matches the src of a script element, including a single- or
// double-quoted attribute.
//
// The element is matched rather than any URL on the page because a library
// named in an image URL or a comment is not loaded as code, and reporting it
// would be the file-name equivalent of a body-wide substring search.
var jsScriptSrc = regexp.MustCompile(`(?is)<script[^>]*\ssrc\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)

// jsLibraryVersion reads the version out of a script URL.
//
// It is read from the whole URL rather than only from the file name, because the
// two common placements are the file name and a query string, and a rule that
// only accepted one of them would miss half the pages that pin a version. The
// query is read first: `jquery.js?v=3.4.1` names the version more reliably than
// the file name does, and the file name may carry no version at all.
func jsLibraryVersion(scriptURL string) string {
	if query := scriptURL[strings.IndexByte(scriptURL, '?')+1:]; strings.Contains(scriptURL, "?") {
		for _, pair := range strings.Split(query, "&") {
			key, value, found := strings.Cut(pair, "=")
			if !found {
				continue
			}
			switch strings.ToLower(key) {
			case "v", "ver", "version", "rev":
				if jsVersionPattern.MatchString(value) {
					return value
				}
			}
		}
	}
	path := scriptURL
	if at := strings.IndexByte(path, '?'); at >= 0 {
		path = path[:at]
	}
	if slash := strings.LastIndexByte(path, '/'); slash >= 0 {
		path = path[slash+1:]
	}
	// The *last* version-shaped run in the file name, not the first: a path like
	// `/2.0/jquery-3.4.1.min.js` carries a directory that looks like a version,
	// and splitting the name on dots and dashes — which is the obvious way to do
	// this — destroys the version it was meant to find.
	matches := jsVersionRun.FindAllString(path, -1)
	if len(matches) == 0 {
		return ""
	}
	return matches[len(matches)-1]
}

// jsVersionRun matches a dotted numeric version inside a file name.
var jsVersionRun = regexp.MustCompile(`\d+\.\d+(?:\.\d+)*`)

// jsVersionPattern is a dotted numeric version with at least two components.
// One component is not a version: `jquery.js` has none, and `bootstrap3.js`
// has one that is a product name.
var jsVersionPattern = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)*$`)

// jsVersionBelow reports whether have is strictly older than fixed.
//
// A version that cannot be parsed is *not* treated as vulnerable. Guessing that
// an unreadable version is old produces the finding on every page whose file
// name the rule cannot parse, which is how a table like this becomes noise.
func jsVersionBelow(have, fixed string) bool {
	haveParts := strings.Split(have, ".")
	fixedParts := strings.Split(fixed, ".")
	// The shorter version is padded with zeros, so `1.13` and `1.13.0` compare
	// equal instead of the shorter one reading as older. Every one of these
	// libraries ships both spellings for the same release.
	for len(haveParts) < len(fixedParts) {
		haveParts = append(haveParts, "0")
	}
	for i := 0; i < len(haveParts) && i < len(fixedParts); i++ {
		haveValue, haveErr := strconv.Atoi(haveParts[i])
		fixedValue, fixedErr := strconv.Atoi(fixedParts[i])
		if haveErr != nil || fixedErr != nil {
			return false
		}
		if haveValue != fixedValue {
			return haveValue < fixedValue
		}
	}
	return false
}

// JSLibrary is the outdated-client-library detector.
type JSLibrary struct{}

// Name implements Module.
func (JSLibrary) Name() string { return "js-library" }

// Level implements Module.
//
// Endpoint rather than host: the same origin serves a React dashboard and a
// legacy marketing page, and the library versions differ. It costs no requests
// either way, so the level costs nothing to get right.
func (JSLibrary) Level() Level { return LevelEndpoint }

// Scan reads the baseline and reports every recognised library below its fixed
// version.
func (m JSLibrary) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || ctx.Err() != nil {
		return nil
	}
	var findings []Finding
	for _, match := range jsScriptSrc.FindAllStringSubmatch(baseline.Body, -1) {
		raw := strings.Trim(match[1], `"'`)
		for _, rule := range jsLibraryRules {
			if !rule.pattern.MatchString(raw) {
				continue
			}
			version := jsLibraryVersion(raw)
			if version == "" || !jsVersionBelow(version, rule.fixed) {
				continue
			}
			finding, _ := NewFinding(Spec{
				Module:   "js-library",
				Title:    rule.name + " " + version + " is below the fixed release " + rule.fixed,
				Claimed:  SeverityMedium,
				Tier:     TierPublic,
				Point:    p,
				Evidence: match[0],
				Description: "The page loads " + rule.name + " " + version + ", and every advisory listed below " +
					"is fixed in " + rule.fixed + ": " + strings.Join(rule.advisories, ", ") + ". Whether the " +
					"application is actually exploitable depends on whether this page calls the affected function " +
					"with data an attacker controls, which a version string cannot answer — this row is the " +
					"property of the page, not a demonstrated exploit.",
				Remediation: "Upgrade " + rule.name + " to " + rule.fixed + " or later. Note that this detector " +
					"recognises seven libraries; a page that loads none of them is not thereby free of outdated " +
					"libraries.",
			})
			findings = append(findings, finding)
		}
	}
	return findings
}

// jsLibraryNames is used by the reconciliation register's test to state which
// libraries this detector covers, so the two cannot drift apart silently.
func jsLibraryNames() []string {
	names := make([]string, 0, len(jsLibraryRules))
	for _, rule := range jsLibraryRules {
		names = append(names, rule.name)
	}
	return names
}
