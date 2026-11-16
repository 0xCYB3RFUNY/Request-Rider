// Product fingerprinting: what is this thing, which version, and is that version
// still supported.
//
// # Why this module exists when the report is a vulnerability report
//
// The rest of this package reports things that were demonstrated: a database
// answered, a file came back, a marker echoed. This one answers a question that
// comes *before* those — what software is answering at all, and has anyone
// stopped fixing it.
//
// That question has an answer in the response the scanner already has. A server
// that writes `Apache/2.4.49` into `Server`, or `PHP/7.4.33` into
// `X-Powered-By`, has published the exact version of the two components an
// attacker looks up first. Nothing else in this package reads that, and the
// report had no way to say "this finding exists because the target runs a version
// with a published advisory" — which is exactly the sentence a finding about an
// outdated component is made of.
//
// The fields that would carry it were already here and empty. `Spec.Version`,
// `Spec.VersionSource`, `Finding.Version`, `Finding.VersionSource` and the
// `UnverifiedPatch` state that `NewFinding` sets from them had no producer: a
// grep for `Version:` across the detectors found nothing. This module is that
// producer. `severity.go` already named the source strings this writes —
// `banner:Server`, `meta:generator` — which is the tell that the contract was
// written for this and the detector was the piece left out.
//
// # Why a version alone is not a finding
//
// "This server runs nginx" is not a vulnerability, and a row saying so teaches an
// operator to dismiss the module that found it three rows later. So a product is
// only reported when it is *actionable*: either the version it published is below
// a floor past which the vendor stopped shipping security fixes, or the fact
// that the version is published at all is the finding. A product identified with
// no version, or a version with no known floor, produces no row. `Fingerprint`
// is not in the report, and that is the intended behaviour rather than a gap.
//
// # Why the EOL table is small
//
// Every row here is a claim an operator may act on, so a row needs a floor that
// is defensible and a date that is true. A table of forty products with
// remembered version numbers is forty chances to be wrong, and a wrong
// "end of life" is worse than silence: it sends someone to a patch they do not
// need and away from one they do. So the table carries the cases where the end
// of support is both dated and unambiguous, and a product with a clean upgrade
// path and no dated end — nginx is the example everybody reaches for — is absent
// on purpose. `eolFloor` is where a later row goes, with its date and its
// advisory, and `TestEveryEolFloorCarriesItsDateAndFloor` keeps a half-filled
// row from being the way a new product is added.
//
// # Why version disclosure is its own finding
//
// It is a different defect with a different fix. "Upgrade OpenSSL" and "stop
// publishing the OpenSSL version in a header" are two actions, and an operator
// who only needs the second — because they are behind a reverse proxy they do not
// control — still deserves to be told. Emitting both is not duplication: the
// rows carry different evidence, different remediation and different IDs.
//
// # What this module deliberately does not do
//
// It sends no probe. Everything here is read out of the baseline the scan already
// fetched, so a fingerprint costs the target nothing and cannot change its
// state — the property every other module in this package is careful to preserve.
// The consequence is stated rather than hidden: a server that tells nobody what
// it runs yields no row from here, and the report says nothing about its
// components rather than guessing from a `Server` header that carries no number.
package active

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// fingerprint is the product detector.
type fingerprint struct{}

// Name implements Module.
func (fingerprint) Name() string { return "fingerprint" }

// Level implements Module.
//
// Host, not endpoint: the same server answers every URL on it, so a per-endpoint
// row would repeat one answer once per page — the same aggregation mistake
// `Misconfig` documents for hardening headers.
func (fingerprint) Level() Level { return LevelHost }

// fingerprintSource is one place a product and version can be read from.
//
// The patterns are tried in order, and the first match wins, because a header
// can carry more than one `name/version` pair (`OpenSSL/1.1.1k` inside a
// `Server: Apache/2.4.49 (OpenSSL/1.1.1)` banner) and the outermost product is
// the one an operator maintains.
type fingerprintSource struct {
	// header is the response header to read. Empty means the body.
	header string
	// body is the body pattern that identifies the product, for the sources
	// that live in HTML rather than in a header.
	body string
	// source is the `VersionSource` string a finding carries, so a number is
	// never presented without where it came from.
	source string
	// product is the canonical name findings use.
	product string
	// pattern matches the version inside the value.
	pattern *regexp.Regexp
	// fromBody reads the version out of the body rather than a header.
	fromBody bool
}

// versionCapture extracts a version from a value.
const versionCapture = `([0-9]+(?:\.[0-9]+){0,3}(?:[a-z]+[0-9]*)?)`

// fingerprintSources is where a product version is read from.
//
// `name/version` is the near-universal convention for this: Apache, nginx, PHP,
// OpenSSL and Tomcat all write it, so one pattern family covers most of the web.
var fingerprintSources = []fingerprintSource{
	{header: "Server", source: "banner:Server", product: "server", pattern: regexp.MustCompile(`([A-Za-z][A-Za-z0-9._+-]*(?:[ /][A-Za-z][A-Za-z0-9._+-]*)*)/` + versionCapture)},
	{header: "X-Powered-By", source: "header:X-Powered-By", product: "php", pattern: regexp.MustCompile(`PHP/` + versionCapture)},
	{header: "X-AspNet-Version", source: "header:X-AspNet-Version", product: "asp.net", pattern: regexp.MustCompile(versionCapture)},
	{header: "X-AspNetMvc-Version", source: "header:X-AspNetMvc-Version", product: "asp.net-mvc", pattern: regexp.MustCompile(versionCapture)},
	{header: "X-Runtime", source: "header:X-Runtime", product: "rails", pattern: regexp.MustCompile(versionCapture)},
	{header: "X-Drupal-Cache", source: "header:X-Drupal-Cache", product: "drupal", pattern: regexp.MustCompile(versionCapture)},
	{header: "X-Generator", source: "header:X-Generator", product: "cms", pattern: regexp.MustCompile(versionCapture)},
	{body: `<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`, source: "meta:generator", product: "cms", pattern: regexp.MustCompile(versionCapture), fromBody: true},
	{body: `<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']`, source: "meta:generator", product: "cms", pattern: regexp.MustCompile(versionCapture), fromBody: true},
	{body: `<!--\s*WordPress\s+` + versionCapture, source: "meta:generator", product: "wordpress", pattern: regexp.MustCompile(versionCapture), fromBody: true},
	{body: `Drupal\s+` + versionCapture, source: "meta:generator", product: "drupal", pattern: regexp.MustCompile(versionCapture), fromBody: true},
}

// identifiedProduct is one product read out of a response.
type identifiedProduct struct {
	name    string
	version string
	source  string
	// raw is the value the version was read from, kept for the evidence: a
	// triager decides whether to believe a version by looking at what the
	// server actually wrote, not at the number this parsed out of it.
	raw string
}

// eolFloor is one product's last security-supported version.
//
// The claim this encodes is "a version below `floor` does not receive security
// fixes", and it is deliberately narrow: `date` and `advisory` are mandatory, so
// a row cannot exist without the evidence a reader needs to check it.
type eolFloor struct {
	product  string
	floor    string
	date     string
	advisory string
}

// eolTable is every end-of-life claim this module is willing to make.
//
// A product absent from this table is not a product reported as supported; it is
// a product this module has no defensible claim about. See the file comment for
// why that is the better failure.
//
// The Apache row that was here first was wrong and is gone: Apache httpd 2.4 is
// still supported by the ASF, so "2.4.49 is below the last supported 2.4" is
// false. What is true about 2.4.49 is that it is *affected by* CVE-2021-41773,
// which is a different claim with a different table, and writing an end-of-life
// row for it would have sent an operator to patch a host that did not need it.
// This is the failure the file comment describes, reached the way it warned
// about: the version number was remembered, the product's support status was not.
var eolTable = []eolFloor{
	{product: "php", floor: "8.0", date: "2022-11-28", advisory: "PHP 7.4 reached end of life on 2022-11-28; the 7.4 branch stopped receiving fixes there and 8.0 replaced it"},
	{product: "openssl", floor: "3.0", date: "2023-09-11", advisory: "the OpenSSL 1.1.1 branch reached end of life on 2023-09-11; 3.0 is the maintained line"},
	{product: "jquery", floor: "3.0", date: "2020-05-07", advisory: "jQuery 1.x and 2.x are out of support; 3.0 is the maintained line, and 3.5.0 fixed CVE-2020-11022 / CVE-2020-11023"},
	{product: "asp.net", floor: "4.5.2", date: "2016-01-26", advisory: ".NET Framework 4.0 through 4.5.1 are out of support; 4.5.2 is the last supported 4.x release"},
	{product: "drupal-7", floor: "7.0", date: "2021-11-15", advisory: "Drupal 7 reached end of life on 2021-11-15 and is unsupported; the floor is 7.0 so the branch itself is what the row names"},
}

// floorFor returns the end-of-life row for a product, if this module has one.
func floorFor(product string) (eolFloor, bool) {
	for _, row := range eolTable {
		if row.product == product {
			return row, true
		}
	}
	return eolFloor{}, false
}

// Scan implements Module.
//
// It reads the baseline and sends nothing: there is no probe here to send.
func (f fingerprint) Scan(_ context.Context, _ *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil {
		// A nil baseline means the page could not be read. The honest reading
		// is "I cannot tell what this is running", and `Fresh` refuses for the
		// same reason: a detector that guesses here attaches a version to a
		// target it never saw.
		return nil
	}

	var findings []Finding
	for _, product := range identify(baseline) {
		findings = append(findings, f.ScanProduct(p, product)...)
	}
	return findings
}

// ScanProduct turns one identified product into the rows it warrants.
//
// It is separate from `Scan` so the decision — which rows a product earns — can
// be tested against a product the test built, rather than only against a banner
// a fixture happened to write. A module whose rules are only reachable through
// a live HTTP response is a module whose rules are untested.
func (fingerprint) ScanProduct(p Point, product identifiedProduct) []Finding {
	var findings []Finding

	if floor, ok := floorFor(product.name); ok {
		if below(product.version, floor.floor) {
			finding, _ := NewFinding(Spec{
				Module:  "fingerprint",
				Title:   fmt.Sprintf("End-of-life %s %s, below the last supported %s", product.name, product.version, floor.floor),
				Claimed: SeverityHigh,
				Tier:    TierPotential,
				Point:   p,
				Evidence: fmt.Sprintf("%s reported %q, and %s stopped receiving security fixes on %s (%s)",
					product.source, product.raw, floor.product, floor.date, floor.advisory),
				Description: fmt.Sprintf(
					"The server publishes its %s version as %s. That version is below %s, the last release of that line to receive security fixes. "+
						"The published advisories for this line are not patched on this host, so an operator looking for %s would find this version first.",
					product.name, product.version, floor.floor, product.name),
				Remediation:   fmt.Sprintf("Upgrade %s to a supported release, then remove the version from the response header or banner that disclosed it.", product.name),
				Version:       product.version,
				VersionSource: product.source,
			})
			findings = append(findings, finding)
		}
	}

	// The disclosure itself, when the version came from a header or a banner.
	// A body comment or a meta tag is a different situation: pages publish their
	// generator in HTML on purpose, and it is visible to every visitor, so it
	// is not a disclosure to anyone who had not already looked.
	if strings.HasPrefix(product.source, "header:") || strings.HasPrefix(product.source, "banner:") {
		finding, _ := NewFinding(Spec{
			Module:   "fingerprint",
			Title:    fmt.Sprintf("Exact %s version disclosed in %s", product.name, product.source),
			Claimed:  SeverityLow,
			Tier:     TierPotential,
			Point:    p,
			Evidence: fmt.Sprintf("%s: %q", product.source, product.raw),
			Description: fmt.Sprintf(
				"The response names the exact %s version it runs. Version disclosure removes the lookup step from exploiting it: an operator no longer has to fingerprint the server to learn what to search for, and known-version checks stop being guesses.",
				product.name),
			Remediation:   "Suppress the version in the banner and the powered-by headers at the web server or reverse proxy.",
			Version:       product.version,
			VersionSource: product.source,
		})
		findings = append(findings, finding)
	}

	return findings
}

// identify reads every product the response is willing to state.
//
// The returned list is deduplicated by product and version source, because one
// header can be read by two patterns — `X-AspNetMvc-Version` and a body comment
// can both name the same framework — and two identical rows differing only in
// an ID is the noise this module exists not to add.
func identify(resp *Response) []identifiedProduct {
	var found []identifiedProduct
	seen := map[string]bool{}

	for _, src := range fingerprintSources {
		var values []string
		if src.fromBody {
			values = matches(src.body, resp.Body)
		} else {
			raw := resp.HeaderValue(src.header)
			if raw == "" {
				continue
			}
			values = []string{raw}
		}
		for _, value := range values {
			match := src.pattern.FindStringSubmatch(value)
			if match == nil {
				continue
			}
			version := match[len(match)-1]
			if version == "" {
				continue
			}
			key := src.product + "|" + version + "|" + src.source
			if seen[key] {
				continue
			}
			seen[key] = true
			found = append(found, identifiedProduct{
				name:    resolveProduct(src, value),
				version: version,
				source:  src.source,
				raw:     strings.TrimSpace(value),
			})
		}
	}
	return found
}

// matches returns the capture groups of a body pattern, in order.
func matches(pattern, body string) []string {
	re := regexp.MustCompile(pattern)
	var out []string
	for _, group := range re.FindAllStringSubmatch(body, -1) {
		if len(group) > 1 && group[1] != "" {
			out = append(out, group[1])
		}
	}
	return out
}

// resolveProduct maps a source's generic product slot onto the name the EOL table
// uses.
//
// The `Server` header is the awkward one: the same pattern matches `Apache/2.4.49`,
// `nginx/1.18.0` and `Microsoft-IIS/10.0`, and only the first of those has a row
// in `eolTable`. The table is keyed by a name the banner may never spell out, so
// the name is resolved from the value rather than from the slot.
func resolveProduct(src fingerprintSource, value string) string {
	if src.product != "server" {
		return src.product
	}
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "apache"):
		// The banner names OpenSSL and PHP inside an Apache banner too; the
		// leading product is the server, which is what the header starts with.
		return "apache-httpd"
	case strings.Contains(lower, "nginx"):
		return "nginx"
	case strings.Contains(lower, "iis"), strings.Contains(lower, "microsoft"):
		return "iis"
	case strings.Contains(lower, "lighttpd"), strings.Contains(lower, "liteSpeed"):
		return "liteSpeed"
	case strings.Contains(lower, "caddy"):
		return "caddy"
	case strings.Contains(lower, "openresty"):
		return "openresty"
	}
	return src.product
}

// below reports whether a version is strictly less than a floor.
//
// Dotted numeric comparison first, then the non-numeric suffix, because OpenSSL
// and Java both carry the significant digit in a letter: `1.1.1g` is below
// `1.1.1k`, and comparing only the numbers calls them equal. A bare release is
// older than a lettered one, so `1.1.1` is below `1.1.1k`.
//
// A version this cannot read returns false, so an unparseable banner produces
// silence rather than a claim — the same rule the rest of this package applies
// to a fingerprint it cannot confirm.
func below(version, floor string) bool {
	left, okLeft := parseVersion(version)
	right, okRight := parseVersion(floor)
	if !okLeft || !okRight {
		return false
	}
	for i := 0; i < len(left) || i < len(right); i++ {
		var l, r int
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		if l != r {
			return l < r
		}
	}
	// Numerically equal, so the suffix decides — and it decides as text, because
	// that is what a patch letter is.
	ls, rs := versionSuffix(version), versionSuffix(floor)
	switch {
	case ls == rs:
		return false
	case ls == "":
		// A bare release precedes every lettered patch of the same number.
		return true
	case rs == "":
		return false
	}
	return ls < rs
}

// parseVersion reads a dotted version into its numeric components.
//
// A missing component is zero, so `2.4` and `2.4.0` compare equal — which is the
// right answer for a floor comparison and avoids treating a short banner as older
// than it is.
func parseVersion(version string) ([]int, bool) {
	version = versionSuffixless(version)
	if version == "" {
		return nil, false
	}
	parts := strings.Split(version, ".")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// versionSuffix returns the non-numeric tail of a version, or "" when it is all
// numeric.
func versionSuffix(version string) string {
	index := strings.IndexFunc(version, func(r rune) bool {
		return (r < '0' || r > '9') && r != '.'
	})
	if index < 0 {
		return ""
	}
	return version[index:]
}

// versionSuffixless strips the non-numeric tail.
func versionSuffixless(version string) string {
	index := strings.IndexFunc(version, func(r rune) bool {
		return (r < '0' || r > '9') && r != '.'
	})
	if index < 0 {
		return version
	}
	return version[:index]
}
