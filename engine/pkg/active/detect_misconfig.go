// Security misconfiguration: CORS, missing hardening headers, directory
// listing.
//
// # Why a site-wide gap is one row
//
// The upstream detector reports "missing security headers" once per endpoint. A
// site with four hundred pages produces four hundred identical rows differing
// only in a URL, and a report whose four hundred rows say the same thing is a
// report nobody reads to the end — including the one row that would have said
// something different.
//
// The gap is therefore aggregated: one row naming the count and listing the
// affected endpoints. Aggregation here is not a display trick, it is a claim
// about the cause — a server or CDN configured without the header set produces
// this on every page, and a per-page row describes a per-page problem that does
// not exist. A single endpoint missing a header is a different thing and stays a
// single row.
//
// # Why the public-file exemption exists
//
// `robots.txt` is a public routing directive. Reporting "missing security
// headers" on it is a finding about a file whose entire purpose is to be read by
// anyone, and it is the kind of row that teaches an operator to dismiss the
// module. The exemption is by exact path and by asset extension, not by prefix —
// a prefix rule would exempt `/admin/login`, which is the opposite of what the
// rule is for.
//
// # What CORS is and is not
//
// A reflected Origin is a real defect: the server decided that a caller it had
// never seen was allowed. Whether that is exploitable depends on whether the
// response can be read, and the response can be read when the server also
// allows credentials. So the two cases are different severities, and both are
// reported — a reflected origin without credentials lets a page read the
// response, which is already a disclosure, and with credentials it is a full
// cross-origin read of an authenticated endpoint.
package active

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// hardeningHeaders are the response headers a modern application is expected to
// carry, with the reason each one is worth asking for.
var hardeningHeaders = []struct {
	name string
	why  string
}{
	{"Content-Security-Policy", "blocks inline and external script execution, which is the main XSS mitigation"},
	{"X-Content-Type-Options", "stops a response being sniffed as a type the browser did not expect"},
	{"X-Frame-Options", "mitigates clickjacking"},
	{"Strict-Transport-Security", "stops a first request being made in the clear"},
	{"Referrer-Policy", "limits what a leaked URL hands to a third party"},
}

// publicPaths are exact paths that are public by design. A missing hardening
// header on one of them is not a finding.
var publicPaths = []string{
	"/robots.txt", "/sitemap.xml", "/favicon.ico", "/humans.txt",
	"/security.txt", "/.well-known/security.txt", "/.well-known/change-password",
}

// publicExtensions are asset types served to everyone by definition.
var publicExtensions = []string{
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif",
	".woff", ".woff2", ".ttf", ".eot", ".otf", ".map", ".css", ".mp4", ".webm",
}

// directoryListingMarkers are the two shapes an autoindex page takes.
var directoryListingMarkers = []string{
	"Index of /", "Directory listing for", "<title>Index of ",
}

// Misconfig is the security misconfiguration detector.
type Misconfig struct{}

// Name implements Module.
func (Misconfig) Name() string { return "misconfig" }

// Level implements Module.
func (Misconfig) Level() Level { return LevelEndpoint }

// Scan probes one endpoint.
//
// The request carries an Origin the operator controls, because a CORS check
// cannot be performed without offering one. The header is a plain `https://`
// URL on a host that is not the target's; it is never resolved, and it is
// removed from any report that quotes the response.
func (m Misconfig) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if isPublicResource(p.URL) {
		return nil
	}
	probeOrigin := "https://cors-probe.invalid"
	resp, err := t.Do(ctx, http.MethodGet, p.URL, nil, false, http.Header{
		"Origin": {probeOrigin},
	})
	if err != nil {
		return nil
	}
	var out []Finding
	if finding := corsFinding(p, resp, probeOrigin); finding != nil {
		out = append(out, *finding)
	}
	if finding := headerFinding(p, resp); finding != nil {
		out = append(out, *finding)
	}
	if finding := listingFinding(p, resp); finding != nil {
		out = append(out, *finding)
	}
	return out
}

// corsFinding inspects Access-Control-Allow-Origin for a reflected origin.
func corsFinding(p Point, resp *Response, probeOrigin string) *Finding {
	allowed := resp.HeaderValue("Access-Control-Allow-Origin")
	if allowed == "" {
		return nil
	}
	credentialed := strings.EqualFold(resp.HeaderValue("Access-Control-Allow-Credentials"), "true")
	// `*` alongside credentials is rejected by every browser, so a server that
	// sends it is not actually exposing the response and reporting it would be
	// a finding about a configuration no browser honours.
	wildcard := allowed == "*"
	if wildcard && credentialed {
		return nil
	}
	reflected := allowed == probeOrigin
	if !reflected && !wildcard {
		return nil
	}
	claimed := SeverityMedium
	title := "CORS Misconfiguration (origin reflected)"
	if credentialed {
		claimed = SeverityHigh
		title = "CORS Misconfiguration with credentials (origin reflected)"
	}
	evidence := fmt.Sprintf("Access-Control-Allow-Origin: %s | Access-Control-Allow-Credentials: %s",
		allowed, resp.HeaderValue("Access-Control-Allow-Credentials"))
	finding, _ := NewFinding(Spec{
		Module:  "misconfig",
		Title:   title,
		Claimed: claimed,
		// The response itself shows the reflection, and the probe is what
		// provoked it: a server answering for a host it was never configured
		// with has made its decision observable.
		Tier:        TierVerified,
		Point:       p,
		Payload:     "Origin: " + probeOrigin,
		Evidence:    evidence,
		Description: corsDescription(reflected, credentialed),
		Remediation: "Allow-list origins exactly, server-side. Never reflect the Origin header, and never " +
			"combine a reflected origin with Access-Control-Allow-Credentials.",
	})
	return &finding
}

func corsDescription(reflected, credentialed bool) string {
	switch {
	case reflected && credentialed:
		return "The endpoint echoed an origin it was never configured with into Access-Control-Allow-Origin " +
			"and permits credentialed cross-origin reads, so a page on any host can read authenticated " +
			"responses from this endpoint."
	case reflected:
		return "The endpoint echoed an arbitrary origin into Access-Control-Allow-Origin, so a page on any " +
			"host can read responses from it."
	default:
		return "The endpoint allows every origin and permits credentialed cross-origin reads."
	}
}

// headerFinding reports missing hardening headers as one row.
func headerFinding(p Point, resp *Response) *Finding {
	var missing []string
	var because []string
	for _, header := range hardeningHeaders {
		if resp.HeaderValue(header.name) == "" {
			missing = append(missing, header.name)
			because = append(because, header.name+" — "+header.why)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:   "misconfig",
		Title:    "Missing Security Headers (" + strings.Join(missing, ", ") + ")",
		Claimed:  SeverityLow,
		Tier:     TierVerified,
		Point:    p,
		Evidence: strings.Join(because, "; "),
		Description: "The response omits hardening headers. On its own this is a hardening gap rather than a " +
			"vulnerability; it becomes one when combined with a reflection, which is what the chain stage " +
			"looks for.",
		Remediation: "Set the header set at the server or CDN, once, rather than per route — a per-route " +
			"configuration is what produces a gap on some pages and not others.",
	})
	return &finding
}

// listingFinding reports an exposed directory index.
func listingFinding(p Point, resp *Response) *Finding {
	for _, marker := range directoryListingMarkers {
		if !strings.Contains(resp.Body, marker) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:   "misconfig",
			Title:    "Directory Listing Enabled",
			Claimed:  SeverityLow,
			Tier:     TierVerified,
			Point:    p,
			Payload:  "GET " + p.URL,
			Evidence: "autoindex markup: " + Snippet(resp.Body, marker, 100),
			Description: "The server renders a browsable index of a directory, which names files that were " +
				"never meant to be listed and gives an attacker a directory map for free.",
			Remediation: "Disable the directory index and move anything that must exist outside the web root.",
		})
		return &finding
	}
	return nil
}

// AggregateHeaderFindings collapses per-endpoint header rows into one site-wide
// row.
//
// It is deliberately conservative about what it merges. A run with exactly one
// affected endpoint is a per-endpoint problem and stays as it is, and the count
// is carried in the title so a report cannot imply broader coverage than it has.
func AggregateHeaderFindings(findings []Finding) []Finding {
	var affected []string
	var rest []Finding
	for _, finding := range findings {
		if finding.Module == "misconfig" && strings.HasPrefix(finding.Title, "Missing Security Headers") {
			affected = append(affected, finding.Endpoint)
			continue
		}
		rest = append(rest, finding)
	}
	if len(affected) < 2 {
		return findings
	}
	unique := make([]string, 0, len(affected))
	seen := map[string]bool{}
	for _, endpoint := range affected {
		if seen[endpoint] {
			continue
		}
		seen[endpoint] = true
		unique = append(unique, endpoint)
	}
	if len(unique) < 2 {
		return findings
	}
	sort.Strings(unique)

	// The list is capped, and the remainder is counted rather than dropped: a
	// report that silently listed eight of four hundred endpoints reads as if
	// eight were affected.
	const listed = 8
	shown := unique
	extra := 0
	if len(unique) > listed {
		shown = unique[:listed]
		extra = len(unique) - listed
	}
	evidence := fmt.Sprintf("%d endpoints served without the full hardening header set, beginning:\n%s",
		len(unique), strings.Join(shown, "\n"))
	if extra > 0 {
		evidence += fmt.Sprintf("\n…and %d more", extra)
	}
	aggregated, _ := NewFinding(Spec{
		Module:   "misconfig",
		Title:    fmt.Sprintf("Missing Security Headers (site-wide, %d endpoints)", len(unique)),
		Claimed:  SeverityLow,
		Tier:     TierVerified,
		Point:    Point{URL: unique[0], Method: "GET"},
		Evidence: evidence,
		Description: "The header set is absent across the site rather than on a single page. That points at a " +
			"server or CDN configuration rather than at individual routes, and it means the gap is not " +
			"something an analyst has to find page by page.",
		Remediation: "Set the header set once, at the server or CDN, and confirm it on a page that " +
			"currently reports them.",
	})
	return append(rest, aggregated)
}

// isPublicResource reports whether a URL is public by design, so a hardening
// finding on it would be noise.
//
// The test is exact: a known public path, or a known asset extension. It is not a
// prefix rule, because a prefix rule would exempt `/admin/login` — which is
// precisely a URL that should be reported.
func isPublicResource(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	for _, public := range publicPaths {
		if path == public || strings.HasSuffix(path, public) {
			return true
		}
	}
	for _, extension := range publicExtensions {
		if strings.HasSuffix(path, extension) {
			return true
		}
	}
	return false
}
