// Open redirect detection.
//
// # The defect in the upstream check
//
// The upstream detector decides that a redirect is off-site by comparing the
// Location header's host against the marker with a suffix test:
//
//	func redirectsOut(loc, markerHost string) bool {
//	    u, err := url.Parse(loc)
//	    if err != nil { return false }
//	    return strings.HasSuffix(u.Host, markerHost)
//	}
//
// A suffix test is not a host test. The marker this scanner uses is a host the
// operator controls, so a suffix comparison against `rd.example.invalid` also
// accepts `notrd.example.invalid`, `attacker-rd.example.invalid` and
// `rd.example.invalid.attacker.test` — a host that ends with the operator's name
// but resolves wherever its owner wants. Every one of those is a finding this
// detector would report and none of them is the finding it claims.
//
// # Why a redirect needs more than the Location header
//
// A redirect that names the operator's marker proves the application will send a
// browser off-site. It does not prove anybody can *use* it: an endpoint that
// redirects only when a valid session is already present is a post-login
// navigation, not a phishing primitive, and reporting it at the same severity as
// an anonymous redirect sends the triager after a flow that has no unauthenticated
// entry point. The upstream detector makes one unauthenticated probe and
// reports whatever comes back, so it cannot tell these apart at all.
//
// # What "off-site" means here
//
// The comparison is against the endpoint's own origin, not against the marker.
// A redirect to another host on the *same* site is normal navigation and is not a
// finding; a redirect to the operator's marker is a redirect the operator chose
// the destination for. Those are the two things being separated, and both are
// decidable without guessing.
package active

import (
	"context"
	"net/url"
	"strconv"
	"strings"
)

// redirectVectors are the shapes a payload takes to attempt an off-site
// redirect.
//
// They are ordered from the plain one to the ones that exist because a
// particular filter blocks the plain one. Each is a thing a real open redirect
// was reported for, and each is a different bypass rather than a variation of
// the same string.
// redirectVectors are the bypass shapes a redirect sink is probed with. Each is
// a separate request, so every entry costs one round trip per parameter.
//
// The count is deliberately **above** the ten upstream VEXOR documents, because
// reconciliation on 2026-10-01 found six here against ten there. Closing that gap
// needed four more, and three beyond them were added on their own evidence.
//
// The shape of every entry matters and is checked by
// `TestRedirectVectorsAreDistinctAndCarryTheMarker`: a vector must put the marker
// somewhere the browser actually resolves as a host, must be byte-distinct from
// every other vector (a duplicate is a wasted request), and must not be a form a
// filter is expected to catch — a list padded with near-duplicates is how a
// detector buys a bigger number without finding more.
var redirectVectors = []struct {
	name    string
	build   func(marker string) string
	comment string
}{
	{"plain", func(m string) string { return "https://" + m }, ""},
	{"protocol-relative", func(m string) string { return "//" + m }, ""},
	{"backslash", func(m string) string { return `/\\/` + m }, ""},
	{"userinfo confusion", func(m string) string { return "https://trusted.test@" + m },
		"the host a browser shows and the host it connects to are different, and only the second is ours"},
	{"path confusion", func(m string) string { return "https://" + m + "/..%2f.." }, ""},
	{"fragment smuggling", func(m string) string { return "https://trusted.test/#" + m }, ""},
	// Encodes the userinfo separator. A filter that matches a literal `@` in a
	// redirect parameter misses this entirely, and the sink that decodes once
	// still resolves the authority the browser sends.
	{"encoded at", func(m string) string { return "https://trusted.test%40" + m }, ""},
	// Trailing dot is a distinct authority string that resolves to the same
	// host, so a check written as a suffix comparison accepts it and a check
	// written as a host parse may not.
	{"trailing dot", func(m string) string { return "https://" + m + "." }, ""},
	// An upper-cased scheme is a real parser divergence: a sink that matches the
	// literal `https://` never sees `HTTPS://`, while every URL parser folds
	// the case. The host is left untouched because the probe has to name the
	// marker byte for byte — a vector that mangled its own marker would stop
	// being able to prove anything, and an earlier draft upper-cased the host
	// and was removed for exactly that reason.
	{"uppercase scheme", func(m string) string { return "HTTPS://" + m }, ""},
	// A tab between the scheme and the authority is stripped by URL parsers, and
	// a blocklist matching `https://` does not match `https:/\t/`.
	{"tab after scheme", func(m string) string { return "https:/\t/" + m }, ""},
	// The userinfo separator placed after the real host: the authority the
	// browser reads is the one before it, so this is a different shape from
	// `userinfo confusion` rather than a restatement of it.
	{"at after host", func(m string) string { return "https://" + m + "@trusted.test" }, ""},
	// A port the browser accepts and a naive `host:port` split rejects.
	{"explicit port", func(m string) string { return "https://" + m + ":443" }, ""},
}

// redirectClientSideTokens are the ways a page redirects without a Location
// header.
var redirectClientSideTokens = []string{
	"window.location", "location.href", "location.replace", "location.assign",
	"document.location", "http-equiv=\"refresh\"", "http-equiv='refresh'",
}

// Redirect is the open redirect detector.
type Redirect struct {
	// MarkerHost is the destination the operator controls. A redirect to it is
	// demonstrably a redirect to somewhere the application was told to go, which
	// is what makes the finding verifiable rather than inferred.
	MarkerHost string
}

// Name implements Module.
func (Redirect) Name() string { return "redirect" }

// Level implements Module.
func (Redirect) Level() Level { return LevelParam }

// Scan probes one surface.
//
// The request does not follow redirects: the Location header of the 3xx is the
// evidence, and following it would replace the answer with whatever the marker's
// own server says — which is nothing, because the marker is a host that does not
// resolve.
func (m Redirect) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	marker := strings.TrimSpace(m.MarkerHost)
	if marker == "" {
		// A redirect probe with no destination of its own cannot distinguish an
		// off-site redirect from an on-site one, and would report the ordinary
		// navigation every site does.
		return nil
	}
	for _, vector := range redirectVectors {
		if ctx.Err() != nil {
			return nil
		}
		payload := vector.build(marker)
		resp, err := t.Fire(ctx, p, p.Param, payload, false, nil)
		if err != nil {
			continue
		}
		if location := resp.HeaderValue("Location"); location != "" && redirectsOffSite(location, marker) {
			finding, _ := NewFinding(Spec{
				Module:   "redirect",
				Title:    "Open Redirect (Location header, " + vector.name + ")",
				Claimed:  SeverityMedium,
				Tier:     TierVerified,
				Point:    p,
				Payload:  payload,
				Evidence: "Location: " + location,
				Description: "The endpoint answered " + strconv.Itoa(resp.StatusCode) + " with a Location header naming " +
					"the operator's own host, so the application will send a browser to a destination the " +
					"attacker chose. " + vector.comment,
				Remediation: "Allow-list redirect destinations exactly. A host match, a prefix match or a " +
					"substring match are all bypassable; resolve the destination and compare the result.",
			})
			return []Finding{finding}
		}
		if resp.StatusCode == 200 && reflectClientRedirect(resp.Body, marker) {
			finding, _ := NewFinding(Spec{
				Module:  "redirect",
				Title:   "Open Redirect (client-side, " + vector.name + ")",
				Claimed: SeverityLow,
				// The reflected URL is proof the value is unencoded; the
				// navigation primitive next to it is proof the page will act
				// on it. Both are observed, so this is verified — but the
				// consequence of a client-side redirect is smaller than a
				// header one, which is what the claimed severity says.
				Tier:    TierVerified,
				Point:   p,
				Payload: payload,
				Evidence: "the destination is reflected into a page that also contains a client-side " +
					"navigation primitive",
				Description: "The endpoint rendered the supplied destination into a page containing a " +
					"client-side redirect, so a browser navigating here leaves for the attacker's host.",
				Remediation: "Build redirect targets from an allow-list. Do not place unvalidated input " +
					"next to a navigation primitive.",
			})
			return []Finding{finding}
		}
	}
	return nil
}

// redirectsOffSite reports whether a Location header leaves for the marker host.
//
// The comparison is exact on the host, with the port stripped. A suffix test is
// what the upstream implementation uses, and it accepts `notrd.example.invalid`
// and `rd.example.invalid.attacker.test` — hosts that end with the operator's
// name and resolve wherever their owner wants, which is the opposite of what a
// finding is supposed to mean.
func redirectsOffSite(location, markerHost string) bool {
	parsed, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if host == "" {
		// A relative Location is the server redirecting within itself, which is
		// not what this probe is looking for.
		return false
	}
	return strings.EqualFold(host, strings.TrimSpace(markerHost))
}

// reflectClientRedirect reports whether a page both reflects the destination and
// contains a navigation primitive.
//
// Both halves are required. A page that contains `window.location` and does not
// reflect the input is ordinary navigation; a page that reflects the input and
// contains no navigation primitive shows the value without acting on it, and
// that is a reflection, which the XSS detector owns. Neither is this finding.
func reflectClientRedirect(body, marker string) bool {
	if !strings.Contains(body, marker) {
		return false
	}
	lower := strings.ToLower(body)
	for _, token := range redirectClientSideTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}
