package active

// CacheableSecurityResponse reports an HTTPS response a cache may hold that
// carries something only its recipient should read.
//
// Burp's check is `0x00700100` (Cacheable HTTPS response). It is a body reader:
// the two facts it needs are the response's own caching headers and its own
// body, and both are in the baseline the surface already fetched.
//
// Why two conditions and not one. Cacheable alone is not a finding — a cache
// exists precisely so responses can be held — and a sensitive body alone is not
// either, because an authenticated response marked `private` never leaves the
// client. The finding is the *combination*: a shared cache told to hold a
// response that carries a credential means the second visitor may be served the
// first visitor's page.
//
// The measurement of "sensitive" is therefore deliberately narrow: the page
// carries a session identifier, a CSRF token or a password field, or the URL
// names an account. A page that merely contains the word "security" is not
// sensitive, and a detector that reported one would be noise.

import (
	"context"
	"regexp"
	"strings"
)

// CacheableSecurityResponse is the cacheable-credential reader.
type CacheableSecurityResponse struct{}

// Name implements Module.
func (CacheableSecurityResponse) Name() string { return "cacheable-https" }

// Level implements Module.
func (CacheableSecurityResponse) Level() Level { return LevelEndpoint }

// cacheableSensitiveMarkers are what a page carries when holding it on a shared
// cache is a disclosure rather than an optimisation.
//
// The first group is a session: an identifier the next visitor must not receive.
// The second is a secret the page hands to its recipient, which is a token or a
// password field. The URL is not in this table because `Snippet` reads the body,
// and a URL-shaped claim belongs to the surface the run already names.
var cacheableSensitiveMarkers = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"session cookie", regexp.MustCompile(`(?i)set-cookie[^\n]{0,160}\b(jsessionid|phpsessid|aspsessionid|session|sessionid|sid|auth|token)\b`)},
	{"bearer token", regexp.MustCompile(`(?i)\b(bearer\s+[A-Za-z0-9\-_\.]{8,}|authorization:\s*(?:bearer|basic)\s+[A-Za-z0-9\-_\.=]{8,})`)},
	{"csrf token field", regexp.MustCompile(`(?i)<input[^>]+name\s*=\s*["'][^"']*(csrf|xsrf|_token|authenticity_token)[^"']*["']`)},
	{"password field", regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*["']?password["']?`)},
	{"account surface", regexp.MustCompile(`(?i)(\b(?:my[-_ ]?account|account[-_ ]?settings|profile|dashboard|billing|api[-_ ]?key|secret|private[-_ ]?key)\b)`)},
}

// Scan reports the response when a cache may hold it and it carries something
// only its recipient should read.
func (CacheableSecurityResponse) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.StatusCode >= 400 {
		return nil
	}
	// A cleartext page has no secure context to defend, and the claim this
	// check makes is about a cache holding what HTTPS was supposed to
	// protect.
	if !strings.EqualFold(schemeOf(p.URL), "https") {
		return nil
	}
	if !isCacheable(baseline) {
		return nil
	}
	if strings.EqualFold(strings.ToLower(baseline.HeaderValue("Cache-Control")), "no-store") {
		return nil
	}

	// The scan reads the *headers and the body together*: a Set-Cookie on a
	// cacheable response is the finding, and it is in the headers rather than
	// in the body the page rendered.
	haystack := baseline.Body
	for _, header := range []string{"Set-Cookie", "Authorization", "X-Account-Id", "X-Api-Key"} {
		if value := baseline.HeaderValue(header); value != "" {
			haystack += "\n" + header + ": " + value + "\n"
		}
	}

	var matched []string
	for _, marker := range cacheableSensitiveMarkers {
		if marker.pattern.MatchString(haystack) {
			matched = append(matched, marker.name)
		}
	}
	if len(matched) == 0 {
		return nil
	}
	return []Finding{cacheableFinding(p, baseline, matched)}
}

// cacheableFinding names what a cache was told to hold.
func cacheableFinding(p Point, baseline *Response, matched []string) Finding {
	finding, _ := NewFinding(Spec{
		Module:  "cacheable-https",
		Title:   "Cacheable HTTPS Response Carrying Per-Recipient Data",
		Claimed: SeverityMedium,
		Tier:    TierPotential,
		Point:   p,
		Evidence: "cache: " + baseline.HeaderValue("Cache-Control") + "\n" +
			"per-recipient data: " + strings.Join(matched, ", "),
		Description: "This HTTPS response is cacheable and carries " + strings.Join(matched, ", ") +
			". A shared cache that holds it serves the next visitor the first visitor's page, so " +
			"the identifier or the token is disclosed to whoever arrives second. The tier is " +
			"potential because a cache in front of this origin was not observed storing it — " +
			"that part is a property of the deployment, not of this response.",
		Remediation: "Mark authenticated and account responses `Cache-Control: private, no-store`, " +
			"and keep the account surface off any cache shared between visitors.",
	})
	return finding
}
