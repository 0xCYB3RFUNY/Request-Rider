// Web cache deception: a dynamic page served unchanged for a static-looking path.
//
// # The bug
//
// A shared cache — CDN, reverse proxy, or the operator's own — keys entries by
// URL. If `/profile` and `/profile.css` are the same document as far as the
// origin is concerned, and the cache treats them as two different resources, a
// second user requesting `/profile.css` is served the *first* user's page from
// the cache. The extension is what makes it work: caches are configured to store
// `.css`, `.png` and `.ico` because those are static, so a cache that would
// never store `/profile` stores `/profile.css` without being configured to.
//
// # What is proven and what is not
//
// Proven here: the origin returns the dynamic document, byte for byte, for a
// path that ends in a static extension. That is the precondition, and it is a
// property of the application — no cache is required to observe it, which is
// exactly why it can be checked on a server that has no CDN in front.
//
// Not proven here: that a cache in front of this origin actually stored the
// response. That needs a second request through that cache, which this scanner
// has no way to name. The finding says so in its own text rather than letting
// the tier imply it.
//
// # Why the extension list is short
//
// Each extension is one request against a live target, and the list is not a
// coverage claim: any extension the origin treats as static reproduces the bug.
// Four are tried, the four that caches are configured to store by default, and
// the finding names the one that worked so an operator can reason about their own
// cache rules.
package active

import (
	"context"
	"regexp"
	"strings"
)

// cacheDeceptionExtensions are the suffixes tried, in order.
//
// They are suffixes, not separate paths: the probe asks for the surface's own
// URL with a static extension appended, so the two requests differ in exactly
// the way an attacker would exploit and in no other way.
var cacheDeceptionExtensions = []string{".css", ".js", ".png", ".ico"}

// WebCacheDeception is the cache-deception precondition detector.
type WebCacheDeception struct{}

// Name implements Module.
func (WebCacheDeception) Name() string { return "cache-deception" }

// Level implements Module.
func (WebCacheDeception) Level() Level { return LevelEndpoint }

// Scan probes one surface.
func (m WebCacheDeception) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.StatusCode != 200 || ctx.Err() != nil {
		return nil
	}
	// A response with no body cannot be "served unchanged for a static-looking
	// path" in any sense worth a row, and a baseline of a few bytes matches every
	// extension by accident.
	if len(strings.TrimSpace(baseline.Body)) < 200 {
		return nil
	}
	// A path that already ends in one of the extensions has nothing to append.
	for _, suffix := range cacheDeceptionExtensions {
		if strings.HasSuffix(strings.ToLower(p.URL), suffix) {
			return nil
		}
	}
	for _, suffix := range cacheDeceptionExtensions {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := t.Do(ctx, p.Method, p.URL+suffix, p.Values, false, nil)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		if stripDynamicNoise(resp.Body) != stripDynamicNoise(baseline.Body) {
			continue
		}
		finding, _ := NewFinding(Spec{
			Module:   "cache-deception",
			Title:    "Dynamic page served unchanged for the static path " + suffix,
			Claimed:  SeverityMedium,
			Tier:     TierVerified,
			Point:    p,
			Payload:  p.URL + suffix,
			Evidence: "GET " + p.URL + suffix + " -> 200, body identical to " + p.URL,
			Description: "The origin returned the same document for " + p.URL + " and for " + p.URL + suffix +
				". A shared cache keys by URL and stores static extensions by default, so a second user " +
				"requesting the suffixed path can be served the first user's copy. Whether a cache in front of " +
				"this origin would actually store it is not established by this scan — the precondition, which is " +
				"a property of the application, is what was demonstrated.",
			Remediation: "Do not serve per-user or session-specific content for URLs that end in a static " +
				"extension, and normalise the cache key so `/profile.css` and `/profile` cannot become two " +
				"entries for one document. On the cache side, restrict which extensions are storable and make " +
				"sure responses carrying `Set-Cookie` or `Vary` are not stored at all.",
		})
		return []Finding{finding}
	}
	return nil
}

// rotatingValue is a pattern that matches a per-request value, and which of its
// capture groups holds that value.
type rotatingValue struct {
	pattern    *regexp.Regexp
	valueGroup int
}

// rotatingValuePatterns match the per-request values two fetches of one page
// differ in.
//
// The alternation is deliberately narrow: a CSRF token in a hidden field, a
// request or trace id in a JSON field or a URL. A pattern loose enough to catch a
// real token would also catch content, and deleting content is how this
// comparison starts calling two different pages the same.
var rotatingValuePatterns = []rotatingValue{
	{regexp.MustCompile(`(?i)name=["'][^"']*token[^"']*["'][^>]*?value=["']([A-Za-z0-9_\-+/=]{16,})["']`), 1},
	{regexp.MustCompile(`(?i)content=["'][^"']*token[^"']*["']`), 0},
	{regexp.MustCompile(`(?i)("(?:request[_-]?id|trace[_-]?id|nonce|correlation[_-]?id)"\s*:\s*")([A-Za-z0-9_\-]{8,})(")`), 2},
	{regexp.MustCompile(`(?i)(?:x-request-id|x-correlation-id|request-id)=["']?([A-Za-z0-9_\-]{8,})`), 1},
}

// stripDynamicNoise removes the parts of a document that legitimately differ
// between two requests for the same page.
//
// Without it every page carrying a request id, a CSRF token or a timestamp is
// "different", and the detector reports nothing on any real site — which is the
// same false-negative the CRLF detector's baseline comparison is written to
// avoid. A token and a request id are removed; nothing else is, because removing
// more would make two genuinely different pages compare equal.
func stripDynamicNoise(body string) string {
	for _, rotating := range rotatingValuePatterns {
		for _, match := range rotating.pattern.FindAllStringSubmatch(body, -1) {
			if rotating.valueGroup >= len(match) {
				continue
			}
			body = strings.ReplaceAll(body, match[rotating.valueGroup], "")
		}
	}
	return strings.Join(strings.Fields(body), " ")
}

// nonceValues extracts the rotating values a body carries, for the tests.
func nonceValues(body string) []string {
	var out []string
	for _, rotating := range rotatingValuePatterns {
		for _, match := range rotating.pattern.FindAllStringSubmatch(body, -1) {
			if rotating.valueGroup < len(match) && match[rotating.valueGroup] != "" {
				out = append(out, match[rotating.valueGroup])
			}
		}
	}
	return out
}
