package active

// ScriptIncludeOfAnotherDomain reads a page for the code it loads from somebody
// else's host.
//
// Burp's check is `0x00500500` (Cross-domain script include). It is a body
// reader with no probe of its own: the decision this reports is one the
// application already made in markup it already served, and re-asking the server
// about it would spend a request to learn what the response says.
//
// The distinction that matters is between a host the application runs and a
// host it *uses*. A bundle from the origin is not this finding. A bundle from
// a CDN the application chose is a dependency the application's security
// posture now includes: the CDN answers for every visitor, and a compromised
// CDN serves code that runs in the page's origin with access to everything the
// page can see.
//
// What this row does not claim is that any of it happened. It names the
// includes; whether the third party is honestly run is the operator's question,
// and a scanner answering it from a hostname would be guessing.

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

// ScriptIncludeOfAnotherDomain is the cross-domain code-include reader.
type ScriptIncludeOfAnotherDomain struct{}

// Name implements Module.
func (ScriptIncludeOfAnotherDomain) Name() string { return "script-include" }

// Level implements Module.
func (ScriptIncludeOfAnotherDomain) Level() Level { return LevelEndpoint }

// scriptIncludeScope are the elements that make the page *run or render* code
// from somewhere else. A `<link>` counts only for a rel the browser fetches,
// which is the same rule the mixed-content reader applies, because a canonical
// URL is a reference and not a load.
var scriptIncludeScope = map[string]string{
	"script": "src",
	"iframe": "src",
	"embed":  "src",
	"object": "data",
}

// Scan reads the baseline and reports the code the page loads from elsewhere.
func (ScriptIncludeOfAnotherDomain) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.StatusCode >= 400 || isPublicResource(p.URL) {
		return nil
	}
	if !strings.Contains(strings.ToLower(baseline.HeaderValue("Content-Type")), "text/html") {
		return nil
	}
	if strings.TrimSpace(baseline.Body) == "" {
		return nil
	}

	page, err := url.Parse(p.URL)
	if err != nil {
		return nil
	}

	refs := foreignScriptIncludes(baseline.Body, page.Host)
	if len(refs) == 0 {
		return nil
	}
	return []Finding{scriptIncludeFinding(p, refs)}
}

// scriptInclude is one resource the page loads from a host that is not its own.
type scriptInclude struct {
	// url is the include exactly as the markup spelled it.
	url string
	// element names the tag that loads it.
	element string
	// host is the resolved host the code comes from.
	host string
}

// foreignScriptIncludes walks a parsed document and returns the code it loads
// from another host, in document order.
func foreignScriptIncludes(body, pageHost string) []scriptInclude {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil || doc == nil {
		return nil
	}
	var out []scriptInclude
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			name := strings.ToLower(n.Data)
			if attribute, loads := scriptIncludeScope[name]; loads {
				if raw := strings.TrimSpace(attrValue(n, attribute)); raw != "" && !isLocalOrRelative(raw) {
					if target, err := url.Parse(raw); err == nil && target.Host != "" && target.Host != pageHost {
						out = append(out, scriptInclude{url: raw, element: name, host: target.Host})
					}
				}
			}
			// A stylesheet is code the page renders with, and a foreign one is
			// the same dependency reported by the same rule.
			if strings.EqualFold(name, "link") && linkRelLoads(n) {
				if raw := strings.TrimSpace(attrValue(n, "href")); raw != "" && !isLocalOrRelative(raw) {
					if target, err := url.Parse(raw); err == nil && target.Host != "" && target.Host != pageHost {
						out = append(out, scriptInclude{url: raw, element: "link", host: target.Host})
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return out
}

// isLocalOrRelative reports whether a URL stays inside the document, so it is
// never a cross-domain include. A protocol-relative URL is absolute in host
// terms, so it is *not* local by this test; the host comparison catches the ones
// that name the page's own host.
func isLocalOrRelative(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.HasPrefix(lower, "data:") ||
		strings.HasPrefix(lower, "blob:") ||
		strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "about:") ||
		strings.HasPrefix(raw, "/") ||
		strings.HasPrefix(raw, "./") ||
		strings.HasPrefix(raw, "../") ||
		strings.HasPrefix(raw, "#") ||
		!strings.Contains(raw, "//")
}

// scriptIncludeFinding renders one row grouping the foreign hosts.
func scriptIncludeFinding(p Point, refs []scriptInclude) Finding {
	hosts := make([]string, 0, len(refs))
	seen := make(map[string]bool, len(refs))
	for _, ref := range refs {
		if !seen[ref.host] {
			seen[ref.host] = true
			hosts = append(hosts, ref.host)
		}
	}
	shown := refs
	more := 0
	if len(shown) > 4 {
		more = len(shown) - 4
		shown = shown[:4]
	}
	lines := make([]string, 0, len(shown))
	for _, ref := range shown {
		lines = append(lines, "<"+ref.element+"> → "+ref.url)
	}
	evidence := "foreign host(s): " + strings.Join(hosts, ", ") + "\n" + strings.Join(lines, "\n")
	if more > 0 {
		evidence += "\n…and " + strconv.Itoa(more) + " more"
	}
	finding, _ := NewFinding(Spec{
		Module:   "script-include",
		Title:    "Cross-Domain Script Include",
		Claimed:  SeverityLow,
		Tier:     TierVerified,
		Point:    p,
		Evidence: evidence,
		Description: "The page loads " + strconv.Itoa(len(refs)) + " resource(s) from " +
			strconv.Itoa(len(hosts)) + " host(s) other than its own. Each of those hosts answers " +
			"for every visitor to this page, so code or styling from any of them runs in this " +
			"page's origin and can read everything the page can read. This row names the " +
			"dependency; whether the third party is honestly run is a question about the " +
			"organisation, not about the hostname.",
		Remediation: "Serve what the page needs from its own origin, or pin the include with " +
			"Subresource Integrity so a changed payload stops the page rather than executing. " +
			"Review the list of hosts periodically and remove the ones you no longer use.",
	})
	return finding
}
