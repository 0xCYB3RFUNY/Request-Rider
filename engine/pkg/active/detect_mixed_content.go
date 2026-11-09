package active

// MixedContent reads an HTTPS response for the subresources it loads over
// cleartext HTTP (Burp check 0x01000400).
//
// The check is a body reader, not a prober: nothing is fired, the baseline is
// the whole input, and the report names the exact URLs the page loads in the
// clear. That is the honest shape of the finding — the page is HTTPS, the
// resource is not, and the difference is a decision the application already
// made, in markup it already served.
//
// What counts as "loads" is narrower than "mentions". An `<a href="http://…">`
// navigates on a click and is not a load, so it is not mixed content; a
// `<script src>`, a stylesheet, an iframe, an `<img src>` and a CSS `url()`
// are all fetched by the browser without asking. The distinction is the whole
// difference between a scanner that reports every http:// string it can grep
// and one that reports what the browser actually retrieved, and it is why the
// walker below enumerates loading elements by name rather than scanning for a
// scheme.
//
// The parse is `html.Parse` for the same reason the crawler uses it: a regex
// sees `data-src="http://…"` as a `src`, and a page with a commented-out
// script becomes a finding the browser would never make.

import (
	"context"
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

// MixedContent is the cleartext-subresource reader for one HTTPS endpoint.
type MixedContent struct{}

// Name implements Module.
func (MixedContent) Name() string { return "mixed-content" }

// Level implements Module.
func (MixedContent) Level() Level { return LevelEndpoint }

// Scan reads the baseline and reports the subresources it loads over HTTP.
func (MixedContent) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil {
		return nil
	}
	// A cleartext page has nothing to be mixed with: every resource on it is
	// as cleartext as the page itself. The check exists for the page that
	// promises a secure context and then breaks it.
	if !strings.EqualFold(schemeOf(p.URL), "https") {
		return nil
	}
	if !strings.Contains(strings.ToLower(baseline.HeaderValue("Content-Type")), "text/html") {
		return nil
	}
	if strings.TrimSpace(baseline.Body) == "" {
		return nil
	}

	refs := mixedSubresources(baseline.Body)
	if len(refs) == 0 {
		return nil
	}

	// Two rows, because the two severities are different decisions: an active
	// subresource is script that runs and styles that render, and a passive one
	// is an image. Reporting them as one row would make the operator read them
	// as the same thing.
	active := []mixedRef{}
	passive := []mixedRef{}
	for _, ref := range refs {
		if ref.active {
			active = append(active, ref)
		} else {
			passive = append(passive, ref)
		}
	}

	var out []Finding
	if len(active) > 0 {
		out = append(out, mixedFinding(p, active, SeverityMedium, "active"))
	}
	if len(passive) > 0 {
		out = append(out, mixedFinding(p, passive, SeverityLow, "passive"))
	}
	return out
}

// mixedRef is one subresource the page loads over cleartext HTTP, with the
// element that loads it.
type mixedRef struct {
	// url is the cleartext URL exactly as the markup spelled it.
	url string
	// element names the tag that fetches it, so the evidence line tells the
	// operator what the browser does with the URL.
	element string
	// active is whether the subresource executes or defines layout. A
	// stylesheet can restyle the page into a credential form, so it counts as
	// active even though it is not script.
	active bool
}

// activeElements maps a loading element to whether what it loads executes or
// defines layout. The keys are the tags whose fetch is a *load*: a download
// attribute, a link preview and an `<a>` are a navigation, not a fetch.
var activeLoadElements = map[string]bool{"script": true,
	"iframe": true,
	"object": true,
	"embed":  true,
	"base":   true,
	"link":   true,
	"style":  true,
	"source": false,
	"img":    false,
	"video":  false,
	"audio":  false,
	"track":  false,
	"input":  false,
}

// mixedSubresources walks a parsed document and returns every resource it loads
// over cleartext HTTP, in document order.
//
// A `<base href="http://…">` is listed first by `html.Parse`'s own traversal
// order, which is right: a relative URL under a cleartext base is as cleartext
// as the base, and it is the first thing the reader needs to see.
func mixedSubresources(body string) []mixedRef {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil || doc == nil {
		return nil
	}
	var out []mixedRef
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if active, loads := activeLoadElements[strings.ToLower(n.Data)]; loads {
				// A `<link>` only loads what its rel asks for: `canonical`,
				// `alternate` and `author` are references, not fetches.
				if strings.EqualFold(n.Data, "link") && !linkRelLoads(n) {
					return
				}
				// An `<input>` loads only as an image submit button.
				if strings.EqualFold(n.Data, "input") && !attrIs(n, "type", "image") {
					return
				}
				for _, url := range loadingURLsOf(n) {
					if isCleartextHTTP(url) {
						out = append(out, mixedRef{url: url, element: n.Data, active: active})
					}
				}
			}
			// A CSS `url(http://…)` inside an inline `<style>` is a fetch the
			// browser performs while parsing the sheet, so it belongs in the
			// same list as a `<link>`'s href.
			if strings.EqualFold(n.Data, "style") && n.FirstChild != nil {
				for _, url := range cssURLs(n.FirstChild.Data) {
					if isCleartextHTTP(url) {
						out = append(out, mixedRef{url: url, element: "style url()", active: true})
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

// linkRelLoads reports whether a `<link>` element's rel makes the browser fetch
// its href. Stylesheets, icons, manifests and preloads do; a canonical URL, a
// search description and a translation alternate do not.
func linkRelLoads(n *html.Node) bool {
	rel := strings.ToLower(attrValue(n, "rel"))
	if rel == "" {
		return false
	}
	for _, token := range strings.Fields(rel) {
		switch token {
		case "stylesheet", "icon", "shortcut", "apple-touch-icon", "apple-touch-icon-precomposed",
			"manifest", "preload", "prefetch", "modulepreload", "prerender":
			return true
		}
	}
	return false
}

// loadingURLsOf returns the URLs an element fetches, from the attributes that
// carry one. `srcset` is expanded into its candidate URLs, because a `2x`
// descriptor does not change which scheme the browser dials.
func loadingURLsOf(n *html.Node) []string {
	var out []string
	appendURL := func(name string) {
		if value := strings.TrimSpace(attrValue(n, name)); value != "" {
			out = append(out, value)
		}
	}
	// Every attribute an element may fetch through, by element: `data` for
	// `<object>`, `href` for `<link>` and `<base>`, `src` for the rest, plus
	// `poster` for the media elements and `srcset` for the responsive ones.
	appendURL("src")
	appendURL("href")
	appendURL("data")
	appendURL("poster")
	for _, candidate := range srcsetCandidates(attrValue(n, "srcset")) {
		out = append(out, candidate)
	}
	return out
}

// srcsetCandidates expands a `srcset` value into its bare URLs, dropping the
// width and density descriptors that follow each one.
func srcsetCandidates(srcset string) []string {
	srcset = strings.TrimSpace(srcset)
	if srcset == "" {
		return nil
	}
	var out []string
	for _, candidate := range strings.Split(srcset, ",") {
		fields := strings.Fields(candidate)
		if len(fields) > 0 {
			out = append(out, fields[0])
		}
	}
	return out
}

// isCleartextHTTP reports whether a URL the markup spells is an absolute HTTP
// URL. A protocol-relative URL (`//host/x`) inherits the page's scheme, so it
// is not mixed; a relative URL resolves against the base and is reported by the
// `<base>` check when that base is cleartext.
func isCleartextHTTP(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	// A data:, blob: or javascript: URL never leaves the document.
	if strings.Contains(trimmed, ":") && !strings.HasPrefix(strings.ToLower(trimmed), "http") {
		return false
	}
	lower := strings.ToLower(trimmed)
	return strings.HasPrefix(lower, "http://")
}

// cssURLs reads the `url(…)` terms out of an inline stylesheet.
func cssURLs(css string) []string {
	var out []string
	rest := css
	for {
		idx := strings.Index(strings.ToLower(rest), "url(")
		if idx < 0 {
			return out
		}
		rest = rest[idx+len("url("):]
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			return out
		}
		target := strings.TrimSpace(rest[:end])
		target = strings.Trim(target, `"'`)
		out = append(out, target)
		rest = rest[end+1:]
	}
}

// attrValue returns one attribute's value, or "" when the element does not carry
// it.
func attrValue(n *html.Node, name string) string {
	for _, attr := range n.Attr {
		if strings.EqualFold(attr.Key, name) {
			return attr.Val
		}
	}
	return ""
}

// attrIs reports whether an attribute equals a value, case-insensitively.
func attrIs(n *html.Node, name, value string) bool {
	return strings.EqualFold(strings.TrimSpace(attrValue(n, name)), value)
}

// mixedFinding renders one row for one class of subresource.
func mixedFinding(p Point, refs []mixedRef, claimed Severity, class string) Finding {
	shown := refs
	more := 0
	if len(shown) > 3 {
		more = len(shown) - 3
		shown = shown[:3]
	}
	lines := make([]string, 0, len(shown))
	for _, ref := range shown {
		lines = append(lines, "<"+ref.element+"> → "+ref.url)
	}
	evidence := strings.Join(lines, "\n")
	if more > 0 {
		evidence += "\n…and " + strconv.Itoa(more) + " more"
	}
	description := "The HTTPS page loads " + strconv.Itoa(len(refs)) + " " + class + " subresource(s) over " +
		"cleartext HTTP. Every one of them is a request a network observer can read and rewrite: a " +
		"stylesheet restyles the page, a script runs in the page's origin, and an image is the least an " +
		"attacker learns."
	if class == "active" {
		description = "The HTTPS page loads " + strconv.Itoa(len(refs)) + " active subresource(s) over " +
			"cleartext HTTP. A script or stylesheet fetched in the clear is one an observer can rewrite " +
			"before it reaches the page, which turns a page that promised a secure context into a page " +
			"that executes whatever was sent instead."
	}
	finding, _ := NewFinding(Spec{
		Module:      "mixed-content",
		Title:       "Mixed Content: Cleartext Subresources on an HTTPS Page (" + class + ")",
		Claimed:     claimed,
		Tier:        TierVerified,
		Point:       p,
		Evidence:    evidence,
		Description: description,
		Remediation: "Serve every subresource over HTTPS, or remove it. A protocol-relative or " +
			"relative URL inherits the page's scheme and needs no change once the target is HTTPS.",
	})
	return finding
}
