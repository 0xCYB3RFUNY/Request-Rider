// Katana's parsers, spliced into our crawler.
//
// # What this file is
//
// Katana registers thirty response parsers in `NewResponseParser()`
// (`pkg/engine/parser/parser.go`): three header parsers, twenty-six body
// parsers, and a custom-field one. Our own `extractMapLinks` (`main.go:2861`)
// reads five element/attribute pairs. Measured on the shared fixture, the two
// together cover all 52 capabilities — but only if they run **in one crawl**.
//
// Before this file katana was reachable only as `bin/katana`, a second process
// with its own crawl, its own result shape, and its own place in the UI. That is
// a separate tool, not an integration: the operator would have to run two crawls
// and merge two maps by hand, and the evidence from one would not reach History
// or the Project.
//
// So the parsers are imported and called from inside our crawl loop, and the
// references they yield join the same queue the rest of the map uses.
//
// # Why the library and not a rewrite
//
// The thirty parsers are the upstream capability, tested there. Re-typing them
// would create a third copy to keep in sync and would make the reconciliation
// register a comparison against our own paraphrasing rather than against
// upstream. Importing makes the register's "совпадає" rows true by
// construction: the code we run is the code the register describes.
//
// The import is pinned to a commit (`04a51b8`, recorded in
// `reconciliation/katana_reconciliation.md`), so the parsers cannot move under
// a rebuild.
//
// # Why our own parser still runs
//
// `extractMapLinks` is not removed. Three reasons, each measured:
//
//   - it keeps its own frontier rule, which differs from katana's: our JS
//     analysis holds back references containing an expression so the crawl does
//     not follow a URL that was never written as one
//     (`containsJSExpression`, `target_javascript_test.go:162`);
//   - our `classifyMapURL` is the single source of `kind`, so a URL found by
//     katana lands in the map with the same classification as one found by us;
//   - katana's parsers yield relative references that still have to be resolved
//     against the page they were written in, and that resolution is ours.
//
// Both are called. The union is de-duplicated before it reaches the queue, so
// a link both find is enqueued once.

package main

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	katanaParser "github.com/projectdiscovery/katana/pkg/engine/parser"
	katanaNav "github.com/projectdiscovery/katana/pkg/navigation"
)

// katanaResponseParsers is the parser set from upstream, built once.
//
// `NewResponseParser` returns a value that holds only function pointers, so it
// is safe to share. It is still built under a `sync.Once` rather than at package
// init, because building it in `init` would run it before the first test could
// install a fixture, and the failure would then look like a broken parser.
var (
	katanaParsersOnce sync.Once
	katanaParsers     *katanaParser.Parser
)

// katanaParserSet returns upstream's parser set.
func katanaParserSet() *katanaParser.Parser {
	katanaParsersOnce.Do(func() {
		katanaParsers = katanaParser.NewResponseParser()
	})
	return katanaParsers
}

// katanaReferences runs upstream's parsers over one response and returns the
// references they found.
//
// Three things are deliberately NOT done here, because each would move a
// decision from our code into a library that knows nothing about this product:
//
//   - references are not resolved against the page. `mustResolveURL` is ours and
//     stays ours, so a relative reference is resolved the same way whether
//     `extractMapLinks` or katana found it;
//   - references are not filtered by scope. The scope decision is
//     `same_origin`, applied by the caller after both sets are merged, so
//     katana's parsers cannot widen the crawl;
//   - results are not deduplicated here. The caller already has a `seen` set,
//     and a second map would be a second answer to the same question.
func katanaReferences(statusCode int, header http.Header, contentType string, body []byte, pageURL *url.URL) []string {
	if len(body) == 0 {
		return nil
	}
	document, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		// A body goquery cannot parse yields no references. That is not a
		// failure of the crawl: our own extractor has already read the bytes, and
		// a malformed document is a fact about the target, not an error here.
		return nil
	}
	// # Why `Resp.Request` has to carry the page
	//
	// Upstream's parsers resolve a reference themselves:
	// `navigation.AbsoluteURL` calls `n.Resp.Request.URL.Parse(path)`. With a nil
	// `Request` that dereferences nil and panics — measured, not assumed: the
	// first run of this file crashed in `bodyATagParser` on every HTML page.
	//
	// The page URL is therefore part of the call, not an option. It is the URL the
	// body was served from, which is exactly the base a relative reference must
	// resolve against.
	response := &katanaNav.Response{
		Resp: &http.Response{
			StatusCode: statusCode,
			Header:     header,
			Request:    &http.Request{URL: pageURL},
		},
		Reader:     document,
		Depth:      0,
		Body:       string(body),
		StatusCode: statusCode,
	}
	if contentType != "" {
		response.Headers = katanaNav.Headers{"Content-Type": contentType}
	}

	requests := katanaParserSet().ParseResponse(response)
	if len(requests) == 0 {
		return nil
	}
	out := make([]string, 0, len(requests))
	for _, request := range requests {
		reference := strings.TrimSpace(request.URL)
		if reference == "" {
			continue
		}
		out = append(out, reference)
	}
	return out
}

// katanaHeaderReferences runs only the header parsers.
//
// It exists because a redirect answers with no body: `bodyParser` entries need
// `resp.Reader`, and a 302 has none, so the header parsers are the only thing
// that can say where the redirect goes. Calling them on the empty body of a
// redirect would return nothing, which would lose the single most common source
// of a link in a map.
func katanaHeaderReferences(statusCode int, header http.Header, pageURL *url.URL) []string {
	if header == nil {
		return nil
	}
	response := &katanaNav.Response{
		Resp: &http.Response{
			StatusCode: statusCode,
			Header:     header,
			Request:    &http.Request{URL: pageURL},
		},
		Depth:      0,
		StatusCode: statusCode,
	}
	requests := katanaParserSet().ParseResponse(response)
	out := make([]string, 0, len(requests))
	for _, request := range requests {
		reference := strings.TrimSpace(request.URL)
		if reference == "" {
			continue
		}
		out = append(out, reference)
	}
	return out
}

// # The four capabilities upstream's parsers do not yield
//
// The register claimed katana read 52 of 52. Measured against the same bytes,
// it reads 48: four of the fixture's capabilities come back empty from the
// upstream parser set, and the reasons are different in each case. All four were
// found by running upstream's own `ParseResponse` over the fixture documents and
// printing what it returned, not by reading its source and concluding.
//
//	<source src> / <source srcset>
//	    `NewResponseParser` registers parsers for `audio`, `video`, `img`,
//	    `embed`, `frame` and `object`, and none for `source`. There is no
//	    capability to miss: upstream never had one. `source` is how every real
//	    site ships its responsive images, so its absence is the single largest
//	    hole in the union.
//
//	<meta http-equiv="refresh" content="0; url=/next">
//	    `bodyMetaContentTagParser` reads the `content` attribute but does not
//	    look at `http-equiv`; it hands the value to
//	    `utils.ExtractRelativeEndpoints`, which is a JavaScript-endpoint regex.
//	    Measured: `ExtractRelativeEndpoints("/next.html")` returns nothing,
//	    `ExtractRelativeEndpoints("\"/next.html\"")` returns `/next.html`. It
//	    needs the path quoted *and* carrying a file extension. The standard
//	    refresh form is unquoted, so on a real page this parser never fires.
//	    Reading `http-equiv` and taking the `url=` parameter works on the
//	    standard form, so this is a fix rather than a substitute.
//
//	<iframe srcdoc="...">
//	    `bodyIframeTagParser` does read `srcdoc`, and passes it to the same
//	    `ExtractRelativeEndpoints`. Measured: the decoded attribute is
//	    `<a href="/probe-iframe-srcdoc">x</a>`, and the quoted path *without*
//	    an extension still yields nothing. Adding `.html` makes upstream fire.
//	    A `srcdoc` is a whole document, so parsing it as a document finds
//	    everything in it rather than the one shape a regex anticipates.
//
// None of this is a re-implementation of something upstream has. Each of the
// four is either absent or broken there, and each is measured broken or absent
// rather than assumed.
func frontierLayerReferences(statusCode int, pageURL *url.URL, body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	document, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil
	}
	return documentLayerReferences(document, statusCode, pageURL, 0)
}

// srcdocDepthLimit bounds how deep a `srcdoc` inside a `srcdoc` is followed.
//
// A `srcdoc` can contain an iframe whose `srcdoc` contains another. The limit
// exists because the nesting is attacker-controlled text: a document that nests
// itself a hundred deep would otherwise cost a hundred parses of a body the
// analyst never asked to render. Two levels is past anything a real page uses.
const srcdocDepthLimit = 2

// documentLayerReferences reads one document: our four capabilities, and — for a
// nested `srcdoc` — the whole chain again.
//
// The recursion runs `extractMapLinks` and katana's parsers over the nested
// markup as well, because a `srcdoc` is not a fragment of the outer page: it is
// a complete document that the browser renders on its own, and a link inside it
// is as real as one in the outer body. Running only this layer over it would
// find a nested `<source>` and miss a nested `<a href>`, which is a worse answer
// than the one the outer document gets.
func documentLayerReferences(document *goquery.Document, statusCode int, pageURL *url.URL, depth int) []string {
	var out []string

	document.Find("source").Each(func(_ int, item *goquery.Selection) {
		if value, ok := item.Attr("src"); ok {
			out = append(out, strings.TrimSpace(value))
		}
		if value, ok := item.Attr("srcset"); ok {
			out = append(out, srcsetReferences(value)...)
		}
	})

	document.Find("meta[http-equiv]").Each(func(_ int, item *goquery.Selection) {
		equiv, _ := item.Attr("http-equiv")
		if !strings.EqualFold(strings.TrimSpace(equiv), "refresh") {
			return
		}
		content, ok := item.Attr("content")
		if !ok {
			return
		}
		if target := metaRefreshTarget(content); target != "" {
			out = append(out, target)
		}
	})

	if depth < srcdocDepthLimit {
		document.Find("iframe[srcdoc]").Each(func(_ int, item *goquery.Selection) {
			nested, ok := item.Attr("srcdoc")
			if !ok || strings.TrimSpace(nested) == "" {
				return
			}
			inner, err := goquery.NewDocumentFromReader(strings.NewReader(nested))
			if err != nil {
				return
			}
			out = append(out, extractMapLinks(nested, "text/html")...)
			out = append(out, katanaReferences(statusCode, nil, "text/html", []byte(nested), pageURL)...)
			out = append(out, documentLayerReferences(inner, statusCode, pageURL, depth+1)...)
		})
	}

	return out
}

// srcsetReferences splits a `srcset` into its candidate URLs.
//
// The attribute is a comma-separated list of `url descriptor` pairs, and the
// descriptor is what makes a naive split wrong: `/a.png 1x, /b.png 2x` splits
// cleanly, but `/a.png 1x,/b.png 2x` — legal per the spec, since the comma may
// abut the previous candidate — yields a candidate whose URL ends in `1x`.
func srcsetReferences(value string) []string {
	var out []string
	for _, candidate := range strings.Split(value, ",") {
		fields := strings.Fields(strings.TrimSpace(candidate))
		if len(fields) == 0 {
			continue
		}
		out = append(out, fields[0])
	}
	return out
}

// metaRefreshTarget pulls the URL out of a refresh `content` value.
//
// The value is a delay, a semicolon and a `url=` parameter. Only the parameter
// matters here: the delay is how long the *browser* would wait, and a map has no
// browser to wait with. The parameter is matched case-insensitively because the
// HTML spec makes attribute values case-insensitive for the keywords.
func metaRefreshTarget(content string) string {
	for _, part := range strings.Split(content, ";") {
		trimmed := strings.TrimSpace(part)
		lower := strings.ToLower(trimmed)
		if !strings.HasPrefix(lower, "url=") {
			continue
		}
		target := strings.TrimSpace(trimmed[len("url="):])
		// The spec allows the value to be quoted, and pages do write it that
		// way. Both forms occur, and the quotes are not part of the URL.
		target = strings.Trim(target, `"'`)
		if target != "" {
			return target
		}
	}
	return ""
}

// mergeCrawlReferences joins our extractor's references with katana's, keeping
// the order of first appearance.
//
// Order matters more than it looks: the crawl is breadth-first, so the order in
// which references enter the queue is the order a reader sees pages in. Sorting
// the union would make the map look reproducible while hiding which extractor
// found what first, and a reviewer comparing two runs would be comparing
// alphabetical order rather than behaviour.
func mergeCrawlReferences(ours []string, theirs []string) []string {
	if len(ours) == 0 && len(theirs) == 0 {
		return nil
	}
	merged := make([]string, 0, len(ours)+len(theirs))
	seen := make(map[string]bool, len(ours)+len(theirs))
	for _, list := range [][]string{ours, theirs} {
		for _, reference := range list {
			trimmed := strings.TrimSpace(reference)
			if trimmed == "" || seen[trimmed] {
				continue
			}
			seen[trimmed] = true
			merged = append(merged, trimmed)
		}
	}
	return merged
}
