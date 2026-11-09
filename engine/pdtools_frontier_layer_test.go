package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The four capabilities upstream's parser set does not yield.
//
// Each case uses a focused inline document, so a parser regression fails here
// rather than silently in a broader crawl.
//
// These assertions must go red when `frontierLayerReferences` is broken, so the
// mutation check in `TestFrontierLayerReferencesRedWithoutTheLayer` removes the
// call and records that four cases stop passing.

func fixturePageURL(t *testing.T) *url.URL {
	t.Helper()
	parsed, err := url.Parse("http://127.0.0.1:1/cap/a_href")
	if err != nil {
		t.Fatalf("fixture page url: %v", err)
	}
	return parsed
}

func TestFrontierLayerReadsTheFourUpstreamMisses(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			// Upstream registers no `<source>` parser at all: `NewResponseParser`
			// has audio, video, img, embed, frame and object, and no source.
			name: "source src",
			body: `<video><source src="/probe-source-src"></video>`,
			want: "/probe-source-src",
		},
		{
			// The attribute is a list, and the descriptor is what makes a naive
			// split wrong: `/a 1x,/b 2x` is legal and yields a URL ending `1x`.
			name: "source srcset with an abutting comma",
			body: `<picture><source srcset="/probe-source-srcset 1x,/probe-source-srcset-2x 2x"></picture>`,
			want: "/probe-source-srcset-2x",
		},
		{
			// Upstream ignores `http-equiv` and hands the value to a JS-endpoint
			// regex that needs the path quoted. The standard form is unquoted.
			name: "meta refresh, unquoted, as the standard writes it",
			body: `<meta http-equiv="refresh" content="0; url=/probe-meta-refresh">`,
			want: "/probe-meta-refresh",
		},
		{
			// Upstream reads `srcdoc` through the same regex, so a path without an
			// extension vanishes. Parsing it as a document finds the link.
			name: "iframe srcdoc, extensionless link",
			body: `<iframe srcdoc="&lt;a href=&quot;/probe-iframe-srcdoc&quot;&gt;x&lt;/a&gt;"></iframe>`,
			want: "/probe-iframe-srcdoc",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			references := frontierLayerReferences(200, fixturePageURL(t), []byte(testCase.body))
			for _, reference := range references {
				if reference == testCase.want {
					return
				}
			}
			t.Fatalf("frontierLayerReferences(%q) = %v, want it to contain %q",
				testCase.body, references, testCase.want)
		})
	}
}

// A refresh whose URL is quoted is legal and occurs on real pages. The quotes are
// not part of the URL, so a map that kept them would queue a URL nothing serves.
func TestMetaRefreshTargetUnquotes(t *testing.T) {
	cases := map[string]string{
		`0; url=/next`:      "/next",
		`0; url="/next"`:    "/next",
		`0; url='/next'`:    "/next",
		`5; URL=/next`:      "/next",
		`0`:                 "",
		`0; url=`:           "",
		`0; url=/a; url=/b`: "/a",
		// Whatever precedes `url=` is the delay, and the delay is not required
		// to be a number for the URL to be there. Dropping the whole value
		// because the first field is not a delay would lose the target on a
		// page that wrote it that way.
		`refresh; url=/next`: "/next",
	}
	for content, want := range cases {
		if got := metaRefreshTarget(content); got != want {
			t.Errorf("metaRefreshTarget(%q) = %q, want %q", content, got, want)
		}
	}
}

// A `meta` that is not a refresh must not produce anything. `og:url` and
// `description` live in `content` too, and a map that enqueued them would report
// social-image URLs as pages.
func TestFrontierLayerIgnoresNonRefreshMeta(t *testing.T) {
	body := `<meta property="og:url" content="/probe-og-url">` +
		`<meta name="description" content="/probe-description">`
	if references := frontierLayerReferences(200, fixturePageURL(t), []byte(body)); len(references) != 0 {
		t.Fatalf("frontierLayerReferences read %v from non-refresh meta, want nothing", references)
	}
}

// The recursion is bounded: `srcdoc` is attacker-controlled text and a document
// may nest itself as deeply as it likes.
func TestFrontierLayerBoundsSrcdocNesting(t *testing.T) {
	// Build `<iframe srcdoc="...">` nested past the limit, with a marker at the
	// bottom. The marker must not be found, and the call must return.
	body := `<a href="/probe-too-deep">x</a>`
	for i := 0; i < srcdocDepthLimit+3; i++ {
		body = `<iframe srcdoc="` + htmlEscapeAttribute(body) + `"></iframe>`
	}
	references := frontierLayerReferences(200, fixturePageURL(t), []byte(body))
	for _, reference := range references {
		if reference == "/probe-too-deep" {
			t.Fatalf("the recursion followed srcdoc past srcdocDepthLimit=%d", srcdocDepthLimit)
		}
	}
}

// An empty body is not an error and must not panic: a redirect has none, and the
// crawler calls this for every response it reads.
func TestFrontierLayerOnEmptyBody(t *testing.T) {
	if references := frontierLayerReferences(200, fixturePageURL(t), nil); references != nil {
		t.Fatalf("frontierLayerReferences(nil) = %v, want nil", references)
	}
}

func htmlEscapeAttribute(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", `"`, "&quot;", "<", "&lt;", ">", "&gt;")
	return replacer.Replace(value)
}

// The four cases above must fail without the layer. If they do not, the layer is
// not what is being measured and the coverage number would be reading something
// else.
func TestFrontierLayerReferencesRedWithoutTheLayer(t *testing.T) {
	body := `<video><source src="/probe-source-src"></video>` +
		`<meta http-equiv="refresh" content="0; url=/probe-meta-refresh">` +
		`<picture><source srcset="/probe-source-srcset 1x"></picture>` +
		`<iframe srcdoc="&lt;a href=&quot;/probe-iframe-srcdoc&quot;&gt;x&lt;/a&gt;"></iframe>`

	withoutLayer := mergeCrawlReferences(
		extractMapLinks(body, "text/html"),
		katanaReferences(200, http.Header{}, "text/html", []byte(body), fixturePageURL(t)),
	)

	wanted := []string{
		"/probe-source-src", "/probe-meta-refresh",
		"/probe-source-srcset", "/probe-iframe-srcdoc",
	}
	for _, marker := range wanted {
		for _, reference := range withoutLayer {
			if reference == marker {
				t.Errorf("%s is reachable without frontierLayerReferences, so this layer "+
					"is not what provides it and the coverage number is measuring something else",
					marker)
			}
		}
	}
}
