package active

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// The row an operator acts on is the one that names what the browser fetches:
// a script and a stylesheet over cleartext HTTP, with the URLs the markup
// spells.
func TestMixedContentActiveSubresource(t *testing.T) {
	detector := MixedContent{}
	p := Point{URL: "https://example.com/app", Method: http.MethodGet}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body: `<!DOCTYPE html><html><head>
			<link rel="stylesheet" href="http://cdn.example.invalid/site.css">
			<script src="http://cdn.example.invalid/app.js"></script>
		</head><body>ok</body></html>`,
	}

	findings := detector.Scan(context.Background(), nil, p, baseline)
	if len(findings) != 1 {
		t.Fatalf("expected one active-subresource row, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if !strings.Contains(f.Title, "active") {
		t.Errorf("title should say the subresources are active: %q", f.Title)
	}
	if f.Severity != SeverityMedium {
		t.Errorf("an active subresource should claim medium, got %v", f.Severity)
	}
	if !strings.Contains(f.Evidence, "http://cdn.example.invalid/site.css") ||
		!strings.Contains(f.Evidence, "http://cdn.example.invalid/app.js") {
		t.Errorf("evidence should name both cleartext URLs: %q", f.Evidence)
	}
	if !strings.Contains(f.Evidence, "<script>") || !strings.Contains(f.Evidence, "<link>") {
		t.Errorf("evidence should name the elements that fetch them: %q", f.Evidence)
	}
}

// What the browser loads is narrower than what the markup mentions. An anchor
// navigates on a click, a relative URL inherits the page's scheme, and a
// protocol-relative URL is not cleartext at all — none of those are mixed
// content, and a detector that reports them teaches the operator to ignore it.
func TestMixedContentIgnoresNavigationsAndInheritedSchemes(t *testing.T) {
	detector := MixedContent{}
	p := Point{URL: "https://example.com/app", Method: http.MethodGet}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body: `<!DOCTYPE html><html><head>
			<link rel="canonical" href="http://www.example.invalid/app">
			<link rel="stylesheet" href="/styles/site.css">
			<link rel="stylesheet" href="//cdn.example.invalid/site.css">
		</head><body>
			<a href="http://www.example.invalid/other">a navigation, not a load</a>
			<img src="images/logo.png" srcset="images/logo@2x.png 2x">
		</body></html>`,
	}

	if findings := detector.Scan(context.Background(), nil, p, baseline); len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

// A page served over cleartext HTTP has nothing to be mixed with: the module must
// stay silent there, because the finding is the contradiction and not the scheme.
func TestMixedContentSilentOnPlainHTTPPage(t *testing.T) {
	detector := MixedContent{}
	p := Point{URL: "http://example.com/app", Method: http.MethodGet}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body:       `<html><head><script src="http://cdn.example.invalid/app.js"></script></head></html>`,
	}

	if findings := detector.Scan(context.Background(), nil, p, baseline); len(findings) != 0 {
		t.Fatalf("expected 0 findings on a cleartext page, got %d: %+v", len(findings), findings)
	}
}

// An image is a load, so it is reported — separately from the active row, because
// a stylesheet that rewrites the page and a picture an observer can see are
// different decisions for the operator.
func TestMixedContentPassiveSubresourceSeparateRow(t *testing.T) {
	detector := MixedContent{}
	p := Point{URL: "https://example.com/app", Method: http.MethodGet}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body:       `<html><body><img src="http://cdn.example.invalid/logo.png"></body></html>`,
	}

	findings := detector.Scan(context.Background(), nil, p, baseline)
	if len(findings) != 1 {
		t.Fatalf("expected one passive-subresource row, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != SeverityLow {
		t.Errorf("a passive subresource should claim low, got %v", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Evidence, "http://cdn.example.invalid/logo.png") {
		t.Errorf("evidence should name the cleartext image: %q", findings[0].Evidence)
	}
}

// A `<base href>` over cleartext HTTP makes every relative URL on the page
// cleartext too, which is the row's highest-severity shape.
func TestMixedContentBaseHrefIsActive(t *testing.T) {
	detector := MixedContent{}
	p := Point{URL: "https://example.com/app", Method: http.MethodGet}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body:       `<html><head><base href="http://cdn.example.invalid/"></head><body>ok</body></html>`,
	}

	findings := detector.Scan(context.Background(), nil, p, baseline)
	if len(findings) == 0 || findings[0].Severity != SeverityMedium {
		t.Fatalf("expected a cleartext <base> to claim medium, got: %+v", findings)
	}
}
