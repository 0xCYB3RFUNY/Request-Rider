package active

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// A duplicate cookie name is a disagreement the response makes with itself, so
// the row has to quote both lines: which of the two survives is the client's
// decision, and the difference between the lines is what the operator triages.
func TestResponseHeadersDuplicateCookieName(t *testing.T) {
	detector := ResponseHeaders{}
	p := Point{URL: "https://example.com/app", Method: http.MethodGet}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": {"text/html; charset=utf-8"},
			"Set-Cookie": {
				"session=abc123; Path=/; HttpOnly",
				"session=def456; Path=/admin",
			},
		},
		Body: "<html><body>ok</body></html>",
	}

	findings := detector.Scan(context.Background(), nil, p, baseline)
	duplicates := 0
	for _, f := range findings {
		if strings.Contains(f.Title, "Duplicate Cookies") {
			duplicates++
			if !strings.Contains(f.Evidence, "session=abc123") || !strings.Contains(f.Evidence, "session=def456") {
				t.Errorf("evidence does not quote both lines: %q", f.Evidence)
			}
			if f.Tier != TierVerified {
				t.Errorf("a header fact should be verified, got tier %v", f.Tier)
			}
		}
	}
	if duplicates != 1 {
		t.Fatalf("expected exactly 1 duplicate-cookie row, got %d: %+v", duplicates, findings)
	}
}

// Two distinct cookie names in two headers is how a hardened application sets
// cookies, so the row must not fire on it.
func TestResponseHeadersDistinctCookieNamesPass(t *testing.T) {
	detector := ResponseHeaders{}
	p := Point{URL: "https://example.com/app", Method: http.MethodGet}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": {"text/html; charset=utf-8"},
			"Set-Cookie": {
				"session=abc123; Path=/; HttpOnly; Secure",
				"prefs=dark; Path=/; Max-Age=600",
			},
		},
		Body: "<html><body>ok</body></html>",
	}

	findings := detector.Scan(context.Background(), nil, p, baseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for distinct cookie names, got %d: %+v", len(findings), findings)
	}
}

// A body that says it is HTML under a header that says it is not is the row this
// module exists for.
func TestResponseHeadersContentTypeContradictsBody(t *testing.T) {
	detector := ResponseHeaders{}
	p := Point{URL: "https://example.com/app", Method: http.MethodGet}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": {"text/plain"},
		},
		Body: "<!DOCTYPE html><html><body>form</body></html>",
	}

	findings := detector.Scan(context.Background(), nil, p, baseline)
	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Content Type Incorrectly Stated") {
			found = true
			if !strings.Contains(f.Evidence, "text/plain") || !strings.Contains(f.Evidence, "<!DOCTYPE html>") {
				t.Errorf("evidence should name both the declared type and the body opening: %q", f.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("expected an incorrectly-stated content type row, got: %+v", findings)
	}
}

// An HTML response with no Content-Type at all leaves the decode to the client's
// guess, and one with an unknown charset name leaves it to a fallback that
// pretends to be a decision. Both are facts and both are reported.
func TestResponseHeadersCharsetFacts(t *testing.T) {
	detector := ResponseHeaders{}
	p := Point{URL: "https://example.com/app", Method: http.MethodGet}

	missing := &Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/html"}},
		Body:       "<html><body>ok</body></html>",
	}
	found := false
	for _, f := range detector.Scan(context.Background(), nil, p, missing) {
		if strings.Contains(f.Title, "HTML Charset Missing") {
			found = true
		}
	}
	if !found {
		t.Error("expected a missing-charset row for a charsetless text/html response")
	}

	unknown := &Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/html; charset=x-vendor-9"}},
		Body:       "<html><body>ok</body></html>",
	}
	found = false
	for _, f := range detector.Scan(context.Background(), nil, p, unknown) {
		if strings.Contains(f.Title, "HTML Charset Unrecognized") {
			found = true
			if !strings.Contains(f.Evidence, "x-vendor-9") {
				t.Errorf("evidence should name the charset the header claimed: %q", f.Evidence)
			}
		}
	}
	if !found {
		t.Error("expected an unrecognized-charset row for a charset no client implements")
	}
}

// A stylesheet is not an HTML document, so the content-type rows must not fire
// on it — the module reports endpoints that disagree with themselves, not
// endpoints it does not like.
func TestResponseHeadersNonHTMLPasses(t *testing.T) {
	detector := ResponseHeaders{}
	p := Point{URL: "https://example.com/app.css", Method: http.MethodGet}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/css"}},
		Body:       "body{color:#080c12}",
	}

	if findings := detector.Scan(context.Background(), nil, p, baseline); len(findings) != 0 {
		t.Fatalf("expected 0 findings for a stylesheet, got %d: %+v", len(findings), findings)
	}
}
