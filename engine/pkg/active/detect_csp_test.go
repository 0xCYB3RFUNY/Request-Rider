package active

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestCSPWeaknesses(t *testing.T) {
	detector := CSP{}
	p := Point{URL: "https://example.com/app", Method: http.MethodGet}

	// Baseline with unsafe-inline without nonce and missing frame-ancestors
	baseline := &Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":            {"text/html; charset=utf-8"},
			"Content-Security-Policy": {"default-src 'self'; script-src 'self' 'unsafe-inline'"},
		},
	}

	findings := detector.Scan(context.Background(), nil, p, baseline)
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings (unsafe-inline + missing frame-ancestors), got %d: %+v", len(findings), findings)
	}

	foundInline := false
	foundFrame := false
	for _, f := range findings {
		if strings.Contains(f.Title, "unsafe-inline") {
			foundInline = true
		}
		if strings.Contains(f.Title, "frame-ancestors") {
			foundFrame = true
		}
	}

	if !foundInline {
		t.Errorf("missing unsafe-inline finding")
	}
	if !foundFrame {
		t.Errorf("missing frame-ancestors finding")
	}
}

func TestCSPStrictPolicyPasses(t *testing.T) {
	detector := CSP{}
	p := Point{URL: "https://example.com/app", Method: http.MethodGet}

	// Strict CSP with nonce and frame-ancestors
	baseline := &Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":            {"text/html; charset=utf-8"},
			"Content-Security-Policy": {"default-src 'self'; script-src 'self' 'nonce-rAnd0m'; frame-ancestors 'none'; form-action 'self'"},
		},
	}

	findings := detector.Scan(context.Background(), nil, p, baseline)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for strict CSP, got %d: %+v", len(findings), findings)
	}
}

// A stylesheet can restyle the page into a credential form with no script at
// all, so `style-src 'unsafe-inline'` is its own row rather than a duplicate of
// the script one.
func TestCSPUnsafeInlineStyle(t *testing.T) {
	detector := CSP{}
	p := Point{URL: "https://example.com/app", Method: http.MethodGet}
	baseline := &Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": {"text/html; charset=utf-8"},
			"Content-Security-Policy": {"default-src 'self'; script-src 'self'; " +
				"style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'"},
		},
	}

	findings := detector.Scan(context.Background(), nil, p, baseline)
	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Untrusted Style") {
			found = true
			if !strings.Contains(f.Evidence, "style-src") {
				t.Errorf("the row should quote the directive that permits it: %q", f.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("expected an untrusted-style row, got: %+v", findings)
	}
}
