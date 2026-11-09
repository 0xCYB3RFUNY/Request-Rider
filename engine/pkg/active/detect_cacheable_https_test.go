package active

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// A cacheable response carrying a session cookie is the finding; the same
// response marked `no-store` is not, because it never leaves the client.
func TestCacheableSecurityResponseNamesWhatTheCacheMayHold(t *testing.T) {
	baseline := &Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type":  {"text/html"},
			"Cache-Control": {"public, max-age=600"},
			"Set-Cookie":    {"session=abc123; Path=/"},
		},
		Body: "<html><body>account overview</body></html>",
	}
	point := Point{URL: "https://example.com/account", Method: http.MethodGet}
	findings := (CacheableSecurityResponse{}).Scan(context.Background(), nil, point, baseline)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "max-age=600") {
		t.Errorf("evidence does not name the caching headers: %s", findings[0].Evidence)
	}
}

// The control pair: the same body with `no-store` is silent, and the same
// caching headers on a page that carries nothing per-recipient is silent too. A
// detector that reported either would be reporting the cache itself rather than
// what it holds.
func TestCacheableSecurityResponseIsSilentOnEitherHalfAlone(t *testing.T) {
	cases := []struct {
		name   string
		header map[string][]string
		body   string
		scheme string
	}{
		{"cache told not to store", map[string][]string{
			"Content-Type": {"text/html"}, "Cache-Control": {"no-store"},
			"Set-Cookie": {"session=abc; Path=/"}}, "account overview", "https://example.com/account"},
		{"nothing per-recipient in the body", map[string][]string{
			"Content-Type": {"text/html"}, "Cache-Control": {"public, max-age=600"}},
			"a public landing page about the weather", "https://example.com/"},
		{"the page is not secure to begin with", map[string][]string{
			"Content-Type": {"text/html"}, "Cache-Control": {"public, max-age=600"},
			"Set-Cookie": {"session=abc; Path=/"}}, "account overview", "http://example.com/account"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			baseline := &Response{StatusCode: 200, Header: http.Header(testCase.header), Body: testCase.body}
			findings := (CacheableSecurityResponse{}).Scan(context.Background(), nil,
				Point{URL: testCase.scheme, Method: http.MethodGet}, baseline)
			if len(findings) != 0 {
				t.Fatalf("findings = %d, want 0: %+v", len(findings), findings[0].Title)
			}
		})
	}
}
