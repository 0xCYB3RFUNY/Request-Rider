package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// foreignScript is a page that loads code from a host that is not its own, plus
// one reference from its own origin that must not be reported.
const foreignScript = `<html><head>` +
	`<script src="https://cdn.other-host.example/app.js"></script>` +
	`<link rel="stylesheet" href="https://fonts.other-host.example/sheet.css">` +
	`<link rel="canonical" href="https://wiki.other-host.example/self">` +
	`<script src="/static/own.js"></script>` +
	`</head><body></body></html>`

func TestScriptIncludeOfAnotherDomainNamesTheForeignHosts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(foreignScript))
	}))
	defer server.Close()

	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: foreignScript}
	findings := (ScriptIncludeOfAnotherDomain{}).Scan(context.Background(), nil,
		Point{URL: server.URL + "/", Method: http.MethodGet}, baseline)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	evidence := findings[0].Evidence
	if !strings.Contains(evidence, "cdn.other-host.example") {
		t.Errorf("evidence names no CDN: %s", evidence)
	}
	if strings.Contains(evidence, "wiki.other-host.example") {
		t.Errorf("a canonical link is a reference, not a load: %s", evidence)
	}
}

// A page that loads only its own code is the control: a same-origin include is
// the normal case and reporting it would be noise.
func TestScriptIncludeOfAnotherDomainIsSilentOnSameOriginCode(t *testing.T) {
	body := `<html><head><script src="/static/own.js"></script>` +
		`<link rel="stylesheet" href="/static/own.css"></head><body></body></html>`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(body))
	}))
	defer server.Close()

	baseline := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: body}
	findings := (ScriptIncludeOfAnotherDomain{}).Scan(context.Background(), nil,
		Point{URL: server.URL + "/", Method: http.MethodGet}, baseline)
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}

// A public resource — a robots.txt, a sitemap, an error page — is not a page that
// carries a dependency, and reading one as if it were would report the
// application's own routing as a finding.
func TestScriptIncludeOfAnotherDomainSkipsPublicResources(t *testing.T) {
	findings := (ScriptIncludeOfAnotherDomain{}).Scan(context.Background(), nil,
		Point{URL: "http://example.com/robots.txt", Method: http.MethodGet},
		&Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/plain"}}, Body: "User-agent: *"})
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}
