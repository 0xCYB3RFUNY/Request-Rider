package active

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// CORS probes an endpoint for Cross-Origin Resource Sharing vulnerabilities:
// - Arbitrary origin reflection with or without credentials (0x00200601)
// - "null" origin trusted (0x00200601)
// - Unencrypted HTTP origin allowed on HTTPS target (0x00200602)
// - Arbitrary subdomain trusted (0x00200603)
type CORS struct{}

// Name implements Module.
func (CORS) Name() string { return "cors" }

// Level implements Module.
func (CORS) Level() Level { return LevelEndpoint }

func (c CORS) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if isPublicResource(p.URL) {
		return nil
	}
	parsed, err := url.Parse(p.URL)
	if err != nil {
		return nil
	}

	var out []Finding

	// Probe 1: Arbitrary External Origin (0x00200601)
	arbitraryOrigin := "https://evil-attacker.com"
	if f := c.checkOrigin(ctx, t, p, arbitraryOrigin, "Arbitrary Origin Trusted", SeverityMedium,
		"The endpoint trusts an arbitrary external origin. A malicious website can make cross-origin requests to read sensitive data."); f != nil {
		out = append(out, *f)
	}

	// Probe 2: Null Origin Trusted (0x00200601)
	// Null origin is used by sandboxed iframes (<iframe sandbox="allow-scripts" src="...">)
	nullOrigin := "null"
	if f := c.checkOrigin(ctx, t, p, nullOrigin, "Null Origin Trusted", SeverityMedium,
		"The endpoint trusts the 'null' origin. An attacker can host an exploit inside a sandboxed iframe to bypass origin restrictions."); f != nil {
		out = append(out, *f)
	}

	// Probe 3: Insecure Unencrypted HTTP Origin on HTTPS (0x00200602)
	if strings.EqualFold(parsed.Scheme, "https") && parsed.Host != "" {
		insecureOrigin := "http://" + parsed.Host
		resp, err := t.Do(ctx, http.MethodGet, p.URL, nil, false, http.Header{
			"Origin": {insecureOrigin},
		})
		if err == nil && resp != nil {
			allowed := resp.HeaderValue("Access-Control-Allow-Origin")
			if strings.EqualFold(allowed, insecureOrigin) {
				evidence := fmt.Sprintf("Access-Control-Allow-Origin: %s on HTTPS endpoint", allowed)
				finding, _ := NewFinding(Spec{
					Module:      "cors",
					Title:       "CORS: Unencrypted HTTP Origin Trusted",
					Claimed:     SeverityLow,
					Tier:        TierVerified,
					Point:       p,
					Payload:     "Origin: " + insecureOrigin,
					Evidence:    evidence,
					Description: "The HTTPS endpoint trusts an unencrypted HTTP origin. An attacker capable of active network interception (e.g. public WiFi) can inject malicious JavaScript into plaintext HTTP traffic to read responses from this HTTPS endpoint.",
					Remediation: "Ensure Access-Control-Allow-Origin only permits trusted HTTPS origins.",
				})
				out = append(out, finding)
			}
		}
	}

	// Probe 4: Arbitrary Subdomain Trusted (0x00200603)
	if parsed.Host != "" && !strings.Contains(parsed.Host, ":") && strings.Contains(parsed.Host, ".") {
		subdomainOrigin := "https://attacker." + parsed.Host
		if f := c.checkOrigin(ctx, t, p, subdomainOrigin, "All Subdomains Trusted", SeverityLow,
			"The endpoint trusts arbitrary subdomains. An XSS or takeover on any subdomain allows an attacker to access this endpoint."); f != nil {
			// Only report if arbitrary origin wasn't already reported (avoid noise)
			if len(out) == 0 {
				out = append(out, *f)
			}
		}
	}

	return out
}

func (c CORS) checkOrigin(ctx context.Context, t *Transport, p Point, probeOrigin, titleSuffix string, baseSeverity Severity, desc string) *Finding {
	resp, err := t.Do(ctx, http.MethodGet, p.URL, nil, false, http.Header{
		"Origin": {probeOrigin},
	})
	if err != nil || resp == nil {
		return nil
	}

	allowed := resp.HeaderValue("Access-Control-Allow-Origin")
	if allowed == "" {
		return nil
	}

	credentialed := strings.EqualFold(resp.HeaderValue("Access-Control-Allow-Credentials"), "true")
	wildcard := allowed == "*"
	if wildcard && credentialed {
		// Browsers strictly reject '*' with credentials: true
		return nil
	}

	reflected := strings.EqualFold(allowed, probeOrigin)
	if !reflected {
		return nil
	}

	claimed := baseSeverity
	title := "CORS: " + titleSuffix
	if credentialed {
		claimed = SeverityHigh
		title = "CORS with Credentials: " + titleSuffix
		desc += " Because Access-Control-Allow-Credentials is true, user cookies and authentication headers are included in cross-origin reads."
	}

	evidence := fmt.Sprintf("Access-Control-Allow-Origin: %s | Access-Control-Allow-Credentials: %s",
		allowed, resp.HeaderValue("Access-Control-Allow-Credentials"))

	finding, _ := NewFinding(Spec{
		Module:      "cors",
		Title:       title,
		Claimed:     claimed,
		Tier:        TierVerified,
		Point:       p,
		Payload:     "Origin: " + probeOrigin,
		Evidence:    evidence,
		Description: desc,
		Remediation: "Do not dynamically reflect Origin headers or trust 'null'. Maintain a strict server-side allowlist of trusted origins.",
	})
	return &finding
}
