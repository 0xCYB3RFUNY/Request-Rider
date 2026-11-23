package active

import (
	"context"
	"fmt"
	"strings"
)

// CSP analyzes Content Security Policy headers for weaknesses.
// Corresponds to Burp Suite checks:
// 0x00200503 (CSP allowlisted script resources)
// 0x00200504 (CSP allows untrusted script execution)
// 0x00200505 (CSP allows untrusted style execution)
// 0x00200506 (CSP allows clickjacking)
// 0x00200507 (CSP allows form hijacking)
// 0x00200508 (CSP not enforced)
type CSP struct{}

// Name implements Module.
func (CSP) Name() string { return "csp" }

// Level implements Module.
func (CSP) Level() Level { return LevelEndpoint }

func (c CSP) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.StatusCode >= 400 || isPublicResource(p.URL) {
		return nil
	}

	contentType := strings.ToLower(baseline.HeaderValue("Content-Type"))
	if !strings.Contains(contentType, "text/html") && contentType != "" {
		return nil
	}

	csp := baseline.HeaderValue("Content-Security-Policy")
	reportOnly := baseline.HeaderValue("Content-Security-Policy-Report-Only")

	var out []Finding

	// Check 1: CSP Report-Only without Enforcement (0x00200508)
	if csp == "" && reportOnly != "" {
		finding, _ := NewFinding(Spec{
			Module:      "csp",
			Title:       "Content Security Policy Not Enforced (Report-Only)",
			Claimed:     SeverityLow,
			Tier:        TierVerified,
			Point:       p,
			Evidence:    "Content-Security-Policy-Report-Only: " + reportOnly,
			Description: "The policy is configured in report-only mode and is not enforced by the browser. Violations are reported but malicious actions are not blocked.",
			Remediation: "Switch from Content-Security-Policy-Report-Only to Content-Security-Policy once policies have been validated.",
		})
		out = append(out, finding)
	}

	if csp == "" {
		return out
	}

	directives := parseCSPDirectives(csp)

	// Check 2: Unsafe inline scripts (0x00200504)
	scriptSrc, hasScriptSrc := directives["script-src"]
	if !hasScriptSrc {
		scriptSrc = directives["default-src"]
	}

	if strings.Contains(scriptSrc, "'unsafe-inline'") && !hasNonceOrHash(scriptSrc) {
		evidence := fmt.Sprintf("Directive %q contains 'unsafe-inline' without nonce or hash.", scriptSrc)
		finding, _ := NewFinding(Spec{
			Module:      "csp",
			Title:       "Content Security Policy: Allows Untrusted Script Execution ('unsafe-inline')",
			Claimed:     SeverityMedium,
			Tier:        TierVerified,
			Point:       p,
			Evidence:    evidence,
			Description: "The Content Security Policy includes 'unsafe-inline' for scripts without nonces or cryptographic hashes, rendering CSP ineffective against Cross-Site Scripting (XSS).",
			Remediation: "Remove 'unsafe-inline' and use cryptographic nonces (nonce-...) or SHA-256 hashes for authorized inline scripts.",
		})
		out = append(out, finding)
	}

	// Check 3: Wildcard script source (0x00200503)
	if strings.Contains(scriptSrc, "*") || strings.Contains(scriptSrc, "https:") || strings.Contains(scriptSrc, "http:") {
		evidence := fmt.Sprintf("Directive %q uses wildcard or overly broad scheme sources.", scriptSrc)
		finding, _ := NewFinding(Spec{
			Module:      "csp",
			Title:       "Content Security Policy: Wildcard Script Source",
			Claimed:     SeverityLow,
			Tier:        TierVerified,
			Point:       p,
			Evidence:    evidence,
			Description: "The script-src directive allows loading scripts from arbitrary domains or any HTTPS URL, allowing attackers to host malicious payloads on external servers.",
			Remediation: "Restrict script sources to specific trusted origin domains or use strict hash/nonce-based CSP.",
		})
		out = append(out, finding)
	}

	// Check 4: Clickjacking protection (0x00200506)
	if _, hasFrameAncestors := directives["frame-ancestors"]; !hasFrameAncestors {
		xfo := baseline.HeaderValue("X-Frame-Options")
		if xfo == "" {
			finding, _ := NewFinding(Spec{
				Module:      "csp",
				Title:       "Content Security Policy: Missing frame-ancestors (Allows Clickjacking)",
				Claimed:     SeverityLow,
				Tier:        TierVerified,
				Point:       p,
				Evidence:    "Neither CSP frame-ancestors nor X-Frame-Options is defined.",
				Description: "The application does not restrict embedding in iframes via CSP frame-ancestors. An attacker can frame the application to conduct clickjacking attacks.",
				Remediation: "Add 'frame-ancestors 'none'' or 'frame-ancestors 'self'' to Content-Security-Policy.",
			})
			out = append(out, finding)
		}
	}

	// Check 5: Form hijacking (0x00200507)
	if _, hasFormAction := directives["form-action"]; !hasFormAction {
		finding, _ := NewFinding(Spec{
			Module:      "csp",
			Title:       "Content Security Policy: Missing form-action (Allows Form Hijacking)",
			Claimed:     SeverityInfo,
			Tier:        TierVerified,
			Point:       p,
			Evidence:    "Directive form-action is missing from CSP.",
			Description: "The policy omits form-action. If HTML injection exists, an attacker can modify a form's action attribute to exfiltrate submitted data to a remote host.",
			Remediation: "Set form-action 'self' or explicit target endpoints in Content-Security-Policy.",
		})
		out = append(out, finding)
	}

	// Check 6: Unsafe inline styles (0x00200505)
	//
	// The mirror of Check 2, for the directive that governs what the page looks
	// like rather than what it does. It is not a weaker duplicate: a stylesheet
	// can cover the page in a form that says "your session expired, sign in
	// again", and none of that needs script. The fallback to `default-src` is the
	// same rule Check 2 follows — a policy that constrains only `style-src` says
	// nothing about what `default-src` leaves open.
	styleSrc, hasStyleSrc := directives["style-src"]
	sourceDirective := "style-src"
	if !hasStyleSrc {
		styleSrc = directives["default-src"]
		sourceDirective = "default-src"
	}
	if strings.Contains(styleSrc, "'unsafe-inline'") && !hasNonceOrHash(styleSrc) {
		evidence := fmt.Sprintf("Directive %s = %q contains 'unsafe-inline' without nonce or hash.", sourceDirective, styleSrc)
		finding, _ := NewFinding(Spec{
			Module:      "csp",
			Title:       "Content Security Policy: Allows Untrusted Style Execution ('unsafe-inline')",
			Claimed:     SeverityLow,
			Tier:        TierVerified,
			Point:       p,
			Evidence:    evidence,
			Description: "The Content Security Policy permits inline styles. An attacker who can inject a style element or attribute can reposition, overlay and restyle the page — a credential form built out of CSS needs no script at all — and the policy offers no protection against it.",
			Remediation: "Move styles into static files the policy allowlists, or use nonces and hashes for the inline styles that must stay.",
		})
		out = append(out, finding)
	}

	return out
}

func parseCSPDirectives(csp string) map[string]string {
	res := make(map[string]string)
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Fields(part)
		if len(fields) > 0 {
			res[strings.ToLower(fields[0])] = strings.Join(fields[1:], " ")
		}
	}
	return res
}

func hasNonceOrHash(val string) bool {
	lower := strings.ToLower(val)
	return strings.Contains(lower, "'nonce-") ||
		strings.Contains(lower, "'sha256-") ||
		strings.Contains(lower, "'sha384-") ||
		strings.Contains(lower, "'sha512-")
}
