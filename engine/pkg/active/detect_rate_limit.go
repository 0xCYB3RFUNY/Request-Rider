package active

import (
	"context"
	"net/http"
	"strings"
)

// RateLimit checks authentication and verification endpoints for missing
// brute-force throttling or account lockout (CWE-307).
type RateLimit struct{}

// Name implements Module.
func (RateLimit) Name() string { return "rate_limit" }

// Level implements Module.
func (RateLimit) Level() Level { return LevelEndpoint }

var authPathHints = []string{
	"/login", "/signin", "/auth", "/token", "/reset-password", "/forgot-password", "/otp", "/verify",
}

func isAuthRateLimitCandidate(p Point) bool {
	lowerURL := strings.ToLower(p.URL)
	for _, h := range authPathHints {
		if strings.Contains(lowerURL, h) {
			return true
		}
	}
	return false
}

// Scan sends a bounded burst of 6 invalid-credential requests to an auth
// endpoint and reports a finding if none are throttled (429/423/Retry-After).
func (RateLimit) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || !isAuthRateLimitCandidate(p) {
		return nil
	}
	const burstAttempts = 6
	method := p.Method
	if method == "" {
		method = http.MethodPost
	}
	canary := newCanary("rrrl")
	if canary == "" {
		return nil
	}

	throttled := false
	succeeded := 0
	var lastStatus int
	for i := 0; i < burstAttempts; i++ {
		if ctx.Err() != nil {
			return nil
		}
		values := cloneValues(p.Values)
		if p.Param != "" {
			values.Set(p.Param, canary)
		} else {
			values.Set("password", canary)
		}
		resp, err := t.Do(ctx, method, p.URL, values, false, nil)
		if err != nil || resp == nil {
			return nil
		}
		lastStatus = resp.StatusCode
		if resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode == http.StatusLocked ||
			resp.Header.Get("Retry-After") != "" ||
			containsAnyFold(resp.Body, []string{"rate limit", "too many attempts", "try again later", "captcha", "account locked"}) {
			throttled = true
			break
		}
		succeeded++
	}

	if throttled || succeeded < burstAttempts || t.BackoffCount() > 0 {
		return nil
	}
	f, _ := NewFinding(Spec{
		Module:   "rate_limit",
		Title:    "Missing brute-force rate limiting on authentication endpoint " + p.URL,
		Claimed:  SeverityMedium,
		Tier:     TierPotential,
		Point:    Point{URL: p.URL, Method: method, Param: p.Param, Source: p.Source},
		Payload:  "6 consecutive authentication attempts",
		Evidence: http.StatusText(lastStatus),
		Description: "The authentication endpoint accepted 6 consecutive invalid-credential probes without " +
			"returning HTTP 429, Retry-After, account lockout, or CAPTCHA challenges (CWE-307).",
		Remediation: "Enforce per-IP and per-account rate limiting, exponential backoff, and temporary " +
			"account lockout or CAPTCHA challenges on authentication and recovery endpoints.",
	})
	return []Finding{f}
}
