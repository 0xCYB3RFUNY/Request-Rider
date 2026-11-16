package active

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// CachePoisoning probes endpoints for unkeyed HTTP header reflection
// and web cache poisoning vulnerabilities.
// Corresponds to Burp Suite check:
// 0x00200180 (Web cache poisoning)
type CachePoisoning struct{}

// Name implements Module.
func (CachePoisoning) Name() string { return "cache-poisoning" }

// Level implements Module.
func (CachePoisoning) Level() Level { return LevelEndpoint }

type unkeyedHeaderProbe struct {
	name        string
	value       string
	description string
}

var cachePoisonProbes = []unkeyedHeaderProbe{
	{"X-Forwarded-Host", "rr-cache-poison.invalid", "unkeyed X-Forwarded-Host header"},
	{"X-Host", "rr-cache-poison.invalid", "unkeyed X-Host header"},
	{"X-Forwarded-Prefix", "/rr-poison-prefix", "unkeyed X-Forwarded-Prefix path injection"},
	{"X-Original-URL", "/rr-unkeyed-rewrite", "unkeyed X-Original-URL route override"},
}

func (c CachePoisoning) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.StatusCode >= 400 || isPublicResource(p.URL) {
		return nil
	}

	var out []Finding
	for _, probe := range cachePoisonProbes {
		reqHeaders := http.Header{probe.name: {probe.value}}
		resp, err := t.Do(ctx, http.MethodGet, p.URL, nil, false, reqHeaders)
		if err != nil || resp == nil {
			continue
		}

		// Check if probe value is reflected in body or headers
		reflectedInBody := Fresh(baseline, resp, probe.value)
		locHeader := resp.HeaderValue("Location")
		reflectedInLocation := strings.Contains(locHeader, probe.value) &&
			(baseline == nil || !strings.Contains(baseline.HeaderValue("Location"), probe.value))

		if !reflectedInBody && !reflectedInLocation {
			continue
		}

		// Check for cache indicators (e.g. Cache-Control, Age, X-Cache, CF-Cache-Status)
		isCached := isCacheable(resp)

		// Second confirming probe: send request WITHOUT the unkeyed header
		// to test if cache was poisoned for other visitors
		poisonConfirmed := false
		cleanResp, cleanErr := t.Do(ctx, http.MethodGet, p.URL, nil, false, nil)
		if cleanErr == nil && cleanResp != nil {
			if strings.Contains(cleanResp.Body, probe.value) || strings.Contains(cleanResp.HeaderValue("Location"), probe.value) {
				poisonConfirmed = true
			}
		}

		severity := SeverityMedium
		tier := TierPotential
		title := fmt.Sprintf("Unkeyed Header Reflection (%s)", probe.name)

		if poisonConfirmed {
			severity = SeverityHigh
			tier = TierVerified
			title = fmt.Sprintf("Web Cache Poisoning Confirmed (%s)", probe.name)
		} else if isCached {
			severity = SeverityHigh
			tier = TierPotential
			title = fmt.Sprintf("Potential Web Cache Poisoning (%s)", probe.name)
		}

		evidence := fmt.Sprintf("Header %s: %s was reflected in response.", probe.name, probe.value)
		if reflectedInLocation {
			evidence += fmt.Sprintf(" Reflected in Location: %s", locHeader)
		}
		if poisonConfirmed {
			evidence += " Cache poisoning confirmed: subsequent clean request also returned the poisoned content."
		}

		finding, _ := NewFinding(Spec{
			Module:      "cache-poisoning",
			Title:       title,
			Claimed:     severity,
			Tier:        tier,
			Point:       p,
			Payload:     fmt.Sprintf("%s: %s", probe.name, probe.value),
			Evidence:    evidence,
			Description: "The server reflects unkeyed request headers into the response. If an intermediate cache or CDN stores this response without including the header in the cache key, all users requesting this URL will receive the attacker's payload (e.g. malicious script import or open redirect).",
			Remediation: "Ensure reverse proxies strip untrusted forwarding headers, or add all input headers to the cache key (Vary header) or disable caching on dynamic endpoints.",
		})
		out = append(out, finding)
	}

	return out
}

func isCacheable(resp *Response) bool {
	if resp == nil {
		return false
	}
	cc := strings.ToLower(resp.HeaderValue("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		return false
	}
	if strings.Contains(cc, "public") || strings.Contains(cc, "max-age") {
		return true
	}
	if resp.HeaderValue("Age") != "" || resp.HeaderValue("X-Cache") != "" || resp.HeaderValue("CF-Cache-Status") != "" {
		return true
	}
	return false
}
