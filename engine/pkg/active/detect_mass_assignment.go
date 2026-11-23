package active

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// MassAssignment probes state-changing JSON/API endpoints for Mass Assignment
// (CWE-915) by injecting high-risk privilege and state fields (`role`,
// `is_admin`, `is_staff`, `permissions`, `verified`, `balance`, `discount`)
// that are either harvested from the endpoint's own JSON baseline or part of
// the sensitive privilege pool.
type MassAssignment struct{}

// Name implements Module.
func (MassAssignment) Name() string { return "mass_assignment" }

// Level implements Module.
func (MassAssignment) Level() Level { return LevelEndpoint }

var massAssignmentHints = []string{
	"/api/", "/rest/", "/v1/", "/v2/", "/user", "/profile", "/account", "/order", "/checkout", "/settings",
}

func isMassAssignmentCandidate(p Point, baseline *Response) bool {
	if baseline == nil {
		return false
	}
	ct := strings.ToLower(baseline.Header.Get("Content-Type"))
	isJSON := strings.Contains(ct, "application/json") || strings.HasPrefix(strings.TrimSpace(baseline.Body), "{")
	if isJSON {
		return true
	}
	if p.Method == http.MethodPost || p.Method == http.MethodPut || p.Method == http.MethodPatch {
		return true
	}
	lowerURL := strings.ToLower(p.URL)
	for _, hint := range massAssignmentHints {
		if strings.Contains(lowerURL, hint) {
			return true
		}
	}
	return false
}

// Scan probes an eligible endpoint for Mass Assignment using JSON payloads.
func (MassAssignment) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if !isMassAssignmentCandidate(p, baseline) {
		return nil
	}

	canary := newCanary("rrma")
	if canary == "" {
		return nil
	}

	type maProbe struct {
		field string
		value any
		check string
	}
	probes := []maProbe{
		{field: "role", value: canary, check: canary},
		{field: "is_admin", value: true, check: `"is_admin":true`},
		{field: "is_staff", value: true, check: `"is_staff":true`},
		{field: "admin", value: true, check: `"admin":true`},
		{field: "verified", value: true, check: `"verified":true`},
	}

	method := p.Method
	if method == "" || method == http.MethodGet {
		method = http.MethodPost
	}

	var findings []Finding
	for _, pr := range probes {
		if ctx.Err() != nil {
			return findings
		}
		// Skip boolean probes if the baseline already reports that exact state.
		compactBase := strings.ReplaceAll(strings.ToLower(baseline.Body), " ", "")
		if strings.Contains(compactBase, strings.ToLower(pr.check)) {
			continue
		}

		payloadMap := map[string]any{pr.field: pr.value}
		raw, err := json.Marshal(payloadMap)
		if err != nil {
			continue
		}
		resp, err := t.DoBody(ctx, method, p.URL, raw, "application/json", false, nil)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		compactResp := strings.ReplaceAll(strings.ToLower(resp.Body), " ", "")
		if !strings.Contains(compactResp, strings.ToLower(pr.check)) {
			continue
		}
		// Confirm the response is structured JSON rather than a plain text echo.
		var parsed map[string]any
		if err := json.Unmarshal([]byte(resp.Body), &parsed); err != nil {
			continue
		}
		f, _ := NewFinding(Spec{
			Module:   "mass_assignment",
			Title:    "Mass Assignment accepted privileged field '" + pr.field + "' on " + p.URL,
			Claimed:  SeverityHigh,
			Tier:     TierVerified,
			Point:    Point{URL: p.URL, Method: method, Param: pr.field, Source: SourceQuery},
			Payload:  string(raw),
			Evidence: Snippet(resp.Body, pr.field, 220),
			Description: "The endpoint accepted an undeclared privileged JSON field (" + pr.field + ") in a " +
				method + " request and reflected the updated state in its JSON response (CWE-915).",
			Remediation: "Use an explicit allowlist (DTO/schema) when binding request bodies to internal models, " +
				"and reject or strip privileged fields such as role, is_admin, and verified.",
		})
		findings = append(findings, f)
		break
	}
	return findings
}
