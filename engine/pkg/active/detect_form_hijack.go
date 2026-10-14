package active

import (
	"context"
	"regexp"
	"strings"
)

// FormHijack probes parameters reflected into form action attributes.
// Corresponds to Burp Suite check:
// 0x00501500 (Form action hijacking - reflected)
type FormHijack struct{}

// Name implements Module.
func (FormHijack) Name() string { return "form-hijack" }

// Level implements Module.
func (FormHijack) Level() Level { return LevelParam }

var (
	formActionRe = regexp.MustCompile(`(?i)<form[^>]+action\s*=\s*["']?([^"'>\s]+)`)
	passwordRe   = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*["']?password["']?`)
)

func (f FormHijack) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil || baseline.StatusCode >= 400 || isPublicResource(p.URL) {
		return nil
	}

	canaryURL := "https://rr-form-hijack.invalid/collect"
	resp, err := t.Fire(ctx, p, p.Param, canaryURL, false, nil)
	if err != nil || resp == nil {
		return nil
	}

	// Must be fresh reflection
	if !Fresh(baseline, resp, canaryURL) {
		return nil
	}

	// Verify that the reflection actually landed inside a form action attribute
	matches := formActionRe.FindAllStringSubmatch(resp.Body, -1)
	actionHijacked := false
	for _, m := range matches {
		if len(m) > 1 && strings.Contains(m[1], canaryURL) {
			actionHijacked = true
			break
		}
	}

	if !actionHijacked {
		return nil
	}

	hasPassword := passwordRe.MatchString(resp.Body)
	claimed := SeverityMedium
	title := "Form Action Hijacking"
	if hasPassword {
		claimed = SeverityHigh
		title = "Form Action Hijacking on Password Form"
	}

	evidence := Snippet(resp.Body, canaryURL, 120)
	finding, _ := NewFinding(Spec{
		Module:      "form-hijack",
		Title:       title,
		Claimed:     claimed,
		Tier:        TierVerified,
		Point:       p,
		Payload:     canaryURL,
		Evidence:    evidence,
		Description: "The parameter is reflected directly into the 'action' attribute of an HTML form without validation. An attacker can trick users into submitting the form to an attacker-controlled server, exfiltrating credentials or sensitive data.",
		Remediation: "Validate and restrict form action URLs to relative paths on the same origin, or use strict server-side allowlists.",
	})

	return []Finding{finding}
}
