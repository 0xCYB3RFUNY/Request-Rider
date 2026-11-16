package active

import (
	"context"
	"strings"
)

// ErrorDisclosure probes parameters with malformed/type-confusing inputs to
// trigger verbose framework stack traces, debug pages, or internal path leaks
// (CWE-209).
type ErrorDisclosure struct{}

// Name implements Module.
func (ErrorDisclosure) Name() string { return "error_disclosure" }

// Level implements Module.
func (ErrorDisclosure) Level() Level { return LevelParam }

var errorDisclosureMarkers = []string{
	"traceback (most recent call last):",
	"debugger pin:",
	"werkzeug.exceptions",
	"django.core.exceptions",
	"fatal error:",
	"parse error:",
	"whitelabel error page",
	"java.lang.nullpointerexception",
	"server error in '/' application",
	"system.nullreferenceexception",
	"referenceerror:",
	"typeerror:",
	"syntaxerror:",
	"stack trace:",
	"at layer.handle",
}

// Scan sends compact malformed probes and checks for fresh stack-trace/debug markers.
func (ErrorDisclosure) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil {
		return nil
	}
	probes := []string{`[]`, `'"}`, "\x00"}
	for _, payload := range probes {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := t.Fire(ctx, p, p.Param, payload, true, nil)
		if err != nil || resp == nil {
			continue
		}
		for _, marker := range errorDisclosureMarkers {
			if FreshFold(baseline, resp, marker) {
				f, _ := NewFinding(Spec{
					Module:   "error_disclosure",
					Title:    "Verbose error / stack trace disclosure via " + p.Param,
					Claimed:  SeverityMedium,
					Tier:     TierVerified,
					Point:    p,
					Payload:  payload,
					Evidence: Snippet(resp.Body, marker, 220),
					Description: "Sending a malformed input caused the application to return a verbose " +
						"internal error message or stack trace (CWE-209), exposing internal paths, frameworks, or logic.",
					Remediation: "Disable debug mode in production, return generic error responses to clients, " +
						"and log detailed stack traces only on the server side.",
				})
				return []Finding{f}
			}
		}
	}
	return nil
}

func containsAnyFold(body string, needles []string) bool {
	lower := strings.ToLower(body)
	for _, n := range needles {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}
