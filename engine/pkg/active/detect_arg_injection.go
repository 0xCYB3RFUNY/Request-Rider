package active

import (
	"context"
	"strings"
)

// ArgumentInjection probes parameters for CLI argument/flag injection (CWE-88)
// where user input is passed unseparated into a subprocess invocation.
type ArgumentInjection struct{}

// Name implements Module.
func (ArgumentInjection) Name() string { return "arg_injection" }

// Level implements Module.
func (ArgumentInjection) Level() Level { return LevelParam }

var argUsageMarkers = []string{
	"usage:",
	"options:",
	"try '--help' for more information",
	"unknown option",
	"unrecognized option",
	"invalid option --",
}

// Scan sends CLI flag probes (--help, --version) and checks for fresh CLI
// usage/option error banners that were absent from the baseline.
func (ArgumentInjection) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	if baseline == nil {
		return nil
	}
	probes := []string{"--help", "--version"}
	for _, payload := range probes {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := t.Fire(ctx, p, p.Param, payload, true, nil)
		if err != nil || resp == nil {
			continue
		}
		// Ignore simple parameter reflection of the flag string alone.
		if strings.Contains(resp.Body, payload) && !containsAnyFold(resp.Body, argUsageMarkers) {
			continue
		}
		for _, marker := range argUsageMarkers {
			if FreshFold(baseline, resp, marker) {
				f, _ := NewFinding(Spec{
					Module:   "arg_injection",
					Title:    "Potential CLI argument injection via " + p.Param,
					Claimed:  SeverityHigh,
					Tier:     TierVerified,
					Point:    p,
					Payload:  payload,
					Evidence: Snippet(resp.Body, marker, 220),
					Description: "Supplying a CLI flag (" + payload + ") produced command-line usage or " +
						"option-parsing output in the response (CWE-88), indicating unseparated argument passing.",
					Remediation: "Insert an explicit '--' end-of-options delimiter before user-controlled " +
						"arguments or avoid invoking external CLI tools with user input.",
				})
				return []Finding{f}
			}
		}
	}
	return nil
}
