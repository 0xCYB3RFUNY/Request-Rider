// Server-side request forgery detection.
//
// # The defect in the upstream discrimination
//
// The upstream detector distinguishes a real server-side fetch from a page that
// merely echoes the payload with a function called `reflectOnly`, whose default
// branch is:
//
//	func reflectOnly(body string, p Point, payload string) bool {
//	    if !strings.Contains(body, payload) {
//	        return false
//	    }
//	    switch {
//	    case strings.Contains(payload, "169.254.169.254"): ...
//	    case strings.Contains(payload, "metadata.google.internal"): ...
//	    case strings.Contains(payload, "file://"): ...
//	    default:
//	        return strings.Contains(body, payload)   // ← always true here
//	    }
//	}
//
// The function is only called after the guard above it, so in the default branch
// `strings.Contains(body, payload)` is **already known to be true** and the
// function returns true unconditionally. Every loopback and IPv6-loopback probe
// therefore reports "the page echoed it, so this was not a fetch" — which means
// SSRF to localhost and SSRF over IPv6 are **never** reported, silently, forever.
//
// The branch is not merely redundant, it is inverted in effect: the probe that
// most needs to distinguish reflection from fetching is the one where the
// distinction is impossible to make, and the code makes it wrongly and silently.
//
// # A note on the loopback targets specifically
//
// They are the ones the upstream detector never reports, because of the
// inverted branch described above, and they are the cheapest proof available: a
// request to 127.0.0.1 that returns an internal page costs the target one
// loopback connection and settles the question.
//
// # Why the two are separated here, and where they cannot be
//
// A server-side fetch leaves a trace the echo does not: the response contains
// material that could only have come from the internal resource, and does not
// contain the payload as plain text. Those two facts together are the evidence:
//
//   - the fingerprint of the internal resource is present, and
//   - the payload is **not** present verbatim, so nothing echoed it.
//
// Where both hold, the server fetched. Where the payload came back, the page
// reflected it and nothing was fetched, whatever the fingerprint says. Where
// neither holds, nothing happened.
//
// For a target that fetches without reflecting the body there is no evidence in
// the response at all, and the honest outcome is a potential, not a verified
// finding. That is what OAST is for — and the Project has real DNS and HTTP
// listeners, so a blind confirmation is available to the chain stage rather than
// being guessed at here.
package active

import (
	"context"
	"fmt"
	"strings"
)

// ssrfTarget is one internal resource to ask the server to fetch.
type ssrfTarget struct {
	// name identifies the target in the report.
	name string
	// payload is the URL to inject.
	payload string
	// fingerprints are the strings that can only appear if that resource's
	// content came back. Several are listed per target because a truncated read
	// or a different code path may carry only part of it.
	fingerprints []string
	// loopback marks a target on the machine the server runs on, which is the
	// case the upstream detector never reports.
	loopback bool
	// claimed is the severity the evidence supports if it were proven.
	claimed Severity
}

// ssrfTargets are the internal resources asked for, ordered from the one that
// costs a target least.
//
// Loopback comes before cloud metadata on purpose. A request to 127.0.0.1 that
// returns an internal page proves the forgery and is cheap; a request to the
// metadata endpoint is the same proof with a louder consequence, and there is
// no reason to reach for it first.
var ssrfTargets = []ssrfTarget{
	{
		name: "loopback HTTP", payload: "http://127.0.0.1/",
		fingerprints: []string{"<html", "<!doctype html", "<head", "<body"},
		claimed:      SeverityHigh,
	},
	{
		name: "loopback by name", payload: "http://localhost/",
		fingerprints: []string{"<html", "<!doctype html", "<head", "<body"},
		claimed:      SeverityHigh,
	},
	{
		name: "cloud instance metadata", payload: "http://169.254.169.254/latest/meta-data/",
		fingerprints: []string{"ami-id", "instance-id", "local-ipv4", "iam/security-credentials"},
		claimed:      SeverityCritical,
	},
	{
		name: "GCP metadata", payload: "http://metadata.google.internal/computeMetadata/v1/",
		fingerprints: []string{"computeMetadata/v1/instance", "computeMetadata/v1/project"},
		claimed:      SeverityCritical,
	},
	{
		name: "IPv6 loopback", payload: "http://[::1]/",
		fingerprints: []string{"<html", "<!doctype html", "<head", "<body"},
		claimed:      SeverityHigh,
	},
}

// SSRF is the server-side request forgery detector.
type SSRF struct{}

// Name implements Module.
func (SSRF) Name() string { return "ssrf" }

// Level implements Module.
func (SSRF) Level() Level { return LevelParam }

// Scan probes one surface.
//
// The surface is not filtered by parameter name. A name-based gate would skip
// exactly the surfaces a human would check — an application that fetches a
// "template" or a "skin" by URL is not going to name the parameter `url` — and a
// gate that silently reduces coverage looks identical to a clean result.
func (SSRF) Scan(ctx context.Context, t *Transport, p Point, baseline *Response) []Finding {
	for _, target := range ssrfTargets {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := t.Fire(ctx, p, p.Param, target.payload, false, nil)
		if err != nil {
			continue
		}
		finding := judge(baseline, resp, target, p)
		if finding != nil {
			return []Finding{*finding}
		}
	}
	return nil
}

// judge decides what a response to one probe shows.
//
// Three outcomes, and the third is the one the upstream code cannot produce:
//
//   - a fingerprint is present and the payload was not echoed → the server
//     fetched, and this is verified;
//   - the payload came back verbatim → the page reflected it and nothing was
//     fetched, so this is not this finding;
//   - nothing at all → nothing happened, or the server fetched and suppressed
//     the body, which is a potential and belongs to the OOB stage.
func judge(baseline, resp *Response, target ssrfTarget, p Point) *Finding {
	echoed := resp != nil && strings.Contains(resp.Body, target.payload)
	var matched string
	for _, fingerprint := range target.fingerprints {
		if Fresh(baseline, resp, fingerprint) {
			matched = fingerprint
			break
		}
	}
	if matched == "" {
		return nil
	}
	if echoed {
		// The fingerprint is there and so is the payload. A page that renders
		// the internal resource's markup while also echoing what it was asked to
		// fetch is not evidence the server made the request — it is evidence the
		// page was already showing that content.
		return nil
	}
	finding, _ := NewFinding(Spec{
		Module:  "ssrf",
		Title:   "Server-Side Request Forgery (" + target.name + ")",
		Claimed: target.claimed,
		Tier:    TierVerified,
		Point:   p,
		Payload: target.payload,
		Evidence: fmt.Sprintf("the response carries %q, which only the fetched resource can supply, and "+
			"does not contain the requested URL itself, so nothing echoed the probe", matched),
		Description: "The server fetched an internal resource chosen by the parameter and returned its " +
			"content, so requests originate from inside the server's network position rather than the " +
			"client's.",
		Remediation: "Allow-list outbound destinations and resolve the hostname before comparing. Block " +
			"link-local and loopback ranges. Disable the unused URL schemes. On cloud hosts, require " +
			"IMDSv2 and restrict it to the instance role.",
	})
	return &finding
}
